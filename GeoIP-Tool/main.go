package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
)

const (
	magicStr     = "0pioeg"
	magicLen     = 8
	defaultOut   = "geoip.bin"
	ip4EntrySize = 5
	ip6EntrySize = 17
)

// ---- internal data model ----

type category struct {
	Code string
	IPv4 []netip.Prefix
	IPv6 []netip.Prefix
}

type geoData struct {
	Categories []*category
}

// ---- binary format helpers ----

func writeString(w io.Writer, s string) error {
	// length includes the trailing null byte; length=0 is invalid
	b := []byte(s)
	if len(b)+1 > 0xffff {
		return fmt.Errorf("string too long: %q", s)
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(len(b)+1)); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err := w.Write([]byte{0})
	return err
}

func readString(r io.Reader) (string, error) {
	var length uint16
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length == 0 {
		return "", fmt.Errorf("invalid zero-length string")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	if buf[length-1] != 0 {
		return "", fmt.Errorf("string not null-terminated")
	}
	return string(buf[:length-1]), nil
}

func writeIP4(w io.Writer, p netip.Prefix) error {
	addr := p.Addr()
	if !addr.Is4() {
		return fmt.Errorf("not IPv4: %s", p)
	}
	// IP bytes are network order (big-endian). Interpret as BE integer,
	// then store that integer as little-endian UInt32 per format.
	ip4 := addr.As4()
	u := binary.BigEndian.Uint32(ip4[:])
	if err := binary.Write(w, binary.LittleEndian, u); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, uint8(p.Bits()))
}

func readIP4(r io.Reader) (netip.Prefix, error) {
	var u uint32
	var prefix uint8
	if err := binary.Read(r, binary.LittleEndian, &u); err != nil {
		return netip.Prefix{}, err
	}
	if err := binary.Read(r, binary.LittleEndian, &prefix); err != nil {
		return netip.Prefix{}, err
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u) // integer → network-order bytes
	addr := netip.AddrFrom4(b)
	return netip.PrefixFrom(addr, int(prefix)), nil
}

func writeIP6(w io.Writer, p netip.Prefix) error {
	addr := p.Addr()
	if !addr.Is6() {
		return fmt.Errorf("not IPv6: %s", p)
	}
	ip6 := addr.As16()
	// Network-order bytes → BE integers.
	// address_high = upper 64 bits (bytes 0..7), address_low = lower 64 bits (bytes 8..15)
	high := binary.BigEndian.Uint64(ip6[0:8])
	low := binary.BigEndian.Uint64(ip6[8:16])
	// Format order: address_low, address_high, prefix
	if err := binary.Write(w, binary.LittleEndian, low); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, high); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, uint8(p.Bits()))
}

func readIP6(r io.Reader) (netip.Prefix, error) {
	var low, high uint64
	var prefix uint8
	if err := binary.Read(r, binary.LittleEndian, &low); err != nil {
		return netip.Prefix{}, err
	}
	if err := binary.Read(r, binary.LittleEndian, &high); err != nil {
		return netip.Prefix{}, err
	}
	if err := binary.Read(r, binary.LittleEndian, &prefix); err != nil {
		return netip.Prefix{}, err
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], high) // high → network-order first 8 bytes
	binary.BigEndian.PutUint64(b[8:16], low) // low  → network-order last 8 bytes
	addr := netip.AddrFrom16(b)
	return netip.PrefixFrom(addr, int(prefix)), nil
}

// ---- load / save ----

func loadProtobuf(path string) (*geoData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("protobuf unmarshal: %w", err)
	}

	gd := &geoData{}
	for _, e := range list.Entry {
		if e == nil {
			continue
		}
		cat := &category{Code: strings.ToUpper(e.CountryCode)}
		for _, c := range e.Cidr {
			if c == nil || len(c.Ip) == 0 {
				continue
			}
			var addr netip.Addr
			switch len(c.Ip) {
			case 4:
				var b [4]byte
				copy(b[:], c.Ip)
				addr = netip.AddrFrom4(b)
			case 16:
				var b [16]byte
				copy(b[:], c.Ip)
				addr = netip.AddrFrom16(b)
			default:
				continue
			}
			pfx := netip.PrefixFrom(addr, int(c.Prefix))
			if !pfx.IsValid() {
				continue
			}
			if addr.Is4() {
				cat.IPv4 = append(cat.IPv4, pfx)
			} else {
				cat.IPv6 = append(cat.IPv6, pfx)
			}
		}
		if len(cat.IPv4) > 0 || len(cat.IPv6) > 0 {
			gd.Categories = append(gd.Categories, cat)
		}
	}
	sort.SliceStable(gd.Categories, func(i, j int) bool {
		return gd.Categories[i].Code < gd.Categories[j].Code
	})
	return gd, nil
}

func loadBinary(path string) (*geoData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(data)

	magic := make([]byte, magicLen)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	if string(bytes.TrimRight(magic, "\x00")) != magicStr {
		return nil, fmt.Errorf("bad magic: %q (want %q)", magic, magicStr)
	}

	var catCount uint32
	if err := binary.Read(r, binary.LittleEndian, &catCount); err != nil {
		return nil, err
	}

	offsets := make([]uint32, catCount)
	for i := range offsets {
		if err := binary.Read(r, binary.LittleEndian, &offsets[i]); err != nil {
			return nil, err
		}
	}

	gd := &geoData{}
	for i := uint32(0); i < catCount; i++ {
		// seek to category
		if _, err := r.Seek(int64(offsets[i]), io.SeekStart); err != nil {
			return nil, err
		}
		code, err := readString(r)
		if err != nil {
			return nil, fmt.Errorf("category %d name: %w", i, err)
		}
		var ip4Count, ip4Offset, ip6Count, ip6Offset uint32
		if err := binary.Read(r, binary.LittleEndian, &ip4Count); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &ip4Offset); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &ip6Count); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &ip6Offset); err != nil {
			return nil, err
		}

		cat := &category{Code: code}

		// read IPv4 entries
		if ip4Count > 0 {
			if _, err := r.Seek(int64(ip4Offset), io.SeekStart); err != nil {
				return nil, err
			}
			for j := uint32(0); j < ip4Count; j++ {
				pfx, err := readIP4(r)
				if err != nil {
					return nil, fmt.Errorf("category %s ip4[%d]: %w", code, j, err)
				}
				cat.IPv4 = append(cat.IPv4, pfx)
			}
		}

		// read IPv6 entries
		if ip6Count > 0 {
			if _, err := r.Seek(int64(ip6Offset), io.SeekStart); err != nil {
				return nil, err
			}
			for j := uint32(0); j < ip6Count; j++ {
				pfx, err := readIP6(r)
				if err != nil {
					return nil, fmt.Errorf("category %s ip6[%d]: %w", code, j, err)
				}
				cat.IPv6 = append(cat.IPv6, pfx)
			}
		}

		gd.Categories = append(gd.Categories, cat)
	}
	return gd, nil
}

func loadAny(path string) (*geoData, error) {
	// try binary first (has clear magic)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	magic := make([]byte, magicLen)
	_, _ = io.ReadFull(f, magic)
	f.Close()

	if string(bytes.TrimRight(magic, "\x00")) == magicStr {
		return loadBinary(path)
	}
	// fallback to protobuf
	return loadProtobuf(path)
}

func saveBinary(path string, gd *geoData) error {
	// layout:
	// magic[8]
	// category_count u32
	// category_offsets[category_count] u32
	// categories[]
	// ip4_entries[]
	// ip6_entries[]

	// first pass: compute sizes
	type catMeta struct {
		code      string
		ip4Count  uint32
		ip6Count  uint32
		ip4Offset uint32
		ip6Offset uint32
		catOffset uint32
	}

	metas := make([]catMeta, len(gd.Categories))
	var totalIP4, totalIP6 uint32

	// header size
	headerSize := uint32(magicLen + 4 + 4*len(gd.Categories))

	// categories section size (we need to know string lengths)
	catSectionSize := uint32(0)
	for i, c := range gd.Categories {
		metas[i].code = c.Code
		metas[i].ip4Count = uint32(len(c.IPv4))
		metas[i].ip6Count = uint32(len(c.IPv6))
		// String: 2 + len + 1
		strSize := uint32(2 + len(c.Code) + 1)
		// + 4*4 for the four uint32 fields
		metas[i].catOffset = headerSize + catSectionSize
		catSectionSize += strSize + 16
		totalIP4 += metas[i].ip4Count
		totalIP6 += metas[i].ip6Count
	}

	ip4Base := headerSize + catSectionSize
	ip6Base := ip4Base + totalIP4*ip4EntrySize

	// assign offsets into the flat arrays
	var ip4Cursor, ip6Cursor uint32
	for i := range metas {
		if metas[i].ip4Count > 0 {
			metas[i].ip4Offset = ip4Base + ip4Cursor*ip4EntrySize
			ip4Cursor += metas[i].ip4Count
		}
		if metas[i].ip6Count > 0 {
			metas[i].ip6Offset = ip6Base + ip6Cursor*ip6EntrySize
			ip6Cursor += metas[i].ip6Count
		}
	}

	// write
	var buf bytes.Buffer

	// magic (pad to 8 bytes)
	magic := make([]byte, magicLen)
	copy(magic, magicStr)
	buf.Write(magic)

	// category_count
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(gd.Categories))); err != nil {
		return err
	}

	// category_offsets
	for _, m := range metas {
		if err := binary.Write(&buf, binary.LittleEndian, m.catOffset); err != nil {
			return err
		}
	}

	// categories
	for _, m := range metas {
		if err := writeString(&buf, m.code); err != nil {
			return err
		}
		if err := binary.Write(&buf, binary.LittleEndian, m.ip4Count); err != nil {
			return err
		}
		if err := binary.Write(&buf, binary.LittleEndian, m.ip4Offset); err != nil {
			return err
		}
		if err := binary.Write(&buf, binary.LittleEndian, m.ip6Count); err != nil {
			return err
		}
		if err := binary.Write(&buf, binary.LittleEndian, m.ip6Offset); err != nil {
			return err
		}
	}

	// ip4 entries (in category order)
	for _, c := range gd.Categories {
		for _, p := range c.IPv4 {
			if err := writeIP4(&buf, p); err != nil {
				return err
			}
		}
	}

	// ip6 entries
	for _, c := range gd.Categories {
		for _, p := range c.IPv6 {
			if err := writeIP6(&buf, p); err != nil {
				return err
			}
		}
	}

	return os.WriteFile(path, buf.Bytes(), 0644)
}

// ---- CLI actions ----

func listCategories(gd *geoData) {
	fmt.Printf("Total categories: %d\n", len(gd.Categories))
	fmt.Println("----------------------------------------")
	for _, c := range gd.Categories {
		fmt.Printf("%-16s  IPv4=%-6d  IPv6=%-6d  total=%d\n",
			c.Code, len(c.IPv4), len(c.IPv6), len(c.IPv4)+len(c.IPv6))
	}
}

func listIPs(gd *geoData, name string) error {
	name = strings.ToUpper(strings.TrimSpace(name))
	for _, c := range gd.Categories {
		if c.Code == name {
			fmt.Printf("Category: %s  (IPv4=%d, IPv6=%d)\n", c.Code, len(c.IPv4), len(c.IPv6))
			fmt.Println("----------------------------------------")
			for _, p := range c.IPv4 {
				fmt.Println(p.String())
			}
			for _, p := range c.IPv6 {
				fmt.Println(p.String())
			}
			return nil
		}
	}
	return fmt.Errorf("category %q not found", name)
}

func dumpBinary(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	r := bytes.NewReader(data)

	magic := make([]byte, magicLen)
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	fmt.Printf("Magic          : %q\n", string(bytes.TrimRight(magic, "\x00")))

	var catCount uint32
	if err := binary.Read(r, binary.LittleEndian, &catCount); err != nil {
		return err
	}
	fmt.Printf("Category count : %d\n", catCount)

	offsets := make([]uint32, catCount)
	for i := range offsets {
		if err := binary.Read(r, binary.LittleEndian, &offsets[i]); err != nil {
			return err
		}
	}
	fmt.Printf("Category offsets: %v\n", offsets)
	fmt.Println("========================================")

	for i := uint32(0); i < catCount; i++ {
		if _, err := r.Seek(int64(offsets[i]), io.SeekStart); err != nil {
			return err
		}
		code, err := readString(r)
		if err != nil {
			return err
		}
		var ip4Count, ip4Offset, ip6Count, ip6Offset uint32
		binary.Read(r, binary.LittleEndian, &ip4Count)
		binary.Read(r, binary.LittleEndian, &ip4Offset)
		binary.Read(r, binary.LittleEndian, &ip6Count)
		binary.Read(r, binary.LittleEndian, &ip6Offset)

		fmt.Printf("[%d] %s\n", i, code)
		fmt.Printf("    IPv4: count=%d  offset=0x%x\n", ip4Count, ip4Offset)
		fmt.Printf("    IPv6: count=%d  offset=0x%x\n", ip6Count, ip6Offset)

		// show first few entries
		const maxShow = 5
		if ip4Count > 0 {
			r.Seek(int64(ip4Offset), io.SeekStart)
			n := ip4Count
			if n > maxShow {
				n = maxShow
			}
			for j := uint32(0); j < n; j++ {
				p, _ := readIP4(r)
				fmt.Printf("      v4[%d] %s\n", j, p)
			}
			if ip4Count > maxShow {
				fmt.Printf("      ... (%d more)\n", ip4Count-maxShow)
			}
		}
		if ip6Count > 0 {
			r.Seek(int64(ip6Offset), io.SeekStart)
			n := ip6Count
			if n > maxShow {
				n = maxShow
			}
			for j := uint32(0); j < n; j++ {
				p, _ := readIP6(r)
				fmt.Printf("      v6[%d] %s\n", j, p)
			}
			if ip6Count > maxShow {
				fmt.Printf("      ... (%d more)\n", ip6Count-maxShow)
			}
		}
		fmt.Println()
	}
	return nil
}

func convert(inPath, outPath string) error {
	gd, err := loadProtobuf(inPath)
	if err != nil {
		return fmt.Errorf("load protobuf: %w", err)
	}
	if err := saveBinary(outPath, gd); err != nil {
		return fmt.Errorf("write binary: %w", err)
	}
	fmt.Printf("✅ converted %s → %s  (%d categories)\n", inPath, outPath, len(gd.Categories))
	return nil
}

func main() {
	convertPath := flag.String("convert", "", "Convert protobuf geoip.dat to custom binary (input path)")
	dumpFlag := flag.Bool("dump", false, "Dump the entire custom binary file")
	filePath := flag.String("f", "", "Path to the geoip file (protobuf or custom binary; required for list/dump)")
	listCats := flag.Bool("list-categories", false, "List all categories (and entry counts)")
	listIPsFlag := flag.String("list-ips", "", "List IPs of the given category")
	outPath := flag.String("o", defaultOut, "Output path for -convert")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  # Convert official geoip.dat → custom binary
  geoip-tool -convert geoip.dat -o geoip.bin

  # List categories (works on both .dat and .bin)
  geoip-tool -f geoip.dat -list-categories
  geoip-tool -f geoip.bin -list-categories

  # List IPs of a category
  geoip-tool -f geoip.dat -list-ips CN
  geoip-tool -f geoip.bin -list-ips private

  # Dump binary structure
  geoip-tool -f geoip.bin -dump
`)
	}
	flag.Parse()

	var err error
	switch {
	case *convertPath != "":
		err = convert(*convertPath, *outPath)
	case *dumpFlag:
		if *filePath == "" {
			flag.Usage()
			os.Exit(1)
		}
		err = dumpBinary(*filePath)
	case *listCats:
		if *filePath == "" {
			flag.Usage()
			os.Exit(1)
		}
		var gd *geoData
		gd, err = loadAny(*filePath)
		if err == nil {
			listCategories(gd)
		}
	case *listIPsFlag != "":
		if *filePath == "" {
			flag.Usage()
			os.Exit(1)
		}
		var gd *geoData
		gd, err = loadAny(*filePath)
		if err == nil {
			err = listIPs(gd, *listIPsFlag)
		}
	default:
		flag.Usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
