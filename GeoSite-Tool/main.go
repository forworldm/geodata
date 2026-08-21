package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

// ---------- Custom binary format ----------
//
// Binary {
//     magic: byte[8] = "etisoeg\0"   (we pad with null to 8 bytes)
//     category_count: UInt32 (LE)
//     category_offsets: Offset[category_count]   // absolute offsets from file start
//     categories: Category[category_count]
//     entries: Entry[...]                       // may be shared / non-contiguous
// }
//
// Category {
//     name: String
//     entry_count: UInt32
//     entry_offsets: Offset[entry_count]
// }
//
// Entry {
//     type: EntryType (uint8)
//     value: String   // "domain@attr1@attr2"  (attrs sorted, joined by '@')
// }
//
// String {
//     length: UInt16  // includes the terminating null byte; length==0 is invalid
//     bytes: null-terminated UTF-8
// }
//
// Offset = UInt32 (absolute from file start)
// All multi-byte integers are little-endian.

const magic = "etisoeg" // written as 8 bytes: 'e','t','i','s','o','e','g',0

type EntryType uint8

const (
	EntryDomain  EntryType = 0
	EntryFull    EntryType = 1
	EntryKeyword EntryType = 2
	EntryRegexp  EntryType = 3
)

func (t EntryType) String() string {
	switch t {
	case EntryDomain:
		return "domain"
	case EntryFull:
		return "full"
	case EntryKeyword:
		return "keyword"
	case EntryRegexp:
		return "regexp"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// entryKey is used for global deduplication.
type entryKey struct {
	Type  EntryType
	Value string // already contains "@attr..." if any
}

// ---------- Protobuf helpers ----------

func domainTypeToEntryType(t router.Domain_Type) (EntryType, error) {
	switch t {
	case router.Domain_RootDomain:
		return EntryDomain, nil
	case router.Domain_Full:
		return EntryFull, nil
	case router.Domain_Plain:
		return EntryKeyword, nil
	case router.Domain_Regex:
		return EntryRegexp, nil
	default:
		return 0, fmt.Errorf("unknown domain type: %v", t)
	}
}

func buildValue(d *router.Domain) string {
	attrs := make([]string, 0, len(d.Attribute))
	for _, a := range d.Attribute {
		attrs = append(attrs, a.Key)
	}
	sort.Strings(attrs)
	if len(attrs) == 0 {
		return d.Value
	}
	return d.Value + "@" + strings.Join(attrs, "@")
}

// ---------- Load protobuf geosite.dat ----------

func loadProto(path string) (*router.GeoSiteList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	list := new(router.GeoSiteList)
	if err := proto.Unmarshal(data, list); err != nil {
		return nil, fmt.Errorf("proto unmarshal: %w", err)
	}
	return list, nil
}

// ---------- Protobuf list / dump (for debugging) ----------

func cmdListCategoriesProto(path string) error {
	list, err := loadProto(path)
	if err != nil {
		return err
	}
	// Sort for stable output
	sort.Slice(list.Entry, func(i, j int) bool {
		return list.Entry[i].CountryCode < list.Entry[j].CountryCode
	})
	for _, site := range list.Entry {
		fmt.Printf("%s\t%d\n", strings.ToUpper(site.CountryCode), len(site.Domain))
	}
	fmt.Printf("# total categories: %d\n", len(list.Entry))
	return nil
}

func cmdListSitesProto(path, category string) error {
	list, err := loadProto(path)
	if err != nil {
		return err
	}
	want := strings.ToUpper(category)
	for _, site := range list.Entry {
		if strings.ToUpper(site.CountryCode) == want {
			for _, d := range site.Domain {
				et, err := domainTypeToEntryType(d.Type)
				if err != nil {
					return fmt.Errorf("category %s: %w", site.CountryCode, err)
				}
				val := buildValue(d)
				fmt.Printf("%s:%s\n", et, val)
			}
			fmt.Printf("# %s: %d entries\n", strings.ToUpper(site.CountryCode), len(site.Domain))
			return nil
		}
	}
	return fmt.Errorf("category %q not found", category)
}

func cmdDumpProto(path string) error {
	list, err := loadProto(path)
	if err != nil {
		return err
	}
	sort.Slice(list.Entry, func(i, j int) bool {
		return list.Entry[i].CountryCode < list.Entry[j].CountryCode
	})
	for _, site := range list.Entry {
		name := strings.ToUpper(site.CountryCode)
		fmt.Printf("===== %s (%d) =====\n", name, len(site.Domain))
		for _, d := range site.Domain {
			et, err := domainTypeToEntryType(d.Type)
			if err != nil {
				return fmt.Errorf("category %s: %w", name, err)
			}
			val := buildValue(d)
			fmt.Printf("  %s:%s\n", et, val)
		}
		fmt.Println()
	}
	return nil
}

// ---------- Convert protobuf → custom binary (with entry dedup) ----------

func convert(protoPath, outPath string) error {
	list, err := loadProto(protoPath)
	if err != nil {
		return err
	}

	// 1. Collect unique entries globally
	entryIndex := make(map[entryKey]uint32) // key → index in uniqueEntries
	var uniqueEntries []entryKey

	type catInfo struct {
		name    string
		indices []uint32 // indices into uniqueEntries
	}
	var cats []catInfo

	for _, site := range list.Entry {
		name := strings.ToUpper(site.CountryCode)
		ci := catInfo{name: name}
		seenInCat := make(map[entryKey]struct{}) // per-category dedup as well

		for _, d := range site.Domain {
			et, err := domainTypeToEntryType(d.Type)
			if err != nil {
				return fmt.Errorf("category %s: %w", name, err)
			}
			val := buildValue(d)
			k := entryKey{Type: et, Value: val}

			if _, ok := seenInCat[k]; ok {
				continue
			}
			seenInCat[k] = struct{}{}

			idx, exists := entryIndex[k]
			if !exists {
				idx = uint32(len(uniqueEntries))
				entryIndex[k] = idx
				uniqueEntries = append(uniqueEntries, k)
			}
			ci.indices = append(ci.indices, idx)
		}
		cats = append(cats, ci)
	}

	// Sort categories by name for reproducibility
	sort.Slice(cats, func(i, j int) bool {
		return cats[i].name < cats[j].name
	})

	// 2. Serialize
	// We write in two passes conceptually:
	//   - first compute all offsets
	//   - then write

	var buf []byte

	// helper to append little-endian numbers
	putU32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	putU16 := func(v uint16) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], v)
		buf = append(buf, b[:]...)
	}
	putString := func(s string) {
		// length includes the null terminator
		if len(s)+1 > 0xffff {
			panic("string too long")
		}
		putU16(uint16(len(s) + 1))
		buf = append(buf, s...)
		buf = append(buf, 0)
	}

	// Header
	magicBytes := make([]byte, 8)
	copy(magicBytes, magic)
	buf = append(buf, magicBytes...)

	catCount := uint32(len(cats))
	putU32(catCount)

	// Reserve space for category_offsets
	catOffsetsPos := len(buf)
	for i := 0; i < int(catCount); i++ {
		putU32(0) // placeholder
	}

	// Write categories, record their offsets
	catOffsets := make([]uint32, catCount)
	entryOffsetTable := make([]uint32, len(uniqueEntries)) // will fill later

	for i, c := range cats {
		catOffsets[i] = uint32(len(buf))
		putString(c.name)
		putU32(uint32(len(c.indices)))
		// entry_offsets placeholders
		for range c.indices {
			putU32(0)
		}
	}

	// Write all unique entries, record their absolute offsets
	for i, e := range uniqueEntries {
		entryOffsetTable[i] = uint32(len(buf))
		buf = append(buf, byte(e.Type))
		putString(e.Value)
	}

	// Patch category_offsets
	for i, off := range catOffsets {
		binary.LittleEndian.PutUint32(buf[catOffsetsPos+i*4:], off)
	}

	// Patch each category's entry_offsets
	for i, c := range cats {
		// After name string + entry_count (4 bytes)
		// Find the start of entry_offsets inside the category
		nameLen := 2 + len(c.name) + 1 // UInt16 + bytes + null
		entryOffsetsStart := int(catOffsets[i]) + nameLen + 4
		for j, idx := range c.indices {
			binary.LittleEndian.PutUint32(buf[entryOffsetsStart+j*4:], entryOffsetTable[idx])
		}
	}

	if err := os.WriteFile(outPath, buf, 0644); err != nil {
		return err
	}
	fmt.Printf("converted %s → %s\n", protoPath, outPath)
	fmt.Printf("  categories : %d\n", catCount)
	fmt.Printf("  unique entries : %d (deduplicated)\n", len(uniqueEntries))
	return nil
}

// ---------- Parse custom binary ----------

type BinaryEntry struct {
	Type  EntryType
	Value string
}

type BinaryCategory struct {
	Name    string
	Entries []BinaryEntry
}

type BinaryFile struct {
	Categories []BinaryCategory
}

func readString(r *bufio.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := binary.LittleEndian.Uint16(lenBuf[:])
	if n == 0 {
		return "", fmt.Errorf("invalid string length 0")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	if b[n-1] != 0 {
		return "", fmt.Errorf("string not null-terminated")
	}
	return string(b[:n-1]), nil
}

func readU32(r *bufio.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func loadBinary(path string) (*BinaryFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 12 {
		return nil, fmt.Errorf("file too short")
	}
	if string(data[:7]) != magic {
		return nil, fmt.Errorf("bad magic: %q", data[:8])
	}

	r := bufio.NewReader(bytes.NewReader(data))
	// skip magic
	if _, err := r.Discard(8); err != nil {
		return nil, err
	}

	catCount, err := readU32(r)
	if err != nil {
		return nil, err
	}

	catOffsets := make([]uint32, catCount)
	for i := range catOffsets {
		catOffsets[i], err = readU32(r)
		if err != nil {
			return nil, err
		}
	}

	bf := &BinaryFile{}
	for _, off := range catOffsets {
		if int(off) >= len(data) {
			return nil, fmt.Errorf("category offset out of range: %d", off)
		}
		cr := bufio.NewReader(bytes.NewReader(data[off:]))
		name, err := readString(cr)
		if err != nil {
			return nil, fmt.Errorf("category name: %w", err)
		}
		ec, err := readU32(cr)
		if err != nil {
			return nil, err
		}
		entryOffsets := make([]uint32, ec)
		for i := range entryOffsets {
			entryOffsets[i], err = readU32(cr)
			if err != nil {
				return nil, err
			}
		}

		cat := BinaryCategory{Name: name}
		for _, eoff := range entryOffsets {
			if int(eoff) >= len(data) {
				return nil, fmt.Errorf("entry offset out of range: %d", eoff)
			}
			er := bufio.NewReader(bytes.NewReader(data[eoff:]))
			typByte, err := er.ReadByte()
			if err != nil {
				return nil, err
			}
			val, err := readString(er)
			if err != nil {
				return nil, fmt.Errorf("entry value: %w", err)
			}
			cat.Entries = append(cat.Entries, BinaryEntry{
				Type:  EntryType(typByte),
				Value: val,
			})
		}
		bf.Categories = append(bf.Categories, cat)
	}
	return bf, nil
}

// ---------- Commands ----------

func cmdListCategories(path string) error {
	bf, err := loadBinary(path)
	if err != nil {
		return err
	}
	for _, c := range bf.Categories {
		fmt.Printf("%s\t%d\n", c.Name, len(c.Entries))
	}
	fmt.Printf("# total categories: %d\n", len(bf.Categories))
	return nil
}

func cmdListSites(path, category string) error {
	bf, err := loadBinary(path)
	if err != nil {
		return err
	}
	want := strings.ToUpper(category)
	for _, c := range bf.Categories {
		if c.Name == want {
			for _, e := range c.Entries {
				fmt.Printf("%s:%s\n", e.Type, e.Value)
			}
			fmt.Printf("# %s: %d entries\n", c.Name, len(c.Entries))
			return nil
		}
	}
	return fmt.Errorf("category %q not found", category)
}

func cmdDump(path string) error {
	bf, err := loadBinary(path)
	if err != nil {
		return err
	}
	for _, c := range bf.Categories {
		fmt.Printf("===== %s (%d) =====\n", c.Name, len(c.Entries))
		for _, e := range c.Entries {
			fmt.Printf("  %s:%s\n", e.Type, e.Value)
		}
		fmt.Println()
	}
	return nil
}

// isCustomBinary reports whether the file starts with the custom "etisoeg\0" magic.
func isCustomBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var hdr [8]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false, err
	}
	return string(hdr[:7]) == magic, nil
}

func main() {
	listCat := flag.Bool("list-categories", false, "List all categories (and entry counts)")
	listSites := flag.String("list-sites", "", "List entries of the given category")
	convertFrom := flag.String("convert", "", "Convert protobuf geosite.dat to custom binary (input path)")
	outFile := flag.String("o", "geosite.bin", "Output path for -convert")
	dump := flag.Bool("dump", false, "Dump the entire custom binary file")
	file := flag.String("f", "", "Path to the custom binary file (required for list/dump)")

	flag.Parse()

	var err error
	switch {
	case *convertFrom != "":
		err = convert(*convertFrom, *outFile)
	case *listCat:
		if *file == "" {
			fmt.Fprintln(os.Stderr, "-f is required")
			os.Exit(1)
		}
		bin, errDetect := isCustomBinary(*file)
		if errDetect != nil {
			err = errDetect
		} else if bin {
			err = cmdListCategories(*file)
		} else {
			err = cmdListCategoriesProto(*file)
		}
	case *listSites != "":
		if *file == "" {
			fmt.Fprintln(os.Stderr, "-f is required")
			os.Exit(1)
		}
		bin, errDetect := isCustomBinary(*file)
		if errDetect != nil {
			err = errDetect
		} else if bin {
			err = cmdListSites(*file, *listSites)
		} else {
			err = cmdListSitesProto(*file, *listSites)
		}
	case *dump:
		if *file == "" {
			fmt.Fprintln(os.Stderr, "-f is required")
			os.Exit(1)
		}
		bin, errDetect := isCustomBinary(*file)
		if errDetect != nil {
			err = errDetect
		} else if bin {
			err = cmdDump(*file)
		} else {
			err = cmdDumpProto(*file)
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
