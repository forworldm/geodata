package ipinfo

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/v2fly/geoip/lib"
)

const (
	typeCountryCSVIn = "ipinfoCountryCSV"
	descCountryCSVIn = "Convert IPInfo country CSV data to other formats"
)

var defaultCountryCSVFile = filepath.Join("./", "ipinfo", "country.csv")

func init() {
	lib.RegisterInputConfigCreator(typeCountryCSVIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newCountryCSVIn(action, data)
	})
	lib.RegisterInputConverter(typeCountryCSVIn, &countryCSVIn{
		Description: descCountryCSVIn,
	})
}

func newCountryCSVIn(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var tmp struct {
		URI        string     `json:"uri"`
		Want       []string   `json:"wantedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.URI == "" {
		tmp.URI = defaultCountryCSVFile
	}

	wantList := make(map[string]bool)
	for _, want := range tmp.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList[want] = true
		}
	}

	return &countryCSVIn{
		Type:        typeCountryCSVIn,
		Action:      action,
		Description: descCountryCSVIn,
		URI:         tmp.URI,
		Want:        wantList,
		OnlyIPType:  tmp.OnlyIPType,
	}, nil
}

type countryCSVIn struct {
	Type        string
	Action      lib.Action
	Description string
	URI         string
	Want        map[string]bool
	OnlyIPType  lib.IPType
}

func (g *countryCSVIn) GetType() string {
	return g.Type
}

func (g *countryCSVIn) GetAction() lib.Action {
	return g.Action
}

func (g *countryCSVIn) GetDescription() string {
	return g.Description
}

func (g *countryCSVIn) Input(container lib.Container) (lib.Container, error) {
	entries := make(map[string]*lib.Entry, 300)

	if err := g.process(g.URI, entries); err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("❌ [type %s | action %s] no entry is generated", typeCountryCSVIn, g.Action)
	}

	var ignoreIPType lib.IgnoreIPOption
	switch g.OnlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	for _, entry := range entries {
		switch g.Action {
		case lib.ActionAdd:
			if err := container.Add(entry, ignoreIPType); err != nil {
				return nil, err
			}
		case lib.ActionRemove:
			if err := container.Remove(entry, lib.CaseRemovePrefix, ignoreIPType); err != nil {
				return nil, err
			}
		default:
			return nil, lib.ErrUnknownAction
		}
	}

	return container, nil
}

// getReader 支持本地文件、远程 URL，以及 gzip 压缩（.gz 后缀）
func (g *countryCSVIn) getReader(uri string) (io.ReadCloser, error) {
	var f io.ReadCloser
	var err error

	switch {
	case strings.HasPrefix(strings.ToLower(uri), "http://"), strings.HasPrefix(strings.ToLower(uri), "https://"):
		f, err = lib.GetRemoteURLReader(uri)
	default:
		f, err = os.Open(uri)
	}
	if err != nil {
		return nil, err
	}

	uriLower := strings.ToLower(uri)
	if strings.HasSuffix(uriLower, ".gz") || strings.Contains(uriLower, ".gz?") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &gzipReadCloser{Reader: gr, underlying: f}, nil
	}

	return f, nil
}

type gzipReadCloser struct {
	*gzip.Reader
	underlying io.Closer
}

func (g *gzipReadCloser) Close() error {
	err := g.Reader.Close()
	if errU := g.underlying.Close(); errU != nil {
		return errU
	}
	return err
}

// ================================================================
// 核心：解析 CSV → 对齐 /24、/48 → 去重 → 按国家分组写入 entry
// ================================================================

// expandPrefix 将前缀按精度截断到 IPv4 /24、IPv6 /48
func expandPrefix(p netip.Prefix) netip.Prefix {
	bits := p.Bits()
	addr := p.Addr()

	if addr.Is4() {
		if bits < 24 {
			return p // 本身比 /24 还宽，无需缩小
		}
		if norm, err := addr.Prefix(24); err == nil {
			return norm
		}
		return p
	}
	// IPv6
	if bits < 48 {
		return p
	}
	if norm, err := addr.Prefix(48); err == nil {
		return norm
	}
	return p
}

type prefixSet map[netip.Prefix]struct{}

func (g *countryCSVIn) process(uri string, entries map[string]*lib.Entry) error {
	if entries == nil {
		entries = make(map[string]*lib.Entry, 300)
	}

	f, err := g.getReader(uri)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	// ---------- 解析表头，定位列 ----------
	header, err := reader.Read()
	if err != nil {
		return err
	}

	networkIdx, ccIdx := -1, -1
	for i, title := range header {
		t := strings.ToLower(strings.TrimSpace(title))
		switch t {
		case "network":
			if networkIdx < 0 {
				networkIdx = i
			}
		case "country_code":
			if ccIdx < 0 {
				ccIdx = i
			}
		}
	}
	if networkIdx < 0 || ccIdx < 0 {
		return fmt.Errorf("❌ [type %s | action %s] invalid CSV header: %v", typeCountryCSVIn, g.Action, header)
	}

	// ---------- 按国家名 → 已去重前缀集合 ----------
	seen := make(map[string]prefixSet, 300)

	rowCount := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(record) <= networkIdx || len(record) <= ccIdx {
			continue
		}

		rowCount++

		cidrStr := strings.TrimSpace(record[networkIdx])
		cc := strings.ToUpper(strings.TrimSpace(record[ccIdx]))
		if cidrStr == "" || cc == "" {
			continue
		}

		// 兴趣过滤
		if len(g.Want) > 0 && !g.Want[cc] {
			continue
		}

		prefix, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			continue
		}

		// ★ 关键：对齐到 /24 或 /48
		prefix = expandPrefix(prefix)

		// 去重
		set, ok := seen[cc]
		if !ok {
			set = make(prefixSet, 1024)
			seen[cc] = set
		}
		if _, dup := set[prefix]; dup {
			continue
		}
		set[prefix] = struct{}{}

		// 写入 entry
		entry, ok := entries[cc]
		if !ok {
			entry = lib.NewEntry(cc)
		}
		if err := entry.AddPrefix(prefix.String()); err != nil {
			return err
		}
		entries[cc] = entry
	}

	fmt.Printf("    ipinfo country CSV: %d rows read, %d countries, %d unique prefixes after /24+/48 alignment\n",
		rowCount, len(seen), totalPrefixes(seen))

	return nil
}

func totalPrefixes(sets map[string]prefixSet) int {
	n := 0
	for _, s := range sets {
		n += len(s)
	}
	return n
}