package ipinfo

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
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

	// Filter want list
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

	if strings.HasSuffix(strings.ToLower(uri), ".gz") {
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
	if errUnderlying := g.underlying.Close(); errUnderlying != nil {
		return errUnderlying
	}
	return err
}

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
	reader.FieldsPerRecord = -1 // 字段数不固定也能解析
	reader.LazyQuotes = true

	// 解析表头，定位 network 和 country_code 列
	// network,country,country_code,continent,continent_code,asn,as_name,as_domain
	header, err := reader.Read()
	if err != nil {
		return err
	}

	networkIndex, countryCodeIndex := -1, -1
	for i, title := range header {
		switch strings.ToLower(strings.TrimSpace(title)) {
		case "network", "range", "start_ip": // 兼容不同版本的列名
			if networkIndex < 0 {
				networkIndex = i
			}
		case "country_code", "country":
			// 优先使用 country_code
			if strings.EqualFold(strings.TrimSpace(title), "country_code") || countryCodeIndex < 0 {
				countryCodeIndex = i
			}
		}
	}
	if networkIndex < 0 || countryCodeIndex < 0 {
		return fmt.Errorf("❌ [type %s | action %s] invalid CSV header: %v", typeCountryCSVIn, g.Action, header)
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) <= networkIndex || len(record) <= countryCodeIndex {
			return fmt.Errorf("❌ [type %s | action %s] invalid record: %v", typeCountryCSVIn, g.Action, record)
		}

		cidrStr := strings.ToLower(strings.TrimSpace(record[networkIndex]))
		countryCode := strings.ToUpper(strings.TrimSpace(record[countryCodeIndex]))
		if cidrStr == "" || countryCode == "" {
			continue
		}

		if len(g.Want) > 0 && !g.Want[countryCode] {
			continue
		}

		entry, found := entries[countryCode]
		if !found {
			entry = lib.NewEntry(countryCode)
		}
		if err := entry.AddPrefix(cidrStr); err != nil {
			return err
		}
		entries[countryCode] = entry
	}

	return nil
}