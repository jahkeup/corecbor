// Command cbor-registry-gen fetches the IANA CBOR Tags registry and generates
// Go source code containing tag constants and registry lookup data.
//
// Usage:
//
//	# Fetch from IANA and update cache + generated code:
//	go run ./cmd/cbor-registry-gen -fetch -cache registry/registry.json -out registry/tags_gen.go
//
//	# Generate from existing cache (no network):
//	go run ./cmd/cbor-registry-gen -cache registry/registry.json -out registry/tags_gen.go
//
//	# Generate subset:
//	go run ./cmd/cbor-registry-gen -cache registry/registry.json -out registry/tags_gen.go -subset 0,1,2,3,24,55799
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode"
)

type cacheFile struct {
	FetchedAt string     `json:"fetched_at"`
	Source    string     `json:"source"`
	Tags      []tagEntry `json:"tags"`
}

type tagEntry struct {
	Tag       uint64 `json:"tag"`
	DataItem  string `json:"data_item"`
	Semantics string `json:"semantics"`
	Reference string `json:"reference"`
}

var tagNames = map[uint64]string{
	0:     "DateTimeString",
	1:     "EpochDateTime",
	2:     "UnsignedBignum",
	3:     "NegativeBignum",
	4:     "DecimalFraction",
	5:     "Bigfloat",
	16:    "COSEEncrypt0",
	17:    "COSEMac0",
	18:    "COSESign1",
	21:    "Base64URL",
	22:    "Base64",
	23:    "Base16",
	24:    "EncodedCBOR",
	32:    "URI",
	33:    "Base64URLText",
	34:    "Base64Text",
	35:    "Regexp",
	36:    "MIME",
	55799: "SelfDescribe",
	96:    "COSEEncrypt",
	97:    "COSEMac",
	98:    "COSESign",
	258:   "MathSet",
}

const ianaTagsCSVURL = "https://www.iana.org/assignments/cbor-tags/tags.csv"

func main() {
	cachePath := flag.String("cache", "", "path to registry.json cache file (required)")
	outPath := flag.String("out", "", "output file path for generated Go (default: stdout)")
	pkgName := flag.String("package", "registry", "package name for generated code")
	subset := flag.String("subset", "", "comma-separated tag numbers to include (default: all)")
	fetch := flag.Bool("fetch", false, "fetch latest registry from IANA before generating")
	flag.Parse()

	if *cachePath == "" {
		fmt.Fprintf(os.Stderr, "error: -cache flag is required\n")
		os.Exit(1)
	}

	if *fetch {
		if err := fetchIANA(*cachePath); err != nil {
			fmt.Fprintf(os.Stderr, "error fetching registry: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "fetched IANA CBOR tags registry to %s\n", *cachePath)
	}

	data, err := os.ReadFile(*cachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading cache: %v\n", err)
		os.Exit(1)
	}

	var cache cacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing cache: %v\n", err)
		os.Exit(1)
	}

	tags := cache.Tags
	if *subset != "" {
		allowed := parseSubset(*subset)
		var filtered []tagEntry
		for _, t := range tags {
			if allowed[t.Tag] {
				filtered = append(filtered, t)
			}
		}
		tags = filtered
	}

	sort.Slice(tags, func(i, j int) bool {
		return tags[i].Tag < tags[j].Tag
	})

	out := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	tmplData := templateData{
		Package: *pkgName,
		Tags:    make([]templateTag, 0, len(tags)),
	}
	seen := make(map[string]bool)
	for _, t := range tags {
		name := tagNames[t.Tag]
		if name == "" {
			name = deriveName(t.Semantics)
		}
		if seen[name] {
			name = fmt.Sprintf("%s_%d", name, t.Tag)
		}
		seen[name] = true
		tmplData.Tags = append(tmplData.Tags, templateTag{
			Name:      name,
			Tag:       t.Tag,
			DataItem:  t.DataItem,
			Semantics: t.Semantics,
			Reference: t.Reference,
		})
	}

	if err := genTemplate.Execute(out, tmplData); err != nil {
		fmt.Fprintf(os.Stderr, "error executing template: %v\n", err)
		os.Exit(1)
	}
}

func parseSubset(s string) map[uint64]bool {
	m := make(map[uint64]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: ignoring invalid subset value %q\n", part)
			continue
		}
		m[n] = true
	}
	return m
}

func deriveName(semantics string) string {
	var b strings.Builder
	upper := true
	for _, r := range semantics {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			upper = true
			continue
		}
		if upper {
			b.WriteRune(unicode.ToUpper(r))
			upper = false
		} else {
			b.WriteRune(r)
		}
		if b.Len() >= 40 {
			break
		}
	}
	name := b.String()
	goKeywords := map[string]bool{
		"break": true, "case": true, "chan": true, "const": true,
		"continue": true, "default": true, "defer": true, "else": true,
		"fallthrough": true, "for": true, "func": true, "go": true,
		"goto": true, "if": true, "import": true, "interface": true,
		"map": true, "package": true, "range": true, "return": true,
		"select": true, "struct": true, "switch": true, "type": true,
		"var": true,
	}
	if goKeywords[strings.ToLower(name)] {
		name += "Tag"
	}
	return name
}

type templateData struct {
	Package string
	Tags    []templateTag
}

type templateTag struct {
	Name      string
	Tag       uint64
	DataItem  string
	Semantics string
	Reference string
}

var funcMap = template.FuncMap{
	"oneline": func(s string) string {
		s = strings.ReplaceAll(s, "\n", " ")
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.Join(strings.Fields(s), " ")
		if len(s) > 80 {
			s = s[:77] + "..."
		}
		return s
	},
}

var genTemplate = template.Must(template.New("gen").Funcs(funcMap).Parse(`// Code generated by cbor-registry-gen. DO NOT EDIT.

package {{.Package}}

const (
{{- range .Tags}}
	// Tag{{.Name}} is tag {{.Tag}}: {{oneline .Semantics}}
	Tag{{.Name}} uint64 = {{.Tag}}
{{end}})
`))

func fetchIANA(cachePath string) error {
	resp, err := http.Get(ianaTagsCSVURL)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", ianaTagsCSVURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, ianaTagsCSVURL)
	}

	tags, err := parseIANACSV(resp.Body)
	if err != nil {
		return fmt.Errorf("parsing CSV: %w", err)
	}

	sort.Slice(tags, func(i, j int) bool { return tags[i].Tag < tags[j].Tag })

	cache := cacheFile{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Source:    ianaTagsCSVURL,
		Tags:      tags,
	}

	out, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	if err := os.WriteFile(cachePath, out, 0o644); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	return nil
}

func parseIANACSV(r io.Reader) ([]tagEntry, error) {
	reader := csv.NewReader(r)
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}

	tagCol, hasTag := colIdx["tag"]
	dataCol, hasData := colIdx["data item"]
	semCol, hasSem := colIdx["semantics"]
	refCol, hasRef := colIdx["reference"]
	if !hasTag || !hasSem {
		return nil, fmt.Errorf("CSV missing required columns (need 'Tag' and 'Semantics')")
	}

	var tags []tagEntry
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading row: %w", err)
		}

		tagStr := strings.TrimSpace(row[tagCol])
		if tagStr == "" {
			continue
		}
		if strings.Contains(tagStr, "-") {
			continue
		}

		tagNum, err := strconv.ParseUint(tagStr, 10, 64)
		if err != nil {
			continue
		}

		semantics := ""
		if hasSem && semCol < len(row) {
			semantics = strings.TrimSpace(row[semCol])
		}
		if semantics == "" {
			continue
		}

		dataItem := ""
		if hasData && dataCol < len(row) {
			dataItem = strings.TrimSpace(row[dataCol])
		}

		reference := ""
		if hasRef && refCol < len(row) {
			reference = strings.TrimSpace(row[refCol])
		}

		tags = append(tags, tagEntry{
			Tag:       tagNum,
			DataItem:  dataItem,
			Semantics: semantics,
			Reference: reference,
		})
	}

	return tags, nil
}
