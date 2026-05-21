package registry

import "sort"

// TagInfo describes a registered CBOR tag from the IANA registry.
type TagInfo struct {
	Tag       uint64
	DataItem  string
	Semantics string
	Reference string
}

// tagRegistry is the package-level lookup table populated at init time.
var tagRegistry map[uint64]TagInfo

func init() {
	tagRegistry = map[uint64]TagInfo{
		0:     {Tag: 0, DataItem: "text string", Semantics: "Standard date/time string; see Section 3.4.1 of RFC 8949", Reference: "RFC 8949"},
		1:     {Tag: 1, DataItem: "integer or float", Semantics: "Epoch-based date/time; see Section 3.4.2 of RFC 8949", Reference: "RFC 8949"},
		2:     {Tag: 2, DataItem: "byte string", Semantics: "Unsigned bignum; see Section 3.4.3 of RFC 8949", Reference: "RFC 8949"},
		3:     {Tag: 3, DataItem: "byte string", Semantics: "Negative bignum; see Section 3.4.3 of RFC 8949", Reference: "RFC 8949"},
		4:     {Tag: 4, DataItem: "array", Semantics: "Decimal fraction", Reference: "RFC 8949"},
		5:     {Tag: 5, DataItem: "array", Semantics: "Bigfloat", Reference: "RFC 8949"},
		16:    {Tag: 16, DataItem: "COSE_Encrypt0", Semantics: "COSE Single Recipient Encrypted Data Object", Reference: "RFC 9052"},
		17:    {Tag: 17, DataItem: "COSE_Mac0", Semantics: "COSE Mac w/o Recipients Object", Reference: "RFC 9052"},
		18:    {Tag: 18, DataItem: "COSE_Sign1", Semantics: "COSE Single Signer Data Object", Reference: "RFC 9052"},
		21:    {Tag: 21, DataItem: "multiple", Semantics: "Expected conversion to base64url encoding", Reference: "RFC 8949"},
		22:    {Tag: 22, DataItem: "multiple", Semantics: "Expected conversion to base64 encoding", Reference: "RFC 8949"},
		23:    {Tag: 23, DataItem: "multiple", Semantics: "Expected conversion to base16 encoding", Reference: "RFC 8949"},
		24:    {Tag: 24, DataItem: "byte string", Semantics: "Encoded CBOR data item", Reference: "RFC 8949"},
		32:    {Tag: 32, DataItem: "text string", Semantics: "URI", Reference: "RFC 8949"},
		33:    {Tag: 33, DataItem: "text string", Semantics: "base64url", Reference: "RFC 8949"},
		34:    {Tag: 34, DataItem: "text string", Semantics: "base64", Reference: "RFC 8949"},
		35:    {Tag: 35, DataItem: "text string", Semantics: "Regular expression", Reference: "RFC 7049"},
		36:    {Tag: 36, DataItem: "text string", Semantics: "MIME message", Reference: "RFC 7049"},
		96:    {Tag: 96, DataItem: "COSE_Encrypt", Semantics: "COSE Encrypted Data Object", Reference: "RFC 9052"},
		97:    {Tag: 97, DataItem: "COSE_Mac", Semantics: "COSE MACed Data Object", Reference: "RFC 9052"},
		98:    {Tag: 98, DataItem: "COSE_Sign", Semantics: "COSE Signed Data Object", Reference: "RFC 9052"},
		258:   {Tag: 258, DataItem: "array", Semantics: "Mathematical finite set", Reference: "RFC 9557"},
		55799: {Tag: 55799, DataItem: "multiple", Semantics: "Self-Described CBOR", Reference: "RFC 8949"},
	}
}

// LookupTag returns the TagInfo for a registered CBOR tag, or nil if the
// tag is not in the IANA registry.
func LookupTag(tag uint64) *TagInfo {
	info, ok := tagRegistry[tag]
	if !ok {
		return nil
	}
	return &info
}

// IsRegistered reports whether a CBOR tag number is present in the IANA
// registry.
func IsRegistered(tag uint64) bool {
	_, ok := tagRegistry[tag]
	return ok
}

// AllTags returns all registered tags sorted by tag number.
func AllTags() []TagInfo {
	tags := make([]TagInfo, 0, len(tagRegistry))
	for _, info := range tagRegistry {
		tags = append(tags, info)
	}
	sort.Slice(tags, func(i, j int) bool {
		return tags[i].Tag < tags[j].Tag
	})
	return tags
}
