// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package registry

import (
	_ "embed"
	"encoding/json"
	"sort"
)

// TagInfo describes a registered CBOR tag from the IANA registry.
type TagInfo struct {
	Tag       uint64 `json:"tag"`
	DataItem  string `json:"data_item"`
	Semantics string `json:"semantics"`
	Reference string `json:"reference"`
}

//go:embed registry.json
var registryJSON []byte

var tagRegistry map[uint64]TagInfo

func init() {
	var cache struct {
		Tags []TagInfo `json:"tags"`
	}
	if err := json.Unmarshal(registryJSON, &cache); err != nil {
		panic("registry: failed to parse embedded registry.json: " + err.Error())
	}
	tagRegistry = make(map[uint64]TagInfo, len(cache.Tags))
	for _, t := range cache.Tags {
		tagRegistry[t.Tag] = t
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
