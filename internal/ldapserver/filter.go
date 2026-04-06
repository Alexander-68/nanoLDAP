package ldapserver

import (
	"strings"
)

type Filter interface {
	Match(attrs map[string][]string) bool
}

type andFilter []Filter
type orFilter []Filter
type equalityFilter struct {
	attr  string
	value string
}
type presentFilter struct {
	attr string
}

func (f andFilter) Match(attrs map[string][]string) bool {
	for _, child := range f {
		if !child.Match(attrs) {
			return false
		}
	}
	return true
}

func (f orFilter) Match(attrs map[string][]string) bool {
	for _, child := range f {
		if child.Match(attrs) {
			return true
		}
	}
	return false
}

func (f equalityFilter) Match(attrs map[string][]string) bool {
	values := attrs[strings.ToLower(f.attr)]
	for _, value := range values {
		if matchesAttributeValue(f.attr, value, f.value) {
			return true
		}
	}
	return false
}

func (f presentFilter) Match(attrs map[string][]string) bool {
	_, ok := attrs[strings.ToLower(f.attr)]
	return ok
}

func parseFilter(pkt packet) (Filter, error) {
	switch {
	case pkt.class == classContext && pkt.tag == 0:
		children := make([]Filter, 0, len(pkt.children))
		for _, child := range pkt.children {
			parsed, err := parseFilter(child)
			if err != nil {
				return nil, err
			}
			children = append(children, parsed)
		}
		return andFilter(children), nil
	case pkt.class == classContext && pkt.tag == 1:
		children := make([]Filter, 0, len(pkt.children))
		for _, child := range pkt.children {
			parsed, err := parseFilter(child)
			if err != nil {
				return nil, err
			}
			children = append(children, parsed)
		}
		return orFilter(children), nil
	case pkt.class == classContext && pkt.tag == 3:
		if err := expectChildren(pkt, 2); err != nil {
			return nil, err
		}
		return equalityFilter{attr: pkt.children[0].str(), value: pkt.children[1].str()}, nil
	case pkt.class == classContext && pkt.tag == 7:
		return presentFilter{attr: pkt.str()}, nil
	default:
		return presentFilter{attr: "objectClass"}, nil
	}
}

func matchesAttributeValue(attr, actual, wanted string) bool {
	switch strings.ToLower(attr) {
	case "member", "memberof", "uniquemember":
		return normalizeComparableDN(actual) == normalizeComparableDN(wanted)
	default:
		return strings.EqualFold(actual, wanted)
	}
}

func normalizeComparableDN(dn string) string {
	normalized := normalizeDN(dn)
	normalized = strings.Replace(normalized, ",ou=people,", ",", 1)
	normalized = strings.Replace(normalized, ",ou=groups,", ",", 1)
	return normalized
}
