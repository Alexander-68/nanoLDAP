package ldapserver

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func decodeMessages(payload []byte) ([]packet, error) {
	reader := bytes.NewReader(payload)
	messages := make([]packet, 0, 1)
	for reader.Len() > 0 {
		msg, err := readPacket(reader)
		if err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

func formatDebugMessage(pkt packet) string {
	if pkt.class == classUniversal && pkt.tag == 16 && len(pkt.children) >= 2 {
		messageID, err := pkt.children[0].int()
		if err == nil {
			return fmt.Sprintf("LDAPMessage{id=%d, op=%s}", messageID, formatDebugPacket(pkt.children[1]))
		}
	}
	return formatDebugPacket(pkt)
}

func formatDebugMessages(pkts []packet) string {
	parts := make([]string, 0, len(pkts))
	for _, pkt := range pkts {
		parts = append(parts, formatDebugMessage(pkt))
	}
	return strings.Join(parts, "; ")
}

func formatDebugPacket(pkt packet) string {
	switch {
	case pkt.class == classApplication && pkt.tag == 0:
		return formatBindRequest(pkt)
	case pkt.class == classApplication && pkt.tag == 1:
		return formatResultPacket("BindResponse", pkt)
	case pkt.class == classApplication && pkt.tag == 2:
		return "UnbindRequest{}"
	case pkt.class == classApplication && pkt.tag == 3:
		return formatSearchRequest(pkt)
	case pkt.class == classApplication && pkt.tag == 4:
		return formatSearchEntry(pkt)
	case pkt.class == classApplication && pkt.tag == 5:
		return formatResultPacket("SearchResultDone", pkt)
	default:
		return formatGenericPacket(pkt)
	}
}

func formatBindRequest(pkt packet) string {
	if err := expectChildren(pkt, 3); err != nil {
		return "BindRequest{invalid=true}"
	}
	version, _ := pkt.children[0].int()
	auth := formatAuthChoice(pkt.children[2])
	return fmt.Sprintf("BindRequest{version=%d, dn=%s, authentication=%s}", version, strconv.Quote(pkt.children[1].str()), auth)
}

func formatAuthChoice(pkt packet) string {
	if pkt.class == classContext && pkt.tag == 0 {
		return `simple("<redacted>")`
	}
	return formatGenericPacket(pkt)
}

func formatSearchRequest(pkt packet) string {
	if err := expectChildren(pkt, 8); err != nil {
		return "SearchRequest{invalid=true}"
	}
	scope, _ := pkt.children[1].int()
	derefAliases, _ := pkt.children[2].int()
	sizeLimit, _ := pkt.children[3].int()
	timeLimit, _ := pkt.children[4].int()
	attributes := make([]string, 0, len(pkt.children[7].children))
	for _, attr := range pkt.children[7].children {
		attributes = append(attributes, strconv.Quote(attr.str()))
	}
	return fmt.Sprintf(
		"SearchRequest{baseDN=%s, scope=%s, derefAliases=%d, sizeLimit=%d, timeLimit=%d, typesOnly=%t, filter=%s, attributes=[%s]}",
		strconv.Quote(pkt.children[0].str()),
		scopeName(scope),
		derefAliases,
		sizeLimit,
		timeLimit,
		pkt.children[5].boolean(),
		formatFilterPacket(pkt.children[6]),
		strings.Join(attributes, ", "),
	)
}

func formatSearchEntry(pkt packet) string {
	if err := expectChildren(pkt, 2); err != nil {
		return "SearchResultEntry{invalid=true}"
	}
	attrs := make([]string, 0, len(pkt.children[1].children))
	for _, attr := range pkt.children[1].children {
		if len(attr.children) < 2 {
			continue
		}
		values := make([]string, 0, len(attr.children[1].children))
		for _, value := range attr.children[1].children {
			values = append(values, strconv.Quote(value.str()))
		}
		attrs = append(attrs, fmt.Sprintf("%s=[%s]", attr.children[0].str(), strings.Join(values, ", ")))
	}
	return fmt.Sprintf("SearchResultEntry{dn=%s, attributes=[%s]}", strconv.Quote(pkt.children[0].str()), strings.Join(attrs, ", "))
}

func formatResultPacket(name string, pkt packet) string {
	if err := expectChildren(pkt, 3); err != nil {
		return name + "{invalid=true}"
	}
	code, _ := pkt.children[0].int()
	return fmt.Sprintf(
		"%s{result=%s, matchedDN=%s, diagnostic=%s}",
		name,
		resultCodeName(code),
		strconv.Quote(pkt.children[1].str()),
		strconv.Quote(pkt.children[2].str()),
	)
}

func formatFilterPacket(pkt packet) string {
	switch {
	case pkt.class == classContext && pkt.tag == 0:
		children := make([]string, 0, len(pkt.children))
		for _, child := range pkt.children {
			children = append(children, formatFilterPacket(child))
		}
		return "and(" + strings.Join(children, ", ") + ")"
	case pkt.class == classContext && pkt.tag == 1:
		children := make([]string, 0, len(pkt.children))
		for _, child := range pkt.children {
			children = append(children, formatFilterPacket(child))
		}
		return "or(" + strings.Join(children, ", ") + ")"
	case pkt.class == classContext && pkt.tag == 3 && len(pkt.children) >= 2:
		return fmt.Sprintf("eq(%s=%s)", pkt.children[0].str(), strconv.Quote(pkt.children[1].str()))
	case pkt.class == classContext && pkt.tag == 7:
		return "present(" + pkt.str() + ")"
	default:
		return formatGenericPacket(pkt)
	}
}

func formatGenericPacket(pkt packet) string {
	if len(pkt.children) > 0 {
		children := make([]string, 0, len(pkt.children))
		for _, child := range pkt.children {
			children = append(children, formatGenericPacket(child))
		}
		return packetName(pkt) + "{" + strings.Join(children, ", ") + "}"
	}
	switch {
	case pkt.class == classUniversal && (pkt.tag == 2 || pkt.tag == 10):
		value, err := pkt.int()
		if err == nil {
			return fmt.Sprintf("%s(%d)", packetName(pkt), value)
		}
	case pkt.class == classUniversal && pkt.tag == 1:
		return fmt.Sprintf("%s(%t)", packetName(pkt), pkt.boolean())
	case len(pkt.content) > 0:
		return fmt.Sprintf("%s(%s)", packetName(pkt), strconv.Quote(pkt.str()))
	}
	return packetName(pkt) + "()"
}

func packetName(pkt packet) string {
	switch pkt.class {
	case classUniversal:
		switch pkt.tag {
		case 1:
			return "BOOLEAN"
		case 2:
			return "INTEGER"
		case 4:
			return "OCTET_STRING"
		case 10:
			return "ENUMERATED"
		case 16:
			return "SEQUENCE"
		case 17:
			return "SET"
		}
	case classApplication:
		return ldapOpName(pkt.tag)
	case classContext:
		return fmt.Sprintf("CONTEXT[%d]", pkt.tag)
	}
	return fmt.Sprintf("CLASS[%d:%d]", pkt.class, pkt.tag)
}

func ldapOpName(tag int) string {
	switch tag {
	case 0:
		return "BindRequest"
	case 1:
		return "BindResponse"
	case 2:
		return "UnbindRequest"
	case 3:
		return "SearchRequest"
	case 4:
		return "SearchResultEntry"
	case 5:
		return "SearchResultDone"
	case 7:
		return "ModifyResponse"
	case 9:
		return "AddResponse"
	case 11:
		return "DelResponse"
	case 13:
		return "ModifyDNResponse"
	default:
		return fmt.Sprintf("APPLICATION[%d]", tag)
	}
}

func scopeName(scope int) string {
	switch scope {
	case scopeBaseObject:
		return "baseObject"
	case scopeSingle:
		return "singleLevel"
	case scopeSubtree:
		return "subtree"
	default:
		return fmt.Sprintf("scope(%d)", scope)
	}
}

func resultCodeName(code int) string {
	switch code {
	case resultSuccess:
		return "success"
	case resultProtocolError:
		return "protocolError"
	case resultInvalidDNSyntax:
		return "invalidDNSyntax"
	case resultAdminLimitExceeded:
		return "adminLimitExceeded"
	case resultAuthMethodNotSupported:
		return "authMethodNotSupported"
	case resultInvalidCredentials:
		return "invalidCredentials"
	case resultInsufficientAccessRights:
		return "insufficientAccessRights"
	case resultBusy:
		return "busy"
	case resultUnwillingToPerform:
		return "unwillingToPerform"
	default:
		return fmt.Sprintf("code(%d)", code)
	}
}
