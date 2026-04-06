package ldapserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"nanoldap/internal/audit"
	"nanoldap/internal/config"
	"nanoldap/internal/store"
)

const (
	scopeBaseObject = 0
	scopeSingle     = 1
	scopeSubtree    = 2

	resultSuccess                  = 0
	resultProtocolError            = 2
	resultInvalidCredentials       = 49
	resultInsufficientAccessRights = 50
	resultBusy                     = 51
	resultUnwillingToPerform       = 53
	resultInvalidDNSyntax          = 34
	resultAuthMethodNotSupported   = 7
	resultAdminLimitExceeded       = 11
)

type Server struct {
	cfg         config.Config
	store       *store.Store
	audit       *audit.Logger
	connTokens  chan struct{}
	bindLimiter *windowLimiter
}

type connState struct {
	user              store.User
	bound             bool
	anonymous         bool
	hadSuccessfulBind bool
	searchLimiter     rateCounter
	sourceIP          string
}

type ldapMessage struct {
	id   int
	op   packet
	raw  packet
	done bool
}

type searchRequest struct {
	baseDN     string
	scope      int
	filter     Filter
	attributes []string
}

type directoryEntry struct {
	dn               string
	attrs            map[string][]string
	operationalAttrs map[string]struct{}
}

type rateCounter struct {
	windowStart time.Time
	count       int
}

type windowLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	entries map[string][]time.Time
}

func New(cfg config.Config, dataStore *store.Store, auditLog *audit.Logger) *Server {
	return &Server{
		cfg:         cfg,
		store:       dataStore,
		audit:       auditLog,
		connTokens:  make(chan struct{}, cfg.LDAPMaxConnections),
		bindLimiter: &windowLimiter{window: cfg.LDAPBindWindow, limit: cfg.LDAPBindLimit, entries: make(map[string][]time.Time)},
	}
}

func (s *Server) TLSListener(ln net.Listener) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}), nil
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case s.connTokens <- struct{}{}:
			go func() {
				defer func() { <-s.connTokens }()
				_ = s.handleConn(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handleConn(conn net.Conn) error {
	defer conn.Close()
	state := &connState{sourceIP: remoteIP(conn.RemoteAddr())}
	reader := bufio.NewReader(conn)
	for {
		if err := conn.SetDeadline(time.Now().Add(s.cfg.LDAPIdleTimeout)); err != nil {
			return err
		}
		msg, err := readMessage(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil
			}
			return nil
		}
		response, closeConn := s.handleMessage(context.Background(), state, msg)
		if len(response) > 0 {
			if _, err := conn.Write(response); err != nil {
				return nil
			}
		}
		if closeConn {
			return nil
		}
	}
}

func (s *Server) handleMessage(ctx context.Context, state *connState, msg ldapMessage) ([]byte, bool) {
	switch {
	case msg.op.class == classApplication && msg.op.tag == 0:
		return s.handleBind(ctx, state, msg)
	case msg.op.class == classApplication && msg.op.tag == 2:
		return nil, true
	case msg.op.class == classApplication && msg.op.tag == 3:
		return s.handleSearch(ctx, state, msg), false
	case msg.op.class == classApplication && slices.Contains([]int{6, 8, 10, 12}, msg.op.tag):
		return berMessage(msg.id, resultPacket(msg.op.tag+1, resultUnwillingToPerform, "", "directory is read-only")), false
	default:
		return berMessage(msg.id, resultPacket(1, resultProtocolError, "", "unsupported LDAP operation")), false
	}
}

func (s *Server) handleBind(ctx context.Context, state *connState, msg ldapMessage) ([]byte, bool) {
	if !s.bindLimiter.Allow(state.sourceIP) {
		s.audit.LDAPBind(state.sourceIP, "", "rate_limited")
		return berMessage(msg.id, resultPacket(1, resultBusy, "", "bind rate limit exceeded")), true
	}
	if state.hadSuccessfulBind {
		return berMessage(msg.id, resultPacket(1, resultUnwillingToPerform, "", "only one successful bind is allowed per connection")), false
	}
	if err := expectChildren(msg.op, 3); err != nil {
		return berMessage(msg.id, resultPacket(1, resultProtocolError, "", "invalid bind request")), false
	}
	version, err := msg.op.children[0].int()
	if err != nil || version != 3 {
		return berMessage(msg.id, resultPacket(1, resultProtocolError, "", "unsupported LDAP version")), false
	}
	dn := msg.op.children[1].str()
	authChoice := msg.op.children[2]
	if authChoice.class != classContext || authChoice.tag != 0 {
		return berMessage(msg.id, resultPacket(1, resultAuthMethodNotSupported, "", "only simple bind is supported")), false
	}
	password := authChoice.str()
	if dn == "" && password == "" {
		state.bound = true
		state.anonymous = true
		state.hadSuccessfulBind = true
		s.audit.LDAPBind(state.sourceIP, "", "anonymous")
		return berMessage(msg.id, resultPacket(1, resultSuccess, "", "")), false
	}

	username, ok := usernameFromDN(s.cfg.BaseDN, dn)
	if !ok {
		s.audit.LDAPBind(state.sourceIP, dn, "invalid_dn")
		return berMessage(msg.id, resultPacket(1, resultInvalidDNSyntax, "", "invalid bind DN")), false
	}
	user, err := s.store.AuthenticateUser(ctx, username, password)
	if err != nil {
		s.audit.LDAPBind(state.sourceIP, username, "invalid_credentials")
		return berMessage(msg.id, resultPacket(1, resultInvalidCredentials, "", "invalid credentials")), false
	}
	if user.Disabled {
		s.audit.LDAPBind(state.sourceIP, username, "user_disabled")
		return berMessage(msg.id, resultPacket(1, resultInvalidCredentials, "", "user is disabled")), false
	}
	state.user = user
	state.bound = true
	state.anonymous = false
	state.hadSuccessfulBind = true
	s.audit.LDAPBind(state.sourceIP, username, "success")
	return berMessage(msg.id, resultPacket(1, resultSuccess, "", "")), false
}

func (s *Server) handleSearch(ctx context.Context, state *connState, msg ldapMessage) []byte {
	if !state.searchLimiter.Allow(s.cfg.LDAPSearchRate) {
		return berMessage(msg.id, resultPacket(5, resultAdminLimitExceeded, "", "search rate limit exceeded"))
	}
	request, err := parseSearchRequest(msg.op)
	if err != nil {
		return berMessage(msg.id, resultPacket(5, resultProtocolError, "", "invalid search request"))
	}

	var responses [][]byte
	if !state.bound || state.anonymous {
		if !isAnonymousRootDSERequest(request) {
			return berMessage(msg.id, resultPacket(5, resultInsufficientAccessRights, "", "anonymous access is restricted to Root DSE"))
		}
		responses = append(responses, berMessage(msg.id, searchEntryPacket(rootDSE(s.cfg.BaseDN), request.attributes)))
		responses = append(responses, berMessage(msg.id, resultPacket(5, resultSuccess, "", "")))
		return bytesJoin(responses)
	}

	entries, err := s.visibleEntries(ctx, state.user)
	if err != nil {
		return berMessage(msg.id, resultPacket(5, resultBusy, "", "directory unavailable"))
	}
	for _, entry := range entries {
		if !dnWithinScope(request.baseDN, request.scope, entry.dn) {
			continue
		}
		if request.filter != nil && !request.filter.Match(entry.attrs) {
			continue
		}
		responses = append(responses, berMessage(msg.id, searchEntryPacket(entry, request.attributes)))
	}
	responses = append(responses, berMessage(msg.id, resultPacket(5, resultSuccess, "", "")))
	return bytesJoin(responses)
}

func parseSearchRequest(pkt packet) (searchRequest, error) {
	if err := expectChildren(pkt, 8); err != nil {
		return searchRequest{}, err
	}
	scope, err := pkt.children[1].int()
	if err != nil {
		return searchRequest{}, err
	}
	filter, err := parseFilter(pkt.children[6])
	if err != nil {
		return searchRequest{}, err
	}
	var attributes []string
	for _, child := range pkt.children[7].children {
		attributes = append(attributes, child.str())
	}
	return searchRequest{
		baseDN:     pkt.children[0].str(),
		scope:      scope,
		filter:     filter,
		attributes: attributes,
	}, nil
}

func (s *Server) visibleEntries(ctx context.Context, user store.User) ([]directoryEntry, error) {
	allUsers, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	allGroups, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	entries := []directoryEntry{
		baseEntry(s.cfg.BaseDN),
		containerEntry("people", s.cfg.BaseDN),
		containerEntry("groups", s.cfg.BaseDN),
	}
	adminScope := store.IsMemberOf(user, "admins", "mvradmins")
	allowedUsernames := map[string]struct{}{user.Username: {}}
	allowedGroups := map[string]struct{}{}
	if adminScope {
		for _, group := range allGroups {
			allowedGroups[group.Name] = struct{}{}
		}
		for _, candidate := range allUsers {
			allowedUsernames[candidate.Username] = struct{}{}
		}
	} else {
		for _, group := range user.Groups {
			allowedGroups[group.Name] = struct{}{}
		}
	}

	for _, candidate := range allUsers {
		if _, ok := allowedUsernames[candidate.Username]; !ok {
			continue
		}
		entries = append(entries, userEntry(candidate, s.cfg.BaseDN))
	}
	for _, group := range allGroups {
		if _, ok := allowedGroups[group.Name]; !ok {
			continue
		}
		entries = append(entries, groupEntry(group, s.cfg.BaseDN))
	}
	return entries, nil
}

func readMessage(reader *bufio.Reader) (ldapMessage, error) {
	root, err := readPacket(reader)
	if err != nil {
		return ldapMessage{}, err
	}
	if root.class != classUniversal || root.tag != 16 || len(root.children) < 2 {
		return ldapMessage{}, errors.New("invalid LDAP message")
	}
	messageID, err := root.children[0].int()
	if err != nil {
		return ldapMessage{}, err
	}
	return ldapMessage{id: messageID, op: root.children[1], raw: root}, nil
}

func resultPacket(appTag, resultCode int, matchedDN, diagnostic string) []byte {
	return berApplication(appTag, bytesJoin([][]byte{
		berEnumerated(resultCode),
		berOctetString(matchedDN),
		berOctetString(diagnostic),
	}))
}

func searchEntryPacket(entry directoryEntry, requested []string) []byte {
	var attributes [][]byte
	for name, values := range selectedAttributes(entry, requested) {
		var setValues [][]byte
		for _, value := range values {
			setValues = append(setValues, berOctetString(value))
		}
		attributes = append(attributes, berSequence(
			berOctetString(name),
			berSet(setValues...),
		))
	}
	return berApplication(4, bytesJoin([][]byte{
		berOctetString(entry.dn),
		berSequence(attributes...),
	}))
}

func selectedAttributes(entry directoryEntry, requested []string) map[string][]string {
	if slices.Contains(requested, "1.1") {
		return map[string][]string{}
	}

	if len(requested) == 0 {
		return entry.attrs
	}

	includeUserAttrs := requestsAllUserAttributes(requested)
	includeOperationalAttrs := requestsAllOperationalAttributes(requested)
	if includeUserAttrs && includeOperationalAttrs {
		return entry.attrs
	}

	selected := make(map[string][]string)
	for _, name := range requested {
		name = strings.ToLower(name)
		switch name {
		case "*", "+", "all":
			continue
		}
		if values, ok := entry.attrs[name]; ok {
			selected[name] = values
		}
	}
	if includeUserAttrs {
		for name, values := range entry.attrs {
			if isOperationalAttribute(entry, name) {
				continue
			}
			selected[name] = values
		}
	}
	if includeOperationalAttrs {
		for name, values := range entry.attrs {
			if !isOperationalAttribute(entry, name) {
				continue
			}
			selected[name] = values
		}
	}
	return selected
}

func isAnonymousRootDSERequest(request searchRequest) bool {
	return request.baseDN == "" && (request.scope == scopeBaseObject || request.scope == scopeSubtree)
}

func requestsAllUserAttributes(requested []string) bool {
	for _, name := range requested {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "*", "all":
			return true
		}
	}
	return false
}

func requestsAllOperationalAttributes(requested []string) bool {
	for _, name := range requested {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "+", "all":
			return true
		}
	}
	return false
}

func isOperationalAttribute(entry directoryEntry, name string) bool {
	_, ok := entry.operationalAttrs[strings.ToLower(name)]
	return ok
}

func rootDSE(baseDN string) directoryEntry {
	return directoryEntry{
		dn: "",
		attrs: map[string][]string{
			"namingcontexts":       {baseDN},
			"supportedldapversion": {"3"},
			"vendorname":           {"NanoLDAP"},
			"objectclass":          {"top"},
		},
		operationalAttrs: map[string]struct{}{
			"namingcontexts":       {},
			"supportedldapversion": {},
			"vendorname":           {},
		},
	}
}

func baseEntry(baseDN string) directoryEntry {
	return directoryEntry{
		dn: baseDN,
		attrs: map[string][]string{
			"objectclass": {"top", "domain"},
			"dc":          {strings.Split(strings.TrimPrefix(strings.ToLower(baseDN), "dc="), ",")[0]},
		},
	}
}

func containerEntry(ou, baseDN string) directoryEntry {
	return directoryEntry{
		dn: "ou=" + ou + "," + baseDN,
		attrs: map[string][]string{
			"objectclass": {"top", "organizationalUnit"},
			"ou":          {ou},
		},
	}
}

func userEntry(user store.User, baseDN string) directoryEntry {
	memberOf := make([]string, 0, len(user.Groups))
	for _, group := range user.Groups {
		memberOf = append(memberOf, groupDN(baseDN, group.Name))
	}
	return directoryEntry{
		dn: userDN(baseDN, user.Username),
		attrs: map[string][]string{
			"objectclass":       {"inetOrgPerson"},
			"uid":               {user.Username},
			"cn":                {user.Username},
			"displayname":       {user.DisplayName},
			"memberof":          memberOf,
			"distinguishedname": {userDN(baseDN, user.Username)},
		},
	}
}

func groupEntry(group store.Group, baseDN string) directoryEntry {
	members := make([]string, 0, len(group.MemberUIDs))
	for _, member := range group.MemberUIDs {
		members = append(members, userDN(baseDN, member))
	}
	return directoryEntry{
		dn: groupDN(baseDN, group.Name),
		attrs: map[string][]string{
			"objectclass":  {"groupOfNames"},
			"cn":           {group.Name},
			"member":       members,
			"uniquemember": members,
			"memberuid":    append([]string(nil), group.MemberUIDs...),
		},
	}
}

func userDN(baseDN, username string) string {
	return fmt.Sprintf("uid=%s,ou=people,%s", username, baseDN)
}

func groupDN(baseDN, name string) string {
	return fmt.Sprintf("cn=%s,ou=groups,%s", name, baseDN)
}

func dnWithinScope(baseDN string, scope int, entryDN string) bool {
	base := normalizeDN(baseDN)
	entry := normalizeDN(entryDN)
	switch scope {
	case scopeBaseObject:
		return entry == base
	case scopeSingle:
		return parentDN(entry) == base
	case scopeSubtree:
		return entry == base || strings.HasSuffix(entry, ","+base)
	default:
		return false
	}
}

func parentDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func usernameFromDN(baseDN, dn string) (string, bool) {
	normalized := normalizeDN(dn)
	suffix := ",ou=people," + normalizeDN(baseDN)
	if !strings.HasSuffix(normalized, suffix) {
		return "", false
	}
	rdn := strings.TrimSuffix(normalized, suffix)
	parts := strings.SplitN(rdn, "=", 2)
	if len(parts) != 2 || parts[0] != "uid" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func normalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return strings.Join(parts, ",")
}

func bytesJoin(items [][]byte) []byte {
	return slices.Concat(items...)
}

func remoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (r *rateCounter) Allow(limit int) bool {
	now := time.Now()
	if now.Sub(r.windowStart) >= time.Second {
		r.windowStart = now
		r.count = 0
	}
	if r.count >= limit {
		return false
	}
	r.count++
	return true
}

func (w *windowLimiter) Allow(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	entries := w.entries[key][:0]
	for _, ts := range w.entries[key] {
		if now.Sub(ts) < w.window {
			entries = append(entries, ts)
		}
	}
	if len(entries) >= w.limit {
		w.entries[key] = entries
		return false
	}
	w.entries[key] = append(entries, now)
	return true
}
