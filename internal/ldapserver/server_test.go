package ldapserver

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"nanoldap/internal/audit"
	"nanoldap/internal/config"
	"nanoldap/internal/store"
)

func TestAnonymousRootDSEAndRestrictions(t *testing.T) {
	addr, cleanup := startLDAPServer(t, config.Config{
		BaseDN:             "dc=example,dc=com",
		DBPath:             filepath.Join(t.TempDir(), "test.db"),
		AuditLog:           filepath.Join(t.TempDir(), "audit.log"),
		LDAPIdleTimeout:    time.Second,
		LDAPBindWindow:     10 * time.Second,
		LDAPBindLimit:      10,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	})
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)

	writeLDAP(t, conn, bindRequest(1, "", ""))
	bindResponse := readLDAPPacket(t, reader)
	if code := ldapResultCode(t, bindResponse); code != resultSuccess {
		t.Fatalf("anonymous bind result = %d; want %d", code, resultSuccess)
	}

	writeLDAP(t, conn, searchRequestPacket(2, "", scopeBaseObject, presentFilterPacket("objectClass")))
	responses := readLDAPSearchResponses(t, reader)
	if len(responses.entries) != 1 {
		t.Fatalf("anonymous Root DSE entries = %d; want 1", len(responses.entries))
	}
	if !bytes.Contains(responses.entries[0].children[1].content, []byte("namingContexts")) && !containsAttribute(responses.entries[0], "namingcontexts") {
		t.Fatalf("Root DSE response missing namingContexts attribute")
	}

	connAll := dialLDAP(t, addr)
	defer connAll.Close()
	readerAll := bufio.NewReader(connAll)
	writeLDAP(t, connAll, bindRequest(30, "", ""))
	_ = readLDAPPacket(t, readerAll)
	writeLDAP(t, connAll, searchRequestPacketWithAttributes(31, "", scopeBaseObject, presentFilterPacket("objectClass"), "ALL"))
	allResponses := readLDAPSearchResponses(t, readerAll)
	if len(allResponses.entries) != 1 {
		t.Fatalf("anonymous Root DSE ALL entries = %d; want 1", len(allResponses.entries))
	}
	if !containsAttribute(allResponses.entries[0], "namingcontexts") {
		t.Fatalf("Root DSE ALL response missing namingContexts attribute")
	}
	if !containsAttribute(allResponses.entries[0], "objectclass") {
		t.Fatalf("Root DSE ALL response missing objectClass attribute")
	}

	connStarPlus := dialLDAP(t, addr)
	defer connStarPlus.Close()
	readerStarPlus := bufio.NewReader(connStarPlus)
	writeLDAP(t, connStarPlus, bindRequest(34, "", ""))
	_ = readLDAPPacket(t, readerStarPlus)
	writeLDAP(t, connStarPlus, searchRequestPacketWithAttributes(35, "", scopeBaseObject, presentFilterPacket("objectClass"), "*", "+"))
	starPlusResponses := readLDAPSearchResponses(t, readerStarPlus)
	if len(starPlusResponses.entries) != 1 {
		t.Fatalf("anonymous Root DSE * + entries = %d; want 1", len(starPlusResponses.entries))
	}
	if !containsAttribute(starPlusResponses.entries[0], "namingcontexts") {
		t.Fatalf("Root DSE * + response missing namingContexts attribute")
	}
	if !containsAttribute(starPlusResponses.entries[0], "objectclass") {
		t.Fatalf("Root DSE * + response missing objectClass attribute")
	}

	connSubtree := dialLDAP(t, addr)
	defer connSubtree.Close()
	readerSubtree := bufio.NewReader(connSubtree)
	writeLDAP(t, connSubtree, bindRequest(32, "", ""))
	_ = readLDAPPacket(t, readerSubtree)
	writeLDAP(t, connSubtree, searchRequestPacket(33, "", scopeSubtree, presentFilterPacket("objectClass")))
	subtreeResponses := readLDAPSearchResponses(t, readerSubtree)
	if len(subtreeResponses.entries) != 1 {
		t.Fatalf("anonymous Root DSE subtree entries = %d; want 1", len(subtreeResponses.entries))
	}
	if !containsAttribute(subtreeResponses.entries[0], "namingcontexts") {
		t.Fatalf("Root DSE subtree response missing namingContexts attribute")
	}

	conn2 := dialLDAP(t, addr)
	defer conn2.Close()
	reader2 := bufio.NewReader(conn2)
	writeLDAP(t, conn2, bindRequest(3, "", ""))
	_ = readLDAPPacket(t, reader2)
	writeLDAP(t, conn2, searchRequestPacket(4, "ou=people,dc=example,dc=com", scopeSubtree, presentFilterPacket("objectClass")))
	restricted := readLDAPPacket(t, reader2)
	if code := ldapResultCode(t, restricted); code != resultInsufficientAccessRights {
		t.Fatalf("anonymous subtree result = %d; want %d", code, resultInsufficientAccessRights)
	}
}

func TestScopedAndAdminSearches(t *testing.T) {
	addr, cleanup := startLDAPServer(t, config.Config{
		BaseDN:             "dc=example,dc=com",
		DBPath:             filepath.Join(t.TempDir(), "test.db"),
		AuditLog:           filepath.Join(t.TempDir(), "audit.log"),
		LDAPIdleTimeout:    time.Second,
		LDAPBindWindow:     10 * time.Second,
		LDAPBindLimit:      10,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	})
	defer cleanup()

	userConn := dialLDAP(t, addr)
	defer userConn.Close()
	userReader := bufio.NewReader(userConn)
	writeLDAP(t, userConn, bindRequest(1, userDN("dc=example,dc=com", "user"), "user"))
	if code := ldapResultCode(t, readLDAPPacket(t, userReader)); code != resultSuccess {
		t.Fatalf("user bind result = %d; want success", code)
	}
	filter := orFilterPacket(
		equalityFilterPacket("member", userDN("dc=example,dc=com", "user")),
		equalityFilterPacket("uniqueMember", userDN("dc=example,dc=com", "user")),
		equalityFilterPacket("memberUid", "user"),
	)
	writeLDAP(t, userConn, searchRequestPacket(2, "ou=groups,dc=example,dc=com", scopeSubtree, filter))
	groupSearch := readLDAPSearchResponses(t, userReader)
	if len(groupSearch.entries) != 1 || !entryHasDN(groupSearch.entries[0], groupDN("dc=example,dc=com", "users")) {
		t.Fatalf("user group search returned %d entries; want only users", len(groupSearch.entries))
	}

	adminConn := dialLDAP(t, addr)
	defer adminConn.Close()
	adminReader := bufio.NewReader(adminConn)
	writeLDAP(t, adminConn, bindRequest(3, userDN("dc=example,dc=com", "admin"), "admin"))
	if code := ldapResultCode(t, readLDAPPacket(t, adminReader)); code != resultSuccess {
		t.Fatalf("admin bind result = %d; want success", code)
	}
	writeLDAP(t, adminConn, searchRequestPacket(4, "ou=people,dc=example,dc=com", scopeSubtree, equalityFilterPacket("uid", "guest")))
	adminSearch := readLDAPSearchResponses(t, adminReader)
	if len(adminSearch.entries) != 1 || !entryHasDN(adminSearch.entries[0], userDN("dc=example,dc=com", "guest")) {
		t.Fatalf("admin search returned %d entries; want guest", len(adminSearch.entries))
	}

	guestConn := dialLDAP(t, addr)
	defer guestConn.Close()
	guestReader := bufio.NewReader(guestConn)
	writeLDAP(t, guestConn, bindRequest(5, userDN("dc=example,dc=com", "guest"), "guest"))
	_ = readLDAPPacket(t, guestReader)
	writeLDAP(t, guestConn, searchRequestPacket(6, "ou=people,dc=example,dc=com", scopeSubtree, equalityFilterPacket("uid", "admin")))
	guestSearch := readLDAPSearchResponses(t, guestReader)
	if len(guestSearch.entries) != 0 {
		t.Fatalf("guest search returned %d entries; want 0", len(guestSearch.entries))
	}
}

func TestIdleTimeoutAndBindRateLimit(t *testing.T) {
	addr, cleanup := startLDAPServer(t, config.Config{
		BaseDN:             "dc=example,dc=com",
		DBPath:             filepath.Join(t.TempDir(), "test.db"),
		AuditLog:           filepath.Join(t.TempDir(), "audit.log"),
		LDAPIdleTimeout:    200 * time.Millisecond,
		LDAPBindWindow:     500 * time.Millisecond,
		LDAPBindLimit:      3,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	})
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	time.Sleep(350 * time.Millisecond)
	if _, err := conn.Write(bindRequest(1, "", "")); err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := readPacket(bufio.NewReader(conn)); err == nil {
			t.Fatalf("connection remained open after idle timeout")
		}
	}

	for attempt := 1; attempt <= 4; attempt++ {
		conn := dialLDAP(t, addr)
		reader := bufio.NewReader(conn)
		writeLDAP(t, conn, bindRequest(attempt, userDN("dc=example,dc=com", "user"), "wrong"))
		response := readLDAPPacket(t, reader)
		code := ldapResultCode(t, response)
		conn.Close()
		if attempt < 4 && code != resultInvalidCredentials {
			t.Fatalf("bind attempt %d result = %d; want invalid credentials", attempt, code)
		}
		if attempt == 4 && code != resultBusy {
			t.Fatalf("bind attempt %d result = %d; want busy rate limit", attempt, code)
		}
	}
}

func startLDAPServer(t *testing.T, cfg config.Config) (string, func()) {
	t.Helper()
	ctx := context.Background()
	dataStore, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	if err := dataStore.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults() error = %v", err)
	}
	auditLog, err := audit.New(cfg.AuditLog)
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}
	server := New(cfg, dataStore, auditLog)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	go func() { _ = server.Serve(ln) }()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		_ = auditLog.Close()
		_ = dataStore.Close()
	}
}

func dialLDAP(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	return conn
}

func bindRequest(messageID int, dn, password string) []byte {
	return berMessage(messageID, berApplication(0, bytesJoin([][]byte{
		berInteger(3),
		berOctetString(dn),
		berContextPrimitive(0, []byte(password)),
	})))
}

func searchRequestPacket(messageID int, baseDN string, scope int, filter []byte) []byte {
	return searchRequestPacketWithAttributes(messageID, baseDN, scope, filter)
}

func searchRequestPacketWithAttributes(messageID int, baseDN string, scope int, filter []byte, attributes ...string) []byte {
	var attributePackets [][]byte
	for _, attribute := range attributes {
		attributePackets = append(attributePackets, berOctetString(attribute))
	}
	return berMessage(messageID, berApplication(3, bytesJoin([][]byte{
		berOctetString(baseDN),
		berEnumerated(scope),
		berEnumerated(0),
		berInteger(0),
		berInteger(0),
		berBoolean(false),
		filter,
		berSequence(attributePackets...),
	})))
}

func presentFilterPacket(attr string) []byte {
	return append([]byte{0x87}, appendLength([]byte(attr))...)
}

func equalityFilterPacket(attr, value string) []byte {
	return append([]byte{0xa3}, appendLength(bytesJoin([][]byte{
		berOctetString(attr),
		berOctetString(value),
	}))...)
}

func orFilterPacket(children ...[]byte) []byte {
	return append([]byte{0xa1}, appendLength(bytesJoin(children))...)
}

func writeLDAP(t *testing.T, conn net.Conn, message []byte) {
	t.Helper()
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("conn.Write() error = %v", err)
	}
}

func readLDAPPacket(t *testing.T, reader *bufio.Reader) packet {
	t.Helper()
	pkt, err := readPacket(reader)
	if err != nil {
		t.Fatalf("readPacket() error = %v", err)
	}
	return pkt
}

type searchResponses struct {
	entries []packet
	done    packet
}

func readLDAPSearchResponses(t *testing.T, reader *bufio.Reader) searchResponses {
	t.Helper()
	var responses searchResponses
	for {
		pkt := readLDAPPacket(t, reader)
		op := pkt.children[1]
		if op.class == classApplication && op.tag == 4 {
			responses.entries = append(responses.entries, op)
			continue
		}
		responses.done = op
		return responses
	}
}

func ldapResultCode(t *testing.T, pkt packet) int {
	t.Helper()
	op := pkt.children[1]
	if len(op.children) == 0 {
		t.Fatalf("LDAP response missing result code")
	}
	code, err := op.children[0].int()
	if err != nil {
		t.Fatalf("packet.int() error = %v", err)
	}
	return code
}

func containsAttribute(entry packet, wanted string) bool {
	for _, attribute := range entry.children[1].children {
		if len(attribute.children) > 0 && attribute.children[0].str() == wanted {
			return true
		}
	}
	return false
}

func entryHasDN(entry packet, dn string) bool {
	return len(entry.children) > 0 && entry.children[0].str() == dn
}
