package ldapserver

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoldap/internal/audit"
	"nanoldap/internal/config"
	"nanoldap/internal/directory"
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
	if !containsAttribute(responses.entries[0], "namingContexts") {
		t.Fatalf("Root DSE response missing canonical namingContexts attribute")
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
	if !containsAttribute(allResponses.entries[0], "namingContexts") {
		t.Fatalf("Root DSE ALL response missing namingContexts attribute")
	}
	if !containsAttribute(allResponses.entries[0], "objectClass") {
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
	if !containsAttribute(starPlusResponses.entries[0], "namingContexts") {
		t.Fatalf("Root DSE * + response missing namingContexts attribute")
	}
	if !containsAttribute(starPlusResponses.entries[0], "objectClass") {
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
	if !containsAttribute(subtreeResponses.entries[0], "namingContexts") {
		t.Fatalf("Root DSE subtree response missing namingContexts attribute")
	}

	conn2 := dialLDAP(t, addr)
	defer conn2.Close()
	reader2 := bufio.NewReader(conn2)
	writeLDAP(t, conn2, bindRequest(3, "", ""))
	_ = readLDAPPacket(t, reader2)
	writeLDAP(t, conn2, searchRequestPacket(4, peopleBaseDN("dc=example,dc=com"), scopeSubtree, presentFilterPacket("objectClass")))
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
		equalityFilterPacket("member", legacyUserDN("dc=example,dc=com", "user")),
		equalityFilterPacket("uniqueMember", legacyUserDN("dc=example,dc=com", "user")),
		equalityFilterPacket("memberUid", "user"),
	)
	writeLDAP(t, userConn, searchRequestPacket(2, "dc=example,dc=com", scopeSubtree, filter))
	groupSearch := readLDAPSearchResponses(t, userReader)
	if len(groupSearch.entries) != 1 || !entryHasDN(groupSearch.entries[0], groupDN("dc=example,dc=com", "users")) {
		t.Fatalf("user group search returned %d entries; want only users", len(groupSearch.entries))
	}

	adminConn := dialLDAP(t, addr)
	defer adminConn.Close()
	adminReader := bufio.NewReader(adminConn)
	writeLDAP(t, adminConn, bindRequest(3, legacyUserDN("dc=example,dc=com", "admin"), "admin"))
	if code := ldapResultCode(t, readLDAPPacket(t, adminReader)); code != resultSuccess {
		t.Fatalf("admin bind result = %d; want success", code)
	}
	writeLDAP(t, adminConn, searchRequestPacket(4, peopleBaseDN("dc=example,dc=com"), scopeSubtree, equalityFilterPacket("uid", "guest")))
	adminSearch := readLDAPSearchResponses(t, adminReader)
	if len(adminSearch.entries) != 1 || !entryHasDN(adminSearch.entries[0], userDN("dc=example,dc=com", "guest")) {
		t.Fatalf("admin search returned %d entries; want guest", len(adminSearch.entries))
	}

	guestConn := dialLDAP(t, addr)
	defer guestConn.Close()
	guestReader := bufio.NewReader(guestConn)
	writeLDAP(t, guestConn, bindRequest(5, userDN("dc=example,dc=com", "guest"), "guest"))
	_ = readLDAPPacket(t, guestReader)
	writeLDAP(t, guestConn, searchRequestPacket(6, "dc=example,dc=com", scopeSubtree, equalityFilterPacket("uid", "admin")))
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
	// The server must have closed our connection by now. The Write may still
	// succeed because the kernel TCP buffer accepts the bytes locally, so the
	// authoritative check is the read: it must fail (EOF or io.ErrClosedPipe)
	// rather than ever returning a packet.
	_, _ = conn.Write(bindRequest(1, "", ""))
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := readPacket(bufio.NewReader(conn)); err == nil {
		t.Fatalf("connection remained open after idle timeout: read returned a packet")
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

func TestUpdatedBaseDNIsUsedAtRuntime(t *testing.T) {
	addr, cleanup := startLDAPServer(t, config.Config{
		BaseDN:             "dc=example,dc=com",
		DBPath:             filepath.Join(t.TempDir(), "test.db"),
		AuditLog:           filepath.Join(t.TempDir(), "audit.log"),
		LDAPIdleTimeout:    time.Second,
		LDAPBindWindow:     10 * time.Second,
		LDAPBindLimit:      10,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	}, func(settings *directory.Settings, dataStore *store.Store) {
		t.Helper()
		if err := dataStore.SetBaseDN(context.Background(), "dc=corp,dc=local"); err != nil {
			t.Fatalf("SetBaseDN() error = %v", err)
		}
		if err := settings.SetBaseDN("dc=corp,dc=local"); err != nil {
			t.Fatalf("settings.SetBaseDN() error = %v", err)
		}
	})
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writeLDAP(t, conn, bindRequest(1, userDN("dc=corp,dc=local", "admin"), "admin"))
	if code := ldapResultCode(t, readLDAPPacket(t, reader)); code != resultSuccess {
		t.Fatalf("bind with updated base DN result = %d; want success", code)
	}

	writeLDAP(t, conn, searchRequestPacket(2, "dc=corp,dc=local", scopeSubtree, equalityFilterPacket("uid", "guest")))
	responses := readLDAPSearchResponses(t, reader)
	if len(responses.entries) != 1 || !entryHasDN(responses.entries[0], userDN("dc=corp,dc=local", "guest")) {
		t.Fatalf("updated base DN search returned %d entries; want guest under dc=corp,dc=local", len(responses.entries))
	}
}

func TestLegacyPeopleAndGroupsAliasesRemainQueryable(t *testing.T) {
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

	writeLDAP(t, conn, bindRequest(1, legacyUserDN("dc=example,dc=com", "user"), "user"))
	if code := ldapResultCode(t, readLDAPPacket(t, reader)); code != resultSuccess {
		t.Fatalf("legacy bind DN result = %d; want success", code)
	}

	legacyGroupFilter := orFilterPacket(
		equalityFilterPacket("member", legacyUserDN("dc=example,dc=com", "user")),
		equalityFilterPacket("uniqueMember", legacyUserDN("dc=example,dc=com", "user")),
		equalityFilterPacket("memberUid", "user"),
	)
	writeLDAP(t, conn, searchRequestPacket(2, groupsBaseDN("dc=example,dc=com"), scopeSubtree, legacyGroupFilter))
	groupResponses := readLDAPSearchResponses(t, reader)
	if len(groupResponses.entries) != 1 || !entryHasDN(groupResponses.entries[0], groupDN("dc=example,dc=com", "users")) {
		t.Fatalf("legacy group alias search returned %d entries; want users group", len(groupResponses.entries))
	}

	writeLDAP(t, conn, searchRequestPacket(3, peopleBaseDN("dc=example,dc=com"), scopeSubtree, equalityFilterPacket("uid", "user")))
	userResponses := readLDAPSearchResponses(t, reader)
	if len(userResponses.entries) != 1 || !entryHasDN(userResponses.entries[0], userDN("dc=example,dc=com", "user")) {
		t.Fatalf("legacy people alias search returned %d entries; want user", len(userResponses.entries))
	}
}

func TestLDAPDebugLogsRequestsAndResponses(t *testing.T) {
	logSink := &lockedBuffer{}
	addr, cleanup := startLDAPServerWithDebug(t, config.Config{
		BaseDN:             "dc=example,dc=com",
		DBPath:             filepath.Join(t.TempDir(), "test.db"),
		AuditLog:           filepath.Join(t.TempDir(), "audit.log"),
		LDAPDebug:          true,
		LDAPIdleTimeout:    time.Second,
		LDAPBindWindow:     10 * time.Second,
		LDAPBindLimit:      10,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	}, logSink)
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)

	writeLDAP(t, conn, bindRequest(1, userDN("dc=example,dc=com", "user"), "user"))
	if code := ldapResultCode(t, readLDAPPacket(t, reader)); code != resultSuccess {
		t.Fatalf("bind result = %d; want success", code)
	}

	writeLDAP(t, conn, searchRequestPacket(2, "", scopeBaseObject, presentFilterPacket("objectClass")))
	_ = readLDAPSearchResponses(t, reader)

	logs := logSink.String()
	for _, fragment := range []string{
		"request remote=",
		"response remote=",
		"BindRequest{version=3",
		`authentication=simple("<redacted>")`,
		"BindResponse{result=success",
		"SearchRequest{baseDN=\"\"",
		"SearchResultDone{result=success",
	} {
		if !strings.Contains(logs, fragment) {
			t.Fatalf("debug logs missing %q\nlogs:\n%s", fragment, logs)
		}
	}
	if strings.Contains(logs, `authentication=simple("user")`) {
		t.Fatalf("debug logs leaked bind password:\n%s", logs)
	}
}

func TestUnsupportedFiltersReturnProtocolError(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	cases := map[string][]byte{
		"substring":    substringFilterPacket("uid", "ad"),
		"greaterEqual": greaterOrEqualFilterPacket("uid", "a"),
		"lessEqual":    lessOrEqualFilterPacket("uid", "z"),
		"approxMatch":  approxMatchFilterPacket("uid", "admn"),
		"not":          notFilterPacket(equalityFilterPacket("uid", "admin")),
	}
	messageID := 2
	for name, filter := range cases {
		t.Run(name, func(t *testing.T) {
			writeLDAP(t, conn, searchRequestPacket(messageID, "dc=example,dc=com", scopeSubtree, filter))
			pkt := readLDAPPacket(t, reader)
			if code := ldapResultCode(t, pkt); code != resultProtocolError {
				t.Fatalf("%s filter result = %d; want %d", name, code, resultProtocolError)
			}
		})
		messageID++
	}
}

func TestInvalidScopeReturnsProtocolError(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	writeLDAP(t, conn, searchRequestPacket(2, "dc=example,dc=com", 99, presentFilterPacket("objectClass")))
	pkt := readLDAPPacket(t, reader)
	if code := ldapResultCode(t, pkt); code != resultProtocolError {
		t.Fatalf("invalid scope result = %d; want %d", code, resultProtocolError)
	}
}

func TestSingleLevelScopeReturnsImmediateChildren(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	writeLDAP(t, conn, searchRequestPacket(2, "dc=example,dc=com", scopeSingle, presentFilterPacket("objectClass")))
	responses := readLDAPSearchResponses(t, reader)
	if len(responses.entries) == 0 {
		t.Fatalf("singleLevel search returned 0 entries; expected at least the people/groups OUs and seed users")
	}
	for _, entry := range responses.entries {
		dn := entry.children[0].str()
		if !(dn == "ou=people,dc=example,dc=com" ||
			dn == "ou=groups,dc=example,dc=com" ||
			strings.HasPrefix(dn, "uid=") ||
			strings.HasPrefix(dn, "cn=")) {
			t.Fatalf("singleLevel returned unexpected child DN %q", dn)
		}
		if strings.Count(dn, ",") != 1 && strings.Count(dn, ",") != 2 {
			// Each child must be one component below the base.
			t.Fatalf("singleLevel returned non-immediate child DN %q", dn)
		}
	}
}

func TestNoAttributesMarker(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	writeLDAP(t, conn, searchRequestPacketWithAttributes(2, peopleBaseDN("dc=example,dc=com"), scopeSubtree, equalityFilterPacket("uid", "admin"), "1.1"))
	responses := readLDAPSearchResponses(t, reader)
	if len(responses.entries) != 1 {
		t.Fatalf("1.1 marker returned %d entries; want 1", len(responses.entries))
	}
	if count := entryAttributeCount(responses.entries[0]); count != 0 {
		t.Fatalf("1.1 marker entry returned %d attributes; want 0", count)
	}
}

func TestRootDSEPlusReturnsOperationalAttributesOnly(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writeLDAP(t, conn, bindRequest(1, "", ""))
	_ = readLDAPPacket(t, reader)

	writeLDAP(t, conn, searchRequestPacketWithAttributes(2, "", scopeBaseObject, presentFilterPacket("objectClass"), "+"))
	responses := readLDAPSearchResponses(t, reader)
	if len(responses.entries) != 1 {
		t.Fatalf("Root DSE + entries = %d; want 1", len(responses.entries))
	}
	if !containsAttribute(responses.entries[0], "namingContexts") {
		t.Fatalf("Root DSE + missing namingContexts attribute")
	}
	if containsAttribute(responses.entries[0], "objectClass") {
		t.Fatalf("Root DSE + should not include objectClass when only operational attributes are requested")
	}
}

func TestBaseEntryDcIsMultiValued(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	writeLDAP(t, conn, searchRequestPacketWithAttributes(2, "dc=example,dc=com", scopeBaseObject, presentFilterPacket("objectClass"), "dc"))
	responses := readLDAPSearchResponses(t, reader)
	if len(responses.entries) != 1 {
		t.Fatalf("base search entries = %d; want 1", len(responses.entries))
	}
	values := attributeValues(responses.entries[0], "dc")
	if len(values) != 2 || values[0] != "example" || values[1] != "com" {
		t.Fatalf("base entry dc = %v; want [example com]", values)
	}
}

func TestSecondBindOnSameConnectionRejected(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	writeLDAP(t, conn, bindRequest(2, userDN("dc=example,dc=com", "user"), "user"))
	pkt := readLDAPPacket(t, reader)
	if code := ldapResultCode(t, pkt); code != resultUnwillingToPerform {
		t.Fatalf("second bind result = %d; want %d", code, resultUnwillingToPerform)
	}
}

func TestMutationOperationsRejected(t *testing.T) {
	addr, cleanup := startLDAPServer(t, defaultLDAPTestConfig(t))
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	cases := map[string]struct {
		requestTag  int
		responseTag int
	}{
		"modify":   {6, 7},
		"add":      {8, 9},
		"delete":   {10, 11},
		"modifyDN": {12, 13},
	}
	messageID := 2
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			writeLDAP(t, conn, mutationOperationPacket(messageID, tc.requestTag))
			pkt := readLDAPPacket(t, reader)
			op := pkt.children[1]
			if op.class != classApplication || op.tag != tc.responseTag {
				t.Fatalf("%s response op tag = %d; want %d", name, op.tag, tc.responseTag)
			}
			if code := ldapResultCode(t, pkt); code != resultUnwillingToPerform {
				t.Fatalf("%s response code = %d; want %d", name, code, resultUnwillingToPerform)
			}
		})
		messageID++
	}
}

func TestSearchRateLimitTriggersAdminLimitExceeded(t *testing.T) {
	cfg := defaultLDAPTestConfig(t)
	cfg.LDAPSearchRate = 5
	addr, cleanup := startLDAPServer(t, cfg)
	defer cleanup()

	conn := dialLDAP(t, addr)
	defer conn.Close()
	reader := bufio.NewReader(conn)
	bindAs(t, conn, reader, 1, userDN("dc=example,dc=com", "admin"), "admin")

	for messageID := 2; messageID <= 6; messageID++ {
		writeLDAP(t, conn, searchRequestPacket(messageID, "dc=example,dc=com", scopeBaseObject, presentFilterPacket("objectClass")))
		_ = readLDAPSearchResponses(t, reader)
	}

	writeLDAP(t, conn, searchRequestPacket(7, "dc=example,dc=com", scopeBaseObject, presentFilterPacket("objectClass")))
	pkt := readLDAPPacket(t, reader)
	if code := ldapResultCode(t, pkt); code != resultAdminLimitExceeded {
		t.Fatalf("over-limit search result = %d; want %d", code, resultAdminLimitExceeded)
	}
}

func TestConnectionLimitDropsExcessConnections(t *testing.T) {
	cfg := defaultLDAPTestConfig(t)
	cfg.LDAPMaxConnections = 2
	addr, cleanup := startLDAPServer(t, cfg)
	defer cleanup()

	// Hold the two allowed slots with anonymous binds.
	held := make([]net.Conn, 0, 2)
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 1; i <= 2; i++ {
		conn := dialLDAP(t, addr)
		reader := bufio.NewReader(conn)
		writeLDAP(t, conn, bindRequest(i, "", ""))
		if code := ldapResultCode(t, readLDAPPacket(t, reader)); code != resultSuccess {
			t.Fatalf("anonymous bind %d result = %d; want success", i, code)
		}
		held = append(held, conn)
	}

	// The third connection must be dropped immediately by the server.
	overflow := dialLDAP(t, addr)
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 16)
	n, err := overflow.Read(buf)
	if err == nil {
		t.Fatalf("overflow connection read returned %d bytes; want EOF", n)
	}
}

func defaultLDAPTestConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		BaseDN:             "dc=example,dc=com",
		DBPath:             filepath.Join(t.TempDir(), "test.db"),
		AuditLog:           filepath.Join(t.TempDir(), "audit.log"),
		LDAPIdleTimeout:    2 * time.Second,
		LDAPBindWindow:     10 * time.Second,
		LDAPBindLimit:      10,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	}
}

func startLDAPServer(t *testing.T, cfg config.Config, hooks ...func(*directory.Settings, *store.Store)) (string, func()) {
	return startLDAPServerWithDebug(t, cfg, io.Discard, hooks...)
}

func startLDAPServerWithDebug(t *testing.T, cfg config.Config, debugSink io.Writer, hooks ...func(*directory.Settings, *store.Store)) (string, func()) {
	t.Helper()
	ctx := context.Background()
	dataStore, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	if err := dataStore.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults() error = %v", err)
	}
	baseDN, err := dataStore.EnsureBaseDN(ctx, cfg.BaseDN)
	if err != nil {
		t.Fatalf("EnsureBaseDN() error = %v", err)
	}
	settings, err := directory.NewSettings(baseDN)
	if err != nil {
		t.Fatalf("directory.NewSettings() error = %v", err)
	}
	for _, hook := range hooks {
		hook(settings, dataStore)
	}
	auditLog, err := audit.New(cfg.AuditLog)
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}
	server := New(cfg, settings, dataStore, auditLog, debugSink)
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

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
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

func notFilterPacket(child []byte) []byte {
	return append([]byte{0xa2}, appendLength(child)...)
}

func substringFilterPacket(attr, initial string) []byte {
	return append([]byte{0xa4}, appendLength(bytesJoin([][]byte{
		berOctetString(attr),
		berSequence(append([]byte{0x80}, appendLength([]byte(initial))...)),
	}))...)
}

func greaterOrEqualFilterPacket(attr, value string) []byte {
	return append([]byte{0xa5}, appendLength(bytesJoin([][]byte{
		berOctetString(attr),
		berOctetString(value),
	}))...)
}

func lessOrEqualFilterPacket(attr, value string) []byte {
	return append([]byte{0xa6}, appendLength(bytesJoin([][]byte{
		berOctetString(attr),
		berOctetString(value),
	}))...)
}

func approxMatchFilterPacket(attr, value string) []byte {
	return append([]byte{0xa8}, appendLength(bytesJoin([][]byte{
		berOctetString(attr),
		berOctetString(value),
	}))...)
}

func mutationOperationPacket(messageID, appTag int) []byte {
	return berMessage(messageID, berApplication(appTag, nil))
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

func attributeValues(entry packet, wanted string) []string {
	for _, attribute := range entry.children[1].children {
		if len(attribute.children) < 2 || attribute.children[0].str() != wanted {
			continue
		}
		var values []string
		for _, value := range attribute.children[1].children {
			values = append(values, value.str())
		}
		return values
	}
	return nil
}

func entryAttributeCount(entry packet) int {
	return len(entry.children[1].children)
}

func bindAs(t *testing.T, conn net.Conn, reader *bufio.Reader, messageID int, dn, password string) {
	t.Helper()
	writeLDAP(t, conn, bindRequest(messageID, dn, password))
	if code := ldapResultCode(t, readLDAPPacket(t, reader)); code != resultSuccess {
		t.Fatalf("bind result = %d; want success", code)
	}
}
