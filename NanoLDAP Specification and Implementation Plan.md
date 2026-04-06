# **NanoLDAP: Specification and Implementation Plan**

## **1\. Project Overview**

NanoLDAP is a minimalistic, secure, and self-contained LDAP server designed for simple infrastructure deployments. It provides a read-only LDAP/LDAPS interface for service integrations (e.g., VPNs, Nextcloud) and a secure, embedded HTTP/HTTPS web interface for user and group administration.

The primary design philosophy is **zero-dependency deployment**: a single statically linked binary containing all HTML, CSS, JavaScript, and database engines, requiring no external services or configuration files to run.

## **2\. Technology Stack**

* **Language:** Go 1.26  
* **Database Engine:** modernc.org/sqlite (CGO-free SQLite implementation)  
* **LDAP Engine:** Custom read-only handler based on a stripped-down [https://github.com/vjeantet/ldapserver](https://github.com/vjeantet/ldapserver) (supporting only Simple Bind and Search operations).  
* **Web Framework:** Go standard library net/http (leveraging Go 1.22+ wildcard/method routing) and html/template.  
* **Frontend:** Locally served htmx.min.js and Tailwind CSS, bundled via //go:embed.  
* **Cryptography & Auth:** golang.org/x/crypto/argon2 for password hashing, crypto/x509, crypto/ed25519, & crypto/ecdsa for automatic TLS certificate generation.

## **3\. Security Model**

### **3.1. Transport Layer Security (TLS) & Certificate Distribution**

* The system enforces encrypted communication. On startup, the binary checks for cert.pem and key.pem in the working directory.  
* If absent, a routine automatically generates a modern **Ed25519** (or ECDSA P-256) self-signed x509 certificate valid for 10 years.  
* This certificate is shared by both the LDAPS listener and the HTTPS Web UI listener (if those services are activated).  
* **CA Distribution:** The web server exposes a public endpoint (GET /ca.crt) allowing clients to easily download the server's public certificate (e.g., via wget \--no-check-certificate https://\<server\>/ca.crt) to add to their local trust stores.  
* The Web UI enforces HTTP Strict Transport Security (HSTS) headers.

### **3.2. Authentication & Session Management**

* **Passwords:** All passwords (users and the initial admin) are hashed using **Argon2id** and stored in the PHC string format (e.g., $argon2id$v=19...).  
* **Web UI (Admin):** Uses secure, stateful in-memory sessions instead of JWTs. Upon login, a 32-byte cryptographically secure random session ID (using crypto/rand) is generated. It is provided to the client as an HttpOnly, Secure, SameSite=Strict cookie.  
  * **Global Limit:** The system enforces a strict maximum of **3 active sessions globally**. Any login attempt exceeding this limit is explicitly rejected to prevent resource exhaustion and concurrent administrative meddling.  
  * **Timeouts & Cleanup:** Sessions have a 15-minute idle timeout. Activity refreshes the cookie-backed session. The system performs opportunistic expiry cleanup to remove stale sessions. Note: In-memory sessions do not survive a server restart, forcing a secure re-authentication.  
  * **Revocation:** Explicit logouts immediately clear the session from memory. Per-user revocation is supported.  
  * **Access Control:** Access to the Web UI is strictly restricted to members of the admins group. Any other authenticated user attempting to log in will be explicitly rejected.  
* **LDAP Auth & Rate Limiting:** LDAP Simple Bind requests verify the provided cleartext password against the Argon2id hash in the SQLite database. To prevent password brute-forcing, binds are rate-limited per source IP (e.g., maximum 3 bind attempts per 10 seconds per IP).

### **3.3. Audit Trail Logging**

The system maintains a dedicated audit log capturing critical security and access events. The destination is configurable via CLI (e.g., audit.log file, or stdout for containerized environments).

* **Web UI Logins:** Records timestamp, source IP, and username for every login attempt (both successes and rejections, including rejections due to the global session limit).  
* **LDAP Bind Requests:** Records timestamp, source IP, username, and bind result (e.g., Success, Invalid Credentials, User Disabled, Rate Limited) for every bind attempt.

## **4\. Data Model & Directory Mapping**

The system uses a flat relational SQLite database as the single source of truth, which is dynamically mapped into a standard LDAP Directory Information Tree (DIT) on the fly.

### **4.1. SQLite Schema**

| Table | Columns | Description |
| :---- | :---- | :---- |
| users | id (PK), username (Unique), password\_hash, display\_name, disabled (Bool), created\_at, updated\_at | Core user accounts. |
| groups | id (PK), name (Unique), description | Roles or access groups. |
| user\_groups | user\_id (FK), group\_id (FK) | Composite primary key mapping users to groups. |

### **4.2. LDAP DIT Mapping (Virtual Directory)**

* **Base DN:** dc=example,dc=com (Configurable via CLI/Env)  
* **Users:** Exposed directly under the base DN as uid={username},dc=example,dc=com  
  * **Attributes:** objectClass=inetOrgPerson, uid={username}, cn={username}, displayName={display\_name}  
  * **Derived Attribute:** memberOf (Calculated dynamically from user\_groups joins).  
* **Groups:** Exposed directly under the base DN as cn={name},dc=example,dc=com  
  * **Attributes:** objectClass=groupOfNames, cn={name}  
  * **Derived Attributes:** member (Calculated dynamically, listing full canonical DNs of users in the group) AND memberUid (listing only the usernames, for legacy client compatibility).  
* **Compatibility Aliases:** Legacy user and group DNs under ou=people,dc=example,dc=com and ou=groups,dc=example,dc=com remain accepted for bind parsing and subtree search matching so older clients and scripts can keep working during migration.

## **5\. Component Specifications**

### **5.1. The LDAP Engine (Read-Only & Scoped)**

To drastically reduce complexity and increase security, the LDAP protocol is strictly read-only and heavily scoped based on the bind state. Furthermore, strict connection lifecycle constraints are applied to prevent resource exhaustion and abuse.

* **Connection Lifecycle & Limits:**  
  * **Global Concurrency:** A strict maximum of **16 concurrent active connections** across all LDAP/LDAPS listeners.  
  * **Idle Timeout:** Connections have a rigid **5-second inactivity timeout**. Idle connections are aggressively dropped.  
  * **Usage Constraints:** A single connection is permitted a maximum of **1 successful bind**. To support clients utilizing connection pooling, searches are not hard-capped per connection, but are **rate-limited** (e.g., max 50 searches per second per connection) to prevent CPU starvation.  
  * **Anti-Brute Force:** Bind attempts are tracked in-memory by source IP. Exceeding **3 bind attempts per 10 seconds** results in immediate connection closure and an audit log entry.  
* **BindRequest Handler:** \* **Anonymous Bind:** Supported. If no DN/password is provided, the bind succeeds anonymously.  
  * **Authenticated Bind:** Extracts the requested DN, parses the uid, looks up the user in SQLite, and compares the password using Argon2id. Checks if disabled \== false.  
  * Logs the result to the audit trail.  
* **SearchRequest Handler:** Parses standard LDAP search filters (e.g., (&(objectClass=inetOrgPerson)(uid=alice))).  
  * **Anonymous Search Restrictions:** Anonymous users are strictly limited to querying the Root DSE (Base Object search, empty base DN). Any attempt to search the main DIT (e.g., dc=example,dc=com or compatibility aliases like ou=people,dc=example,dc=com) returns an LDAPResultInsufficientAccessRights error. The Root DSE query returns server info like namingContexts, supportedLDAPVersion, etc.  
  * **Authenticated Search Restrictions (Role-Based Scoping):** \* **Service Accounts / Admins:** If the bound user is a member of the admins or mvradmins groups, they are permitted to query the entire DIT. This accommodates standard third-party integrations (like Nextcloud or VPNs) that bind as a service account to look up other users.  
    * **Standard Users:** Standard users (users, guests) are restricted to searching **only** for their own identity and their group memberships. Searches for other users' data return an empty result or insufficient rights.  
* **Mutation Rejection:** Any AddRequest, ModifyRequest, DeleteRequest, or ModifyDNRequest will immediately return an LDAPResultUnwillingToPerform error code.

### **5.2. The Web UI Engine**

* **Routing & Framework:** Explicitly uses the Go standard library net/http multiplexer. Third-party frameworks (like Gin Gonic) are strictly excluded to minimize dependencies.  
* **Session Management:** \* Authenticates requests against a secure in-memory session store (no JWTs).  
  * Enforces a strict maximum of **3 active sessions globally**; further login attempts are rejected with an error.  
  * Sessions use 32-byte random tokens generated via crypto/rand.  
  * Enforces a 15-minute idle timeout. Sessions are refreshed on activity and explicitly cleared upon logout.  
  * Implement opportunistic expiry cleanup to automatically prune expired sessions from memory.  
  * Allows per-user session revocation (e.g., forcing a user logout from all devices if their password or role is changed).  
* **Asset Bundling:** //go:embed is used to pack styles.css (Tailwind output), htmx.min.js, and all html/template files into the compiled binary.  
* **Endpoints:**  
  * GET /ca.crt (Public endpoint to distribute the server's public certificate)  
  * GET /login, POST /login, POST /logout (Auth flow)  
  * GET /users, POST /users, PUT /users/{id}, DELETE /users/{id} (User management via HTMX)  
  * GET /groups, POST /groups, PUT /groups/{id}, DELETE /groups/{id} (Group management)  
* **Interactivity:** Actions like disabling a user or removing them from a group trigger HTMX hx-post or hx-delete requests, updating specific DOM targets (like a table row) without a full page refresh.

## **6\. Implementation Roadmap**

### **Phase 1: Core Cryptography & Database Setup**

1. Initialize Go module and install modernc.org/sqlite and golang.org/x/crypto/argon2.  
2. Implement the Argon2id hashing and verification utility functions.  
3. Implement the startup TLS routine: check for PEM files, generate Ed25519/x509 certs if missing, and save them.  
4. Create the SQLite schema, initialization function, and basic CRUD data access layers (DAL) for users and groups.

### **Phase 2: Web Server & Administration UI**

1. Set up standard net/http server with TLS utilizing the generated certificates.  
2. Implement the GET /ca.crt handler.  
3. Implement HSTS middleware, the custom in-memory Secure Cookie session manager (3 max sessions, 15m timeout), and the audit.log writer (supporting stdout).  
4. Build the embedded asset filesystem (embed.FS) and HTML templates.  
5. Wire up HTMX endpoints. Enforce Web UI access checks (ensure user memberOf includes admins).

### **Phase 3: The Minimal LDAP Engine**

1. Integrate the trimmed-down BER parsing logic.  
2. Implement the connection lifecycle monitors (max 16 connections, 5s timeout, search rate limiting, IP bind rate limiting).  
3. Implement the Bind handler: Handle Anonymous binds and Authenticated binds. Write outcomes to the audit log.  
4. Implement the Search handler:  
   * Build the Root DSE response mechanism for anonymous users.  
   * Build the SQL translation logic for authenticated users, enforcing the "role-based" search constraints (Admins see all, Users see self).  
5. Start the LDAP/LDAPS listeners.

### **Phase 4: Integration & Polish**

1. Bind configuration options to CLI flags. **All 4 network ports (--http-port, \--https-port, \--ldap-port, \--ldaps-port) must be explicitly specified to be activated.**   
2. 2\. Bind \--audit-log configuration to allow output routing (e.g., audit.log or stdout).  
3. Add the automated "first run" routine to provision:  
   * **Groups:** admins, mvradmins, users, guests  
   * **Users:** admin/admin, mvradmin/mvradmin, user/user, guest/guest.

### **Phase 5: Comprehensive Testing Plan**

A rigorous testing strategy must be applied to ensure the integrity of the server. This includes automated unit tests, fuzz testing, and a dedicated end-to-end (E2E) integration script.

#### **5.1 Internal Go Testing**

1. **Database & Core Logic (Unit Testing):** Standard Go testing package for SQLite CRUD operations. Verify Argon2id hashing consistency and timing.  
2. **Fuzz Testing (Security):** Utilize go test \-fuzz targeting the ASN.1/BER decoding functions within the modified LDAP engine to ensure malformed LDAP packets cannot cause a panic or buffer overflow. Fuzz the HTTP endpoints with malformed session cookies and HTMX payloads.

#### **5.2 Cross-Platform Integration Test Suite (PowerShell 7.5)**

An automated E2E test script (ldap\_test.ps1) must be maintained. It requires PowerShell Core 7.5+ to ensure cross-platform compatibility (Windows and Linux). It utilizes standard Invoke-WebRequest for HTTP(S) requests and the built-in .NET System.DirectoryServices.Protocols assembly to avoid external dependencies for LDAP(S) interactions.

**HTTP/HTTPS Test Requirements:**

* **CA Certificate Retrieval:** Fetch http(s)://\<server\>/ca.crt and validate the response contains a valid \-----BEGIN CERTIFICATE----- PEM block.  
* **RBAC Enforcement:** Attempt to access Web UI endpoints using credentials from the guests or users groups and assert an HTTP 403 Forbidden or redirect. Assert success for admins.  
* **Session Limits:** Attempt to establish 4 concurrent admin sessions, asserting that the 4th attempt is successfully rejected.

**LDAP / LDAPS Test Requirements:**

* **Protocol Coverage:** Execute all LDAP tests against both the cleartext LDAP port (e.g., 389\) and the LDAPS port (e.g., 636), ensuring the self-signed TLS certificate is properly trusted and verified when testing secure connections.  
* **Lifecycle Limits:** Test connection drop after 5 seconds of inactivity. Test IP rate limit triggers after 4 bind attempts within 10 seconds.  
* **Anonymous Bind & RootDSE:** Perform an anonymous bind and execute a Base-scoped search (objectClass=\*) against an empty base DN. Assert the retrieval of server info, particularly namingContexts.  
* **Anonymous Search Restrictions:** Attempt a Subtree search (e.g., (objectClass=inetOrgPerson)) against dc=example,dc=com and against the compatibility alias ou=people,dc=example,dc=com as an anonymous user. Assert the server explicitly returns an LDAPResultInsufficientAccessRights exception.  
* **Authenticated Bind:** Perform a Simple Bind using the default seeded users (e.g., uid=user,dc=example,dc=com with password user). Assert successful authentication. Add a compatibility case verifying uid=user,ou=people,dc=example,dc=com still binds successfully.  
* **Scoped Search & Group Resolution:** Using the authenticated connection, query the flat directory base (dc=example,dc=com) with a complex filter designed to test standard directory compatibility: (|(member=uid=...)(uniqueMember=uid=...)(memberUid=...)). Assert that the server parses the filter correctly and returns **only** the groups to which the authenticated user is assigned (e.g., validating the users group is returned for the default user account). Add a compatibility case querying ou=groups,... with legacy member DNs.
* **Service Account Search:** Bind as the admin account and perform a search for a different user (e.g., uid=guest). Assert that the query succeeds because admin bypasses the self-only restriction. Bind as guest and search for admin, asserting an empty result or insufficient rights.
