# NanoLDAP

NanoLDAP is a minimal, self-contained LDAP/LDAPS server with an embedded HTTP/HTTPS administration UI. It stores users and groups in SQLite, exposes a read-only virtual LDAP directory, bundles its static web assets into the binary, and generates a self-signed TLS certificate automatically when `cert.pem` and `key.pem` are missing.

## Features

- Read-only LDAP and LDAPS listeners with anonymous Root DSE access, simple bind, scoped search, mutation rejection, per-IP bind throttling, per-connection search throttling, idle connection expiry, and a global concurrent connection cap. Root DSE searches return `namingContexts` for all-attribute requests including `*`, `ALL`, and `*` with `+`, and anonymous empty-base subtree searches are accepted as a compatibility alias for Root DSE lookups.
- Optional `--ldap-debug` protocol tracing logs each parsed LDAP request and the server's encoded LDAP responses to the process log for troubleshooting, while redacting simple-bind passwords.
- HTTPS administration UI built with `net/http`, `html/template`, bundled `htmx.min.js`, and locally served CSS. Users and groups are managed through compact modal dialogs, row-click editing, a single-row header, and an admin-editable Base DN control. The HTTP listener is restricted to the public `GET /ca.crt` certificate distribution endpoint so credentials and session cookies are never sent in clear text.
- Argon2id password hashing in PHC format, secure in-memory sessions with `Secure`, `HttpOnly`, `SameSite=Strict` cookies, a global 3-session limit, 15-minute idle expiry, and per-user session revocation.
- SQLite-backed user/group CRUD with default first-run provisioning for `admins`, `mvradmins`, `users`, and `guests` plus `admin`, `mvradmin`, `user`, and `guest` seed accounts. The effective Base DN is persisted in SQLite so web UI changes survive restarts.
- Audit logging for web login attempts and LDAP bind attempts to either `stdout` or a file, while routine HTTPS client certificate rejection handshake noise is suppressed from the embedded web server log.

## Build

```bash
go build ./cmd/nanoldap
```

## Run

All listeners are opt-in. A port must be explicitly provided to enable that listener.

If `--http-port` is specified, only the public `GET /ca.crt` certificate distribution endpoint is served over HTTP on that port. The administration UI is only served over HTTPS via `--https-port`.

Unix-like shells:

```bash
go run ./cmd/nanoldap --bind-addr 0.0.0.0 --http-port 8080 --https-port 8443 --ldap-port 1389 --ldaps-port 1636
```

PowerShell:

```powershell
go run ./cmd/nanoldap `
  --bind-addr 0.0.0.0 `
  --http-port 8080 `
  --https-port 8443 `
  --ldap-port 1389 `
  --ldaps-port 1636
```

Built binary:

```powershell
go build -o .\nanoldap.exe .\cmd\nanoldap
.\nanoldap.exe --bind-addr 0.0.0.0 --http-port 8080 --https-port 8443 --ldap-port 1389 --ldaps-port 1636
```

Available flags:

- `--bind-addr`: bind address for all listeners. Default: `0.0.0.0`
- `--base-dn`: initial virtual directory base DN. Default: `dc=example,dc=com`
- `--db-path`: SQLite database file. Default: `nanoldap.db`
- `--audit-log`: `stdout` or a file path. Default: `stdout`
- `--cert-file`: TLS certificate path. Default: `cert.pem`
- `--key-file`: TLS private key path. Default: `key.pem`
- `--ldap-debug`: print LDAP request and response debug traces to the process log. Default: `false`
- `--http-port`, `--https-port`, `--ldap-port`, `--ldaps-port`: listener ports. Default: disabled (`0`)

For LAN access from another PC, do not use `127.0.0.1` or `localhost` as `--bind-addr`. Use `0.0.0.0` to listen on all interfaces, or bind to the machine's LAN IP directly.

## Default Accounts

- `admin` / `admin` in `admins`
- `mvradmin` / `mvradmin` in `mvradmins`
- `user` / `user` in `users`
- `guest` / `guest` in `guests`

The web UI only allows members of `admins` to sign in. LDAP full-directory search is available to members of `admins` and `mvradmins`. Standard users can search only their own entry and their group memberships.

## Web UI

- `GET /ca.crt`: download the generated self-signed certificate
- `GET /login`, `POST /login`, `POST /logout`
- `GET /users`, `POST /users`, `PUT /users/{id}`, `DELETE /users/{id}`
- `GET /groups`, `POST /groups`, `PUT /groups/{id}`, `DELETE /groups/{id}`
- `PUT /settings/base-dn`

The `Users` and `Groups` pages use compact modal dialogs for create and edit actions. Clicking a row opens the edit modal for that record, and the `+` button in the page title opens the create modal.

Admins can update the effective Base DN from the web header on either page. NanoLDAP validates this value as a domain-style DN such as `dc=example,dc=com`, persists it in SQLite, and applies it immediately to the web UI and LDAP/LDAPS directory layout. The `--base-dn` flag seeds the initial value for a new database.

## LDAP Layout

- Base DN: configurable, default `dc=example,dc=com`
- Users: `uid=<username>,<baseDN>`
- Groups: `cn=<groupname>,<baseDN>`
- User attributes: `objectClass=inetOrgPerson`, `uid`, `cn`, `displayName`, `memberOf`
- Group attributes: `objectClass=groupOfNames`, `cn`, `member`, `uniqueMember`, `memberUid`

NanoLDAP uses the flat user and group DNs above as the canonical layout. For compatibility, legacy user and group DNs under `ou=people,<baseDN>` and `ou=groups,<baseDN>` are still accepted for bind and subtree search matching.

## Testing

Unit and integration tests:

```bash
go test ./...
```

Cross-platform PowerShell integration test:

```bash
pwsh -NoLogo -NoProfile -File ./scripts/ldap_test.ps1
```

If `ldapsearch` is installed, the PowerShell suite uses it for LDAP and LDAPS protocol queries in addition to the cross-platform checks. The script resolves `ldapsearch` from `PATH`, `$env:LDAPSEARCH`, the `-LdapsearchPath` parameter, and on Windows also checks `C:\OpenLDAP-2.6.9\bin\ldapsearch.exe`. The LDAPS TLS handshake and certificate are validated separately first, because OpenLDAP `ldapsearch` does not consume NanoLDAP's self-signed leaf certificate as a trust anchor directly.

Windows check:

```powershell
& 'C:\OpenLDAP-2.6.9\bin\ldapsearch.exe' -VV
```

To run the PowerShell suite against an already-running instance:

```bash
pwsh -NoLogo -NoProfile -File ./scripts/ldap_test.ps1 \
  -SkipServerStart \
  -HostName 127.0.0.1 \
  -HttpPort 8080 \
  -HttpsPort 8443 \
  -LdapPort 1389 \
  -LdapsPort 1636
```
