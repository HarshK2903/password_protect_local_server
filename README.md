# Fileshare

A self-hosted Go CLI that shares one local directory through an authenticated, read-only HTTPS server. One executable contains the server, login page, folder browser, and CSS. No database, frontend runtime, or cloud service is used.

## Build

Go 1.25 or newer is required by this module and its dependencies. `go.mod` selects Go 1.26.8 as the preferred toolchain; Go's automatic toolchain selection can download it. Keep your installed toolchain current with security fixes.

```sh
go mod download
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/fileshare ./cmd/fileshare
./bin/fileshare --help
```

The only external modules are `golang.org/x/crypto` (Argon2id), `golang.org/x/term` (password entry without echo), and `golang.org/x/sys` (nonblocking, no-follow Unix file opens).

## Start sharing

You need a TLS certificate whose Subject Alternative Name covers the selected IP or hostname, its matching private key, and a password containing 12–1024 bytes. Put private keys and password files **outside** the shared directory. Hidden files are excluded, but that is not a substitute for separating secrets.

```sh
# Local access only; server.crt must cover 127.0.0.1.
./bin/fileshare share ./documents \
  --cert /private/tls/server.crt --key /private/tls/server.key

# Other devices on your LAN; replace this with the host's actual interface IP.
./bin/fileshare share ./documents --bind 192.168.1.20 --port 8000 \
  --cert /private/tls/server.crt --key /private/tls/server.key \
  --auth --read-only --exclude '*.key' --exclude private
```

The terminal prompts for the password twice without echoing it. The JSON `server_started` log contains the HTTPS URL. Open that URL on a device that trusts the certificate issuer and sign in. The host's firewall must allow the chosen port on the intended LAN interface.

Authentication and read-only behavior are mandatory, including when those flags are omitted. `--auth=false` and `--read-only=false` fail validation. There is no HTTP fallback. The default bind is `127.0.0.1`; wildcard addresses such as `0.0.0.0` and `::` are rejected. Selecting a non-loopback address is an explicit exposure choice; avoid public interfaces unless that is intended.

For unattended startup, use an owner-only password file rather than a command-line password:

```sh
chmod 600 /private/fileshare-password
./bin/fileshare share ./documents --bind 192.168.1.20 \
  --cert /private/tls/server.crt --key /private/tls/server.key \
  --password-file /private/fileshare-password
```

The file contains the password with an optional final LF or CRLF. Other whitespace is preserved. On Unix it must be a regular file with no group/other permission bits. On Windows, restrict its ACL to the owner; Unix permission-bit enforcement is unavailable there. Passwords are never accepted as CLI argument values or environment variables.

## Trusted local HTTPS certificates

Use an existing trusted certificate, or issue a server certificate from a private local CA and explicitly install that CA's **public certificate** in every connecting device's trust store. Never bypass certificate warnings or TLS verification. Fileshare verifies the configured certificate's identity, validity dates, server usage, and key pairing; only the client can establish that its issuer is trusted.

Here is an OpenSSL example. Run it outside your shared directory. Replace `192.168.1.20` with your real LAN IP before creating the certificate:

```sh
umask 077
mkdir -p "$HOME/.fileshare/tls"
cd "$HOME/.fileshare/tls"

openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -noenc \
  -keyout ca.key -out ca.crt -subj '/CN=Fileshare Local CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl req -new -newkey rsa:3072 -noenc \
  -keyout server.key -out server.csr -subj '/CN=Fileshare'

cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1,IP:192.168.1.20
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 90 -sha256 -extfile server.ext
openssl x509 -in ca.crt -noout -fingerprint -sha256
```

Transfer only `ca.crt` to clients, verify its fingerprint through a trusted channel, and install it as a trusted CA using each device/browser's certificate settings. Keep `ca.key` and `server.key` private. After trusting the CA, a verification check such as `curl --cacert ca.crt https://192.168.1.20:8000/login` should succeed. Use the browser login to access protected files. Renew certificates before they expire; restart the server to load a replacement certificate.

For a DNS certificate, use `--hostname fileshare.example` and a certificate with that DNS SAN. Configure your local DNS or hosts entries yourself. The Host header must match the configured hostname (or bind IP when no hostname is set). A trusted reverse proxy must preserve that Host header, and its upstream connection must also use HTTPS.

## Controls and defaults

Run `fileshare share --help` for every option. Flags must be together before or after the directory. `fileshare version` prints the build version. Ctrl-C or SIGTERM starts graceful shutdown.

| Control | Default |
| --- | --- |
| Failed-password window | 5 failures within 10 minutes |
| Login cooldown | 15 minutes, escalating to 30 then 60 minutes |
| Violation history / inactive IP retention | 24 hours / 24 hours |
| Per-IP login rate | 10/minute, burst 5 |
| Global verification rate | 30/minute, burst 5 |
| Concurrent verification | 1/IP, 2 globally |
| Argon2id | 64 MiB, 3 passes, 2 lanes, 16-byte random salt, 32-byte verifier |
| Session idle / absolute lifetime | 30 minutes / 8 hours |
| Tracked IPs / sessions | 4096 / 1024 |
| TCP connections / active handlers / downloads | 128 / 64 / 8 |
| Directory entries scanned per listing | 10,000, then HTTP 413 |
| Header / request read / idle timeout | 5 seconds / 15 seconds / 1 minute |
| Response and transfer deadline | 30 minutes |
| HTTP header / login body limit | `net/http` 16 KiB setting / 4096 bytes |
| Maintenance interval / shutdown grace | 1 minute / 15 seconds |

Common policy options: `--max-failures`, `--failure-window`, `--cooldown`, `--max-cooldown`, `--violation-ttl`, `--ip-ttl`, `--login-rate`, `--login-burst`, `--global-login-rate`, `--global-login-burst`, `--auth-per-ip`, `--auth-concurrency`, `--session-idle`, `--session-lifetime`, `--max-ips`, `--max-sessions`, `--max-connections`, `--max-requests`, `--max-transfers`, `--max-entries`, and `--shutdown-timeout`. Rates are specified per minute. All limits and durations are validated before serving.

Incorrect passwords return 401 below the threshold; reaching the threshold returns 429. Blocked or per-IP rate-limited requests return 429 with `Retry-After` before hashing. Global admission/state exhaustion returns 503 with `Retry-After`. Saturated transfer/request slots return 503; excess TCP connections are closed. Expired records are reclaimed at capacity and by maintenance. Live protected state is never evicted to admit another identity.

Exclusions use Go slash-path glob syntax. Patterns without `/` match any component; patterns with `/` match paths relative to the root. Excluding a directory excludes its descendants. Dot-prefixed components are always hidden. Client path components must exactly match directory-entry spellings; case-folded, Unicode-normalized, and Windows short-name aliases are refused. Every component lookup scans at most `--max-entries` entries, including on direct downloads; very large directories can return 413. Relative paths are limited to 4096 bytes and 128 components. All symbolic links are refused, including links that point inside the shared directory, so aliases cannot bypass exclusions. Only directories and regular files are served. There are no upload, modification, or deletion endpoints.

## HTTP interface

| Endpoint | Access and behavior |
| --- | --- |
| `GET /login` | Public password form; sets a secure login CSRF cookie |
| `POST /login` | URL-encoded `password` and `csrf`; CSRF cookie must match; applies login admission |
| `GET /static/style.css` | Public embedded stylesheet |
| `GET /?path=relative/folder` | Session required; private HTML browser |
| `GET /api/files?path=relative/folder` | Session required; JSON `{path, entries}` |
| `GET /api/download/{path...}` | Session required; attachment streaming with Range/If-Range support |
| `HEAD` on GET routes | Same authorization; no response body |
| `POST /logout` | Session and session-derived CSRF token required; revokes the session |

The session cookie is `__Host-fileshare_session`, with `Secure`, `HttpOnly`, `SameSite=Strict`, path `/`, and no Domain. Tokens contain 256 random bits and only their SHA-256 hashes are stored. Every protected request validates idle expiry, absolute expiry, revocation, and read permission. Logging out revokes the token immediately. Restarting invalidates all sessions and resets temporary IP state.

Form tokens and same-origin checks protect login and logout. Browser access from other origins is refused; no CORS access is enabled. Private responses use `Cache-Control: no-store`, including file-range errors, and downloads use attachment disposition and `nosniff`. Browser templates escape names and encode URLs; file contents are never rendered inline.

## Proxy and IP limitations

Direct deployment uses the TCP peer IP, normalizing IPv4-mapped IPv6 addresses. Forwarding headers are ignored by default. `--trusted-proxy 127.0.0.1/32` enables `X-Forwarded-For` only from that explicitly trusted CIDR. The chain is validated and read from the trusted end to the first untrusted address. Your proxy must remove or safely append incoming forwarding headers; do not trust a subnet containing arbitrary clients. `Forwarded`, `X-Real-IP`, and forwarded scheme headers are not used.

Clients behind NAT share login budgets. IP addresses identify sources, not people: IPv6 privacy addresses and distributed clients can change sources. The global rate, global verification slots, and state caps remain in force. IP-table exhaustion fails new logins closed until state expires; established sessions remain usable. Someone sharing a victim's IP can intentionally trigger a temporary login lockout. Successful logins clear recent failures but preserve violation history until it expires. Cooldowns apply to new logins and never revoke unrelated authenticated sessions.

## Logging and lifecycle

JSON logs go to stderr; they include login outcomes, source IPs, cooldown activation/expiry, session activity/revocation, route patterns, response bytes, latency, lifecycle events, and periodic resource snapshots (active handlers/downloads, sessions, IP records, heap bytes, goroutine count). Passwords, tokens, form bodies, query strings, and client file names are excluded from request logs. Directory names in the startup log and source IPs are operational data; store logs accordingly. Synchronous logging requires no separate flush buffer.

Shutdown stops new connections and admissions, waits for existing requests up to the grace period, cancels remaining requests and closes connections, waits for bounded active verification work, stops maintenance, closes retained filesystem handles, and emits final metrics. Argon2 itself cannot be cancelled midway; an already running verification may finish after the configured grace deadline. File I/O ultimately depends on the host filesystem's responsiveness.

There is no persistent database or remote administration API. Status commands, owner-wide session revocation, allowlisting, and manual cooldown controls are deferred extensions; stopping/restarting the process resets the current in-memory state. Signing out revokes an individual session.

## Validate

```sh
go test ./...
go test -race ./...
go vet ./...
go test ./internal/files -run='^$' -fuzz=FuzzConfinedPaths -fuzztime=15s -parallel=2
```

Integration tests bind only local loopback HTTPS listeners and use an explicitly trusted test CA or `httptest` trust store. They need permission to open loopback sockets. Tests cover real Argon2/TLS authentication, bypass attempts, CSRF and Host checks, cookie properties, idle/absolute expiry, revocation, brute force and parallel reservations, cooldown escalation, resource/state limits, symlink replacement races, special files, malicious-path fuzzing, large sparse-file transfers, byte ranges, cancellation, and graceful/forced shutdown. `Makefile` provides `build`, `test`, `race`, `fuzz`, `vet`, and `check` targets.

See [architecture](docs/architecture.md) and [security boundaries](SECURITY.md) for the design and its limits.
