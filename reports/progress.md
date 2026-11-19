# Fileshare implementation progress

Recorded: 2026-11-08, Asia/Kolkata.

## Status and scope

The initial application described in `task.txt` is implemented and validated. The full task and the referenced architecture image at `/home/bugulnoz/Downloads/mermaid-diagram.png` were read before implementation. The suggested modular package structure was followed at the workspace root, without introducing an additional `fileshare/` wrapper directory.

Workspace: `/media/bugulnoz/New Volume/temp/password_protect_local_server`.

The user subsequently requested this progress record before exiting, preserving existing files and avoiding repeated completed analysis. No existing `reports/progress.md` was present when checked. This report records completed work; saving it did not rerun analysis, rebuild the application, or change application sources. Existing files, including `task.txt`, are preserved.

## Implemented behavior

- A single-process Go CLI and HTTPS server, with embedded HTML templates and CSS, requiring no database, cloud service, frontend runtime, or separate server process.
- `fileshare share DIRECTORY [options]`, root/share help, and version commands. Options can be grouped before or after the directory. Authentication and read-only operation are mandatory; attempts to disable either are rejected.
- Configuration defaults and validation for directory, selected bind address, port, certificate identity, exclusion patterns, proxy trust, rates, concurrency, state capacities, and timeout consistency.
- Loopback binding by default. LAN sharing requires an explicitly selected interface IP. Wildcard binding is rejected.
- Mandatory TLS 1.3, certificate/key pairing checks, certificate validity and server-usage checks, and SAN verification against the selected IP or configured hostname. There is no HTTP fallback or insecure verification option. Connecting devices must separately trust the issuing CA.
- Hidden terminal password entry with confirmation, or an owner-only regular password file for unattended startup. Passwords are not accepted through argument values or environment variables. Configured password files and TLS private keys inside the shared directory are rejected.
- A randomly salted Argon2id verifier using 64 MiB, three passes, two lanes, a 16-byte salt, and a 32-byte output. Application-owned password buffers are cleared when possible.
- Random 256-bit opaque session tokens, indexed only by SHA-256 digest in a bounded, mutex-protected in-memory store. Sessions track creation, last activity, absolute expiration, and read permission. Idle expiration, absolute expiration, and revocation are checked during requests.
- Host-only `__Host-fileshare_session` cookies with `Secure`, `HttpOnly`, `SameSite=Strict`, and path `/`. Login and logout have CSRF protection and same-origin checks. Successful login rotates the browser's prior session; logout revokes it.
- A mutex-protected IP guard with sliding failed-login windows, cooldown deadlines, repeated-violation history, last activity, per-IP rate buckets, and in-flight reservations.
- Default protection of five wrong passwords within ten minutes, followed by fifteen minutes of cooldown, escalating to thirty and sixty minutes. Old failure/history state expires synchronously and through maintenance.
- Atomic reservation of remaining failure budget and per-IP/global verification capacity before expensive hashing. Locks are released during Argon2 work, and reservations release exactly once on all exit paths.
- Independent global authentication rate and concurrent-verification limits. Blocked login requests skip hashing. Per-IP restrictions use HTTP 429 and `Retry-After`; global overload/state exhaustion uses HTTP 503 and `Retry-After`.
- Actual TCP peer identification by default, including IPv4-mapped IPv6 normalization. Forwarding headers are ignored unless the immediate peer is an explicitly trusted proxy. Trusted `X-Forwarded-For` chains are bounded, validated, and processed from the trusted end to the first untrusted address.
- Protected browsing and download routes, so direct file URLs cannot bypass authentication. Cooldowns restrict new login attempts and preserve unrelated established sessions.
- Retained `os.Root` filesystem confinement. Client paths are normalized and checked against dot-file and exclusion policy. Directory handles are retained during traversal, and opened object identities are compared with `Lstat` metadata.
- Exact directory-entry spelling checks for client components, rejecting case-folded, Unicode-normalized, and Windows short-name aliases that could bypass exclusions. These parent-directory scans are bounded. Internally obtained listing names skip redundant spelling scans to avoid quadratic listing work.
- Refusal of all symlinks, including internal aliases, and refusal of special files. Unix final opens use `O_NOFOLLOW` and `O_NONBLOCK`, including protection against blocking FIFO replacement races.
- Descriptor-based metadata and bounded-memory download streaming through a context-aware `ReadSeeker` and `http.ServeContent`. Downloads support HEAD, byte ranges, If-Range, and conditional dates, with independent authentication and authorization.
- Attachment disposition, `nosniff`, private cache policy, CSP, frame denial, and related response headers. `Cache-Control: no-store` is preserved even for invalid-range responses.
- Bounds on accepted TCP connections, concurrent handlers, downloads, tracked IPs, sessions, directory scans, request headers, and login bodies. Network read/write/idle deadlines and cancellation-aware file operations are configured.
- Periodic session/IP cleanup and resource snapshots, plus JSON logging of authentication outcomes, source IPs, cooldown transitions, session activity, route patterns, response bytes, latency, downloads, heap/goroutine counts, and lifecycle events. Passwords, session tokens, form bodies, query strings, and client file names are excluded from request logs.
- SIGINT/SIGTERM shutdown: stop admissions/listening, allow a grace period, cancel remaining requests and close connections, wait for admitted handlers and their synchronous request logs, stop maintenance, release filesystem resources, and finish logging.

## Project organization

- `cmd/fileshare/main.go`: process entry, signals, and exit handling.
- `internal/app/{app,bootstrap,lifecycle}.go`: composition root, owner-resource validation, dependency ownership, and HTTPS lifecycle.
- `internal/cli/{root,share,password}.go`: commands, flags, password acquisition, and version value.
- `internal/config/config.go`: typed settings, defaults, and validation.
- `internal/auth/{password,session}.go`: authenticator and hashed session store.
- `internal/security/`: IP guard/admission, token buckets, proxy address resolution, TLS configuration, and response headers.
- `internal/files/`: logical path policy, retained-root file service, and platform-specific safe file opens.
- `internal/server/`: route composition, middleware, login/logout/browser/API/download handlers, query parsing, and connection-limited listener.
- `internal/telemetry/logger.go`: JSON logger and atomic counters/resource snapshots.
- `internal/maintenance/cleanup.go`: cancellable periodic cleanup and metrics.
- `internal/testutil/cert.go`: private test-CA fixtures, imported only by tests.
- `web/assets.go`, `web/templates/{login,files,error}.html`, and `web/static/style.css`: executable-embedded UI assets.
- Unit tests alongside relevant packages; HTTPS integration tests in `tests/integration/server_test.go`; TLS configuration security tests in `tests/security/tls_test.go`.
- `README.md`: build/start instructions, trusted local CA recipe, configuration, HTTP interface, operational behavior, and validation commands.
- `SECURITY.md`: trust boundaries, abuse/resource behavior, and implementation limitations.
- `docs/architecture.md`: Mermaid request-flow diagram, package contracts, synchronization, filesystem design, and lifecycle.
- `Makefile`: build, test, race, fuzz, vet, check, and clean targets.
- `go.mod`, `go.sum`, and `.gitignore`: module metadata and generated/private artifact exclusions.

The HTTP composition uses the narrow `Authenticator`, `SessionStore`, `IPGuard`, and `FileService` interfaces. Rate buckets are private guard-owned state; global verification capacity is a counting semaphore protected by the same mutex. Handler/transfer admission uses buffered-channel semaphores.

## Key defaults

| Setting | Default |
| --- | --- |
| Bind / port | `127.0.0.1` / `8000` |
| Failed attempts / window | 5 / 10 minutes |
| Initial / maximum cooldown | 15 minutes / 1 hour |
| Violation history / inactive IP retention | 24 hours / 24 hours |
| Per-IP login rate / burst | 10 per minute / 5 |
| Global verification rate / burst | 30 per minute / 5 |
| Concurrent verifications | 1 per IP / 2 globally |
| Session idle / absolute expiration | 30 minutes / 8 hours |
| Tracked IPs / sessions | 4096 / 1024 |
| TCP connections / handlers / downloads | 128 / 64 / 8 |
| Directory/component scan bound | 10,000 entries |
| Logical path bound | 4096 bytes / 128 components |
| Header setting / login body bound | 16 KiB / 4096 bytes |
| Header / request-read / idle timeout | 5 seconds / 15 seconds / 1 minute |
| Response/transfer deadline | 30 minutes |
| Cleanup interval / shutdown grace | 1 minute / 15 seconds |

## HTTP surface

- Public: `GET /login`, `POST /login`, and `GET /static/style.css`.
- Authenticated HTML browser: `GET /?path=relative/folder`.
- Authenticated JSON listing: `GET /api/files?path=relative/folder`.
- Authenticated attachment download: `GET /api/download/{path...}`.
- Authenticated, CSRF-protected revocation: `POST /logout`.
- HEAD is supported on GET routes with the same authorization and no body.
- No upload, write, delete, remote administration, or unauthenticated file-serving routes exist.

## Validation completed

1. The normal Go test suite passed during implementation. After the final filesystem and lifecycle refinements, the complete suite passed again under `go test -race ./...`, exercising the final sources with the race detector.
2. `go vet ./...` passed against the final sources.
3. The final 15-second `FuzzConfinedPaths` run completed **100,130 executions** with two workers and no failures. An earlier 15-second run completed 99,019 executions without failures.
4. Unit/security coverage includes password verification and random salts; session hashing, idle/absolute expiration, revocation, concurrent capacity; sliding failure windows, success reset, cooldown escalation/history expiration, concurrent reservations, global/per-IP rate bounds, state cleanup, shutdown admission; trusted-proxy boundaries; malformed CLI configuration; password-file permissions; confined paths, hidden/excluded entries, exact spellings, symlink replacement races, special files, cancellation, and listing limits.
5. HTTPS integration coverage includes unauthenticated direct URL rejection, protected browsing/listing, CSRF and Host/origin checks, secure cookie properties, login failures, cooldown requests skipping hashing, preserved established sessions during cooldown, simultaneous login rejection, expiry/revocation, oversized forms, bounded handlers/transfers, large sparse-file streaming, ranges/HEAD, privacy headers on range errors, special-character file names, cancellation, and permit reuse.
6. Real application lifecycle tests use an explicitly trusted private test CA and real Argon2 verification. Both completed-transfer graceful shutdown and forced cancellation after the grace deadline passed.
7. Native Linux amd64 build passed. The final `bin/fileshare` is **statically linked**, approximately 13 MB (12,938,340 bytes at the final check).
8. Final Windows amd64 and macOS arm64 cross-builds passed. These are compilation checks; Windows/macOS runtime execution was not performed.
9. A CLI-level smoke test passed against the final static binary: generated certificates using the documented OpenSSL CA recipe; started the actual CLI with an owner-only password file; verified HTTPS using the CA; checked unauthenticated denial; logged in; listed private files; downloaded a byte range; logged out; verified denial after revocation; sent SIGTERM; confirmed clean exit and `server_stopped`; checked that logs contained neither the password nor session token.
10. Root help, share help, and version commands were exercised. The version output is currently `fileshare dev`.

No test servers or sharing processes were intentionally left running. Smoke-test directories, keys, passwords, and certificates were temporary and cleaned up.

## Build and verification environment

- Module: `fileshare`; minimum Go directive: `1.25.0`; preferred toolchain: `go1.26.8`.
- Dependencies: `golang.org/x/crypto v0.55.0`, `golang.org/x/sys v0.47.0`, and `golang.org/x/term v0.45.0`, with checked-in checksums.
- The shell's default Go was `go1.22.2`, so verification explicitly used the installed binary `/home/bugulnoz/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.8.linux-amd64/bin/go`.
- Writable caches used: `GOCACHE=/tmp/fileshare-go-build`, `GOMODCACHE=/tmp/fileshare-go-mod`, and `GOTOOLCHAIN=local`.
- Dependency downloads/checksum verification and loopback HTTPS tests required reviewed sandbox escalation because the sandbox initially blocked network sockets. They completed successfully. No approval rejection remained unresolved.
- The workspace has a nonfunctional/read-only `.git` placeholder rather than a usable repository. Builds use `-buildvcs=false` to avoid failing VCS stamping. No commits or repository changes were attempted.
- Final native build command: `CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/fileshare ./cmd/fileshare`, with the explicit toolchain/cache environment above in this session.
- Cross-build artifacts: `/tmp/fileshare-windows.exe` and `/tmp/fileshare-darwin`.
- CLI smoke-test script used: `/tmp/fileshare-cli-smoke.py`. It is a verification aid, not an application runtime dependency.
- Other `/tmp` artifacts and caches are disposable and may not survive environment cleanup.

## Remaining operational setup and limits

No implementation work from the initial scope remains pending. Actual owner sharing still requires choosing a directory and interface, supplying a valid certificate/key, arranging client CA trust, and choosing a password. Follow `README.md`; no real owner credentials or production certificates were created or requested.

The following are documented design boundaries or deferred optional extensions, not unfinished required implementation:

- State is in-memory. Restarting invalidates sessions and resets temporary cooldown/rate records.
- Shared passwords grant common read-only access; there are no separate user accounts or per-user directory permissions.
- IPs are source indicators, not permanent identities. NAT users share budgets; address rotation/distributed clients can bypass per-IP limits, while global limits and state caps remain effective. IP-table exhaustion fails new logins closed. Intentional lockout remains possible for clients sharing an IP.
- Root confinement cannot prevent exposure of files deliberately hard-linked or mounted into the shared directory, host compromise, or owner changes to shared contents. Dot-file policy uses names, not OS-specific hidden attributes. Windows password-file ACLs must be restricted by the owner.
- All symlinks are unavailable. Client spelling checks and entry/path caps intentionally constrain access even for direct downloads. A directory exceeding scan capacity can return 413.
- A stolen valid session can be replayed until revoked/expired. Sessions deliberately do not bind to IP addresses.
- Certificate trust installation, local DNS, firewall/router configuration, and certificate renewal are owner operations. Certificates reload on restart.
- Argon2 cannot be interrupted midway; already admitted verification work may finish after the shutdown grace deadline. OS-level blocked file I/O and a stalled synchronous log sink can also delay final cleanup.
- Owner status commands, owner-wide session revocation, manual cooldown clearing, IP allowlisting, and remote administration were optional future features in the task and are not implemented. Individual logout revocation and process shutdown/restart are available.

## Resume guidance

Read this report and the project documentation rather than repeating the completed task/diagram analysis. The existing binary and source are ready for review or use with the required owner configuration. If further changes are requested, make targeted edits and rerun only the relevant checks, expanding validation when the change warrants it. Preserve existing source, documentation, `task.txt`, and this history.
