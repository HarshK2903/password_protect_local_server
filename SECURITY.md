# Security boundaries

Fileshare protects a deliberately shared, read-only directory from unauthenticated LAN clients. It is an initial single-instance implementation with production-inspired controls, not a claim of independent audit or protection against every denial-of-service attack.

## Trust model

The owner, OS, executable, CA, and directory contents are trusted. Clients must verify the certificate using an explicitly trusted CA and the correct IP/DNS identity. TLS 1.3 is mandatory. A shared password grants the same read-only access to every authenticated client; there are no separate user accounts or per-user directory permissions.

The retained `os.Root` and opened descriptors enforce filesystem confinement. Component identities are checked across opens, symlink aliases are refused, and Unix final opens use `O_NOFOLLOW | O_NONBLOCK`. Client component spellings must appear exactly in bounded directory-entry scans, refusing case/Unicode/short-name filesystem aliases that could bypass policy. Hidden components and configured exclusions are checked before access. This does not defeat OS permissions, host compromise, files deliberately hard-linked/mounted into the share, or changes to an already opened regular file. Restrict write access to the shared directory. Serve ordinary local filesystems; the OS controls whether blocked disk operations can be interrupted.

Known key/password file paths within the root are rejected during bootstrap. This is a startup guard for owner configuration; it cannot identify every secret, hard-link alias, future mounted file, or subsequent owner mistake. Share a directory containing only material intended for recipients. Dot-prefixed file policy is based on names, not OS-specific hidden attributes.

## Authentication and admission

One salted Argon2id verifier remains in memory. Password buffers owned by the application are cleared when possible, but Go's HTTP parsing and runtime can retain temporary copies until garbage collection. Plaintext passwords and tokens are never deliberately logged or persisted.

Login admission uses one mutex to atomically check cooldown, prune sliding failures, consume per-IP/global token buckets, reserve remaining failure budget, and acquire per-IP/global counting-semaphore slots. Locks are released for hashing. Completion records failures and transitions cooldown state under the same mutex. Every exit path releases its reservation exactly once, including cancelled requests and invalid forms. Live cooldowns and in-flight state are not evicted at the tracking limit.

The global verification limit bounds simultaneously running Argon2 work; each verification uses 64 MiB plus overhead. Process memory also includes the Go heap, HTTP/TLS state, bounded maps, directory metadata, and transfer buffers. The defaults are suited to a small LAN service, not a guarantee of a fixed process RSS. Low-memory systems should reduce `--auth-concurrency` to 1 and use appropriate connection/request limits.

The session store uses 256-bit random opaque tokens with SHA-256 indexes and locks all shared state. Expiration is checked on every use. Secure, host-only cookies and CSRF controls protect browser state. A stolen live session can be replayed until revoked or expired; sessions intentionally do not bind to IPs because NAT and address changes are common. IP login cooldowns therefore leave established sessions intact.

## Abuse and exposure

Per-IP state can be shared by innocent users behind NAT, and source rotation can bypass per-IP policies. Global verification rates/concurrency, connection limits, request limits, session/IP caps, listing bounds, body/header settings, and deadlines apply independently. Distributed floods can still consume network bandwidth or exhaust the configured state capacity. IP lockout is not proof of malicious identity. Review the defaults for your LAN and protect public-facing deployments at the network boundary.

Bind a specific loopback or intended LAN IP. Fileshare does not discover interfaces, configure routers/firewalls, install trust roots, reload certificates, or manage a reverse proxy. Trusted proxy CIDRs are an explicit trust boundary, and forwarding headers from direct clients are ignored. HTTP/1.1 is used over TLS so connection/handler limits do not hide unbounded multiplexed HTTP/2 streams.

## Operational limitations

Restarting destroys all sessions and temporary rate/cooldown records. Certificate changes require restart. The cooldown table has no manual clear command, and sessions have no owner-wide revocation endpoint in this version. SIGINT/SIGTERM initiates bounded graceful shutdown; in-progress non-cancellable Argon2 or blocked OS file operations can extend final cleanup. JSON logging is synchronous, so the owner should direct stderr to a responsive sink.

Tests exercise the documented boundaries and concurrency behavior. They do not replace review of the host's directory contents, operating-system permissions, trusted CA setup, and selected network interface.
