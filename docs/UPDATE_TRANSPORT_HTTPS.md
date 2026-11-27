# HTTPS update transport - design review

Status: design review, written before any code. Nothing here is built yet.
Conclusion: **the design holds**; build notes are at the bottom.

## What HTTPS is for here (and what it is not)

The signed manifest is the only root of trust for an update's content.
Verification (threshold Ed25519, expiry, rollback) happens on bytes after
download, so a hostile or broken transport can only deny service, never
authorize anything. HTTPS therefore buys:

- integrity in transit as defense in depth under the signature,
- confidentiality of which artifacts a device fetches and when,
- a standard, operable way to serve updates.

HTTPS buys no authorization. Every check from `UPDATE_CHANNEL.md` still runs
on the downloaded bytes, unchanged. This is why **certificate pinning stays
rejected**: pinning adds a second, brittle root that can strand every device
on key rotation, while the manifest signature already covers what pinning
would pretend to add. (Pinning was considered before and deliberately not
merged; this review confirms that call.)

## Decisions

- **Scheme: `https://` only.** Plain HTTP is rejected at argument parsing.
  No userinfo (`user:pass@host`) in URLs: credentials do not belong in
  command lines, process lists or audit trails. No query-string credentials
  either; the URL is host + port + path prefix only.
- **TLS: rustls with webpki-roots, TLS 1.2 or newer.** Native system roots
  are not consulted, so behavior is identical across Linux distros and does
  not depend on the host's ca-certificates package. Verification cannot be
  disabled; there is no `--insecure` and never will be.
- **Redirects: rejected.** A manifest URL that redirects is an error, not a
  hint. One URL, one authority, no surprises in logs.
- **Size caps before reading.** The envelope is capped at the verifier's own
  1 MiB limit (the transport refuses `Content-Length` above it and aborts a
  body that grows past it). Each artifact is capped at its manifest-declared
  `size`: the transport requires an exact `Content-Length` equal to `size`
  and reads at most `size` bytes. The flow's `max_total_bytes` cap is checked
  by the flow before any artifact fetch, unchanged.
- **Timeouts: connect 10 s, per-read 30 s, total per request 120 s.**
  A hung server must not hang the CLI.
- **Retries: none in v1.** The operator or a timer re-runs the whole command;
  the flow is idempotent (`AlreadyCurrent`), so re-running is safe.
- **Proxies: ignored.** No `HTTP_PROXY`/`HTTPS_PROXY` env support in v1. A
  silent proxy would be an unrecorded middlebox in an OS that gates network
  access; explicit configuration can come later if a real user needs it.
- **Netpolicy stays separate.** The OS-level allow-list (pos-netpolicy) is
  unverified on real traffic and this transport does not depend on it: a
  blocked network shows up as a connect error, which the CLI reports as a
  transport failure, exit 2. Adding the update host to the netpolicy
  allow-list is an operator/owner step, documented in ADMIN docs when the
  feature ships.
- **HTTP/1.1 only** (ureq's default). No HTTP/2 dependency.
- **ETag/caching: none.** The manifest `sequence` is the versioning
  mechanism; HTTP caching layers would only add ways to serve stale content.

## Dependency choice

`ureq` 3.x (synchronous, matches the sync CLI; rustls-tls feature;
webpki-roots). Synchronous code keeps pos-cli free of an async runtime.
Licenses (MIT/Apache-2.0/ISC across the tree) pass the existing
`cargo deny check licenses`. MSRV must be verified against the workspace's
1.89 CI job before merge; if ureq 3.x needs newer Rust, the fallback is
`ureq` 2.x (also rustls) or `minreq`, in that order, and this document is
updated with what actually shipped.

## Testing plan

- `UrlTransport` sits behind a small `HttpGet` seam (one method: GET a URL,
  honor caps and timeouts, return bytes or an io::Error). Unit tests use a
  fake `HttpGet`; no network in tests.
- One integration test runs a plain-HTTP server on `127.0.0.1` through a
  `#[cfg(test)]`-only constructor that accepts `http://` loopback. The
  production constructor never accepts `http://`.
- TLS itself is not re-tested locally (rustls/webpki have their own suites);
  what we test is our cap, redirect, timeout and error-mapping logic.

## Build notes (if this holds - it does)

1. Add `ureq` (rustls-tls, no default features beyond tls) to pos-cli.
2. `UrlTransport { base_url, http: &dyn HttpGet }` in pos-cli next to
   `DirTransport`; `--transport-url URL` as an alternative to
   `--transport-dir DIR` (exactly one required). Envelope at
   `URL/<channel>.json`, artifacts at `URL/<name>` - same layout as the dir
   transport.
3. `--transport-url` rejects `http://`, userinfo and query/fragment at parse.
4. CLI.md + this document updated with what shipped; ROADMAP moves the HTTPS
   transport out of future work.
