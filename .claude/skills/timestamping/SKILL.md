---
name: timestamping
description: Prime on the AsicSharp Timestamping domain before working on it — the RFC 3161 client, TsaClient and ITsaClient, timestamp requests over HTTP, multi-URL TSA fallback, nonce and signer-certificate policy, WellKnownTsa URLs and AsicTimestampOptions. Use when the task touches obtaining a timestamp token, TSA URLs or fallback, Rfc3161TimestampRequest, the typed HttpClient registration, timeouts, or hash-algorithm configuration. Not for where the token is stored (see container), the offline re-check (see verification), or re-stamping an existing token (see renewal).
---

# Timestamping domain — priming

**Canonical spec:** [`docs/timestamping.md`](../../../docs/timestamping.md) — read it for the full invariant list, key files and gotchas. Terms of record: [`UBIQUITOUS_LANGUAGE.md`](../../../UBIQUITOUS_LANGUAGE.md) § Timestamping.

Turning a hash into a TSA-signed token — the only part of this library that talks to the network. Not storage, not the verdict, not the chain.

## Core invariants (get these right)

- **Only a hash leaves the process.** Never add a path that posts content to a TSA.
- **The `(hash, algorithm)` pair is caller-supplied and unchecked** — a mismatch surfaces much later as a verification hash mismatch.
- **`TimestampAuthorityUrls` replaces `TimestampAuthorityUrl` entirely when non-empty** — not appended. The CLI sets both on purpose.
- **Fallback triggers on `HttpRequestException` and `TimestampAuthorityException` only.** Anything else — including timeout cancellation — aborts the whole walk. The last failure is thrown only after every URL fails.
- **Nonce replay protection is enforced by `Rfc3161TimestampRequest.ProcessResponse`**, not by our code. Don't bypass it.
- **`RequestSignerCertificates` must stay true for offline verification** — without the embedded chain there is no TSA certificate to recover.
- **The stored token is `token.AsSignedCms().Encode()`**, not the raw HTTP body — renewal hashes exactly these bytes.
- **The timeout is baked into the `HttpClient` at DI registration**; mutating `options.Timeout` afterwards does nothing.

## Key files / reuse

- `src/AsicSharp/Services/TsaClient.cs` — the fallback walk, request construction, response processing.
- `src/AsicSharp/Configuration/AsicTimestampOptions.cs` · `WellKnownTsa.cs` (DigiCert default).
- `src/AsicSharp/Extensions/ServiceCollectionExtensions.cs` — typed-`HttpClient` setup, **duplicated across both overloads: change one, change the other**.

## Gotchas

- **A successful call can return a null `TsaCertificate`** — extraction failure is swallowed at Debug level.
- **`TimestampResult.TimestampAuthorityUrl` is whichever TSA actually answered**, possibly a fallback.
- **`Timeout` is per HTTP request** — three fallback URLs means up to 3× the wall clock.
- The token's instant is the TSA's clock; nothing sanity-checks it against local time (accepted trust boundary).
- SHA-1 is reachable on purpose (CA5350 suppressed) for TSA compat, never as a default.

**Same-PR rule:** behavior changes here update `docs/timestamping.md` in the same PR; load-bearing invariant changes update this file too.
