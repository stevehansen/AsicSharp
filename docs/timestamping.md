# Timestamping

Turning a hash into a TSA-signed timestamp token — the one part of this library that talks to the outside world.

**Status:** current as of the domain-priming pass (2026-07-31) · **Governing issues:** none — foundational domain, present since the first commit.
**Priming skill:** [`.claude/skills/timestamping/SKILL.md`](../.claude/skills/timestamping/SKILL.md)

## What it is

The RFC 3161 client: build a timestamp request for a hash, POST it to a Timestamp Authority, validate the reply, hand back a token. It owns the multi-URL fallback walk, the nonce and signer-certificate request policy, and the HTTP timeout.

It is **not** where tokens are stored (→ [`container.md`](container.md)), **not** the act of re-stamping an existing token (→ [`renewal.md`](renewal.md)), and **not** any judgement about whether a TSA is trustworthy — that is deliberately the caller's (→ [`verification.md`](verification.md) § trust).

## Core entities & relationships

```
AsicTimestampOptions ──▶ TsaClient ──HTTP POST──▶ Timestamp Authority
        (URLs, algorithm, nonce, timeout)   │
                                            └──▶ TimestampResult { TokenBytes, Timestamp, TsaCertificate, TimestampAuthorityUrl }
```

`ITsaClient` is the seam every unit test substitutes. `TsaClient` is registered as a **typed `HttpClient`** by [`ServiceCollectionExtensions`](../src/AsicSharp/Extensions/ServiceCollectionExtensions.cs); the standalone constructor takes an `HttpClient` you own. Well-known TSA URLs are constants in [`WellKnownTsa.cs`](../src/AsicSharp/Configuration/WellKnownTsa.cs).

## Invariants & rules

- **Only a hash ever leaves the process.** The TSA sees a digest and never the data. This is the confidentiality property the whole design rests on — never add a code path that posts content.
- **The caller supplies the `(hash, algorithm)` pair and nothing checks they agree.** `RequestTimestampAsync` trusts them. Hand it a SHA-256 digest labelled SHA-512 and the TSA signs a lie that verification will later reject as a hash mismatch, far from the cause.
- **`TimestampAuthorityUrls` replaces `TimestampAuthorityUrl` entirely when non-empty** — it is not appended to, and the single-URL property is then ignored. Setting only the plural and expecting the singular to remain the primary is the mistake to avoid; the CLI sets *both* deliberately.
- **Fallback triggers on exactly two exception types:** `HttpRequestException` and `TimestampAuthorityException`. Anything else (e.g. `TaskCanceledException` from the timeout, `OperationCanceledException` from the caller's token) aborts the whole walk immediately rather than trying the next TSA. Adding a fallback trigger changes availability behavior for every caller.
- **The last failure is thrown only after every URL has failed**, wrapped in a `TimestampAuthorityException` unless it already was one. A partial failure is never surfaced — a successful second TSA looks identical to a successful first.
- **Nonce replay protection is enforced by `Rfc3161TimestampRequest.ProcessResponse`, not by our code.** We generate 8 random bytes and hand them to the request object; the platform checks the echo. Bypassing `ProcessResponse` would silently drop the protection.
- **`RequestSignerCertificates` must stay `true` for offline verification to work.** It asks the TSA to embed its certificate chain in the token. Without it, `VerifySignatureForHash` has no certificate to recover and verification can confirm nothing about who signed.
- **The stored token is `token.AsSignedCms().Encode()`, not the raw HTTP response body.** The `.tst` entry is the CMS structure. Renewal hashes exactly these bytes, so changing the encoding step invalidates every existing chain.
- **The timeout is applied to the `HttpClient` at DI registration time**, from `options.Timeout`. Mutating `Timeout` after the provider is built has no effect — the handler is already configured.
- **SHA-1 is reachable on purpose** (CA5350 suppressed) for TSAs that still require it. It is never a default and `AsicTimestampOptions.HashAlgorithm` defaults to SHA-256.

## Key files

| File | Role |
|---|---|
| [`src/AsicSharp/Services/TsaClient.cs`](../src/AsicSharp/Services/TsaClient.cs) | `ITsaClient`, the URL fallback walk, request construction, response processing |
| [`src/AsicSharp/Configuration/AsicTimestampOptions.cs`](../src/AsicSharp/Configuration/AsicTimestampOptions.cs) | URL(s), `HashAlgorithm`, `UseNonce`, `RequestSignerCertificates`, `Timeout` |
| [`src/AsicSharp/Configuration/WellKnownTsa.cs`](../src/AsicSharp/Configuration/WellKnownTsa.cs) | DigiCert (default), Sectigo, GlobalSign, FreeTSA, Apple, Entrust |
| [`src/AsicSharp/Models/TimestampResult.cs`](../src/AsicSharp/Models/TimestampResult.cs) | Token bytes, instant, TSA certificate, answering URL |
| [`src/AsicSharp/Extensions/ServiceCollectionExtensions.cs`](../src/AsicSharp/Extensions/ServiceCollectionExtensions.cs) | Typed-`HttpClient` registration, timeout and `Accept` header |

## Gotchas

- **A "successful" call can return a null `TsaCertificate`.** Certificate extraction sits in its own try/catch that logs at Debug and moves on. Callers treating a non-null cert as guaranteed will NRE on an unusual TSA.
- **`TimestampResult.TimestampAuthorityUrl` is the URL that actually answered**, which may be a fallback rather than the configured primary. `AsicCreateResult` coalesces it to `options.TimestampAuthorityUrl` when null — so the reported URL is authoritative for "who stamped this" only when non-null upstream.
- **The token's instant comes from the TSA's clock, not ours.** Nothing sanity-checks it against local time; a misconfigured TSA can back- or forward-date. That is an accepted trust boundary, tracked in [`STRIDE.md`](../STRIDE.md).
- **Both `AddAsicSharp` overloads duplicate the `HttpClient` configuration block.** Change one and you must change the other; there is no shared helper.
- **`Timeout` is per HTTP request, not per `RequestTimestampAsync` call.** With three fallback URLs, the worst case is three times the configured timeout.

## Executable references

- [`tests/AsicSharp.Tests/TsaClientTests.cs`](../tests/AsicSharp.Tests/TsaClientTests.cs) — 10 facts against a `MockHttpMessageHandler`, **the authority on fallback and request flags**. `RequestTimestampAsync_FallbackToSecondUrl_ShouldTryBothUrls` and `_AllUrlsFail_ShouldThrowTimestampAuthorityException` settle the fallback contract; the three `UseNonce`/`RequestSignerCertificates` facts decode the outgoing request to assert the flags actually reach the wire.
- [`tests/AsicSharp.Tests/IntegrationTests.cs`](../tests/AsicSharp.Tests/IntegrationTests.cs) — `TsaClient_ShouldGetTimestampFromDigiCert` is the only assertion against a real TSA. `Category=Integration`, and CI runs it with `continue-on-error: true`, so **a break here does not fail the build**.
- [`tests/AsicSharp.Tests/DependencyInjectionTests.cs`](../tests/AsicSharp.Tests/DependencyInjectionTests.cs) — 4 facts pinning the typed-client registration and options binding.
- **Riskiest unasserted behavior:** the timeout path. No test drives `options.Timeout` to expiry, so nothing pins whether a slow TSA falls through to the next URL or aborts the walk — and per the invariant above, it aborts.

## Links

- Glossary: [`UBIQUITOUS_LANGUAGE.md`](../UBIQUITOUS_LANGUAGE.md) § Timestamping
- Threat model: [`STRIDE.md`](../STRIDE.md) — TSA operational security, nonce replay protection
- Related domains: [`container.md`](container.md) (boundary: it stores what this returns) · [`renewal.md`](renewal.md) (boundary: renewal is this domain called again, over a token's bytes) · [`verification.md`](verification.md) (boundary: verification re-checks the token offline, using the token's own algorithm)
- Priming skill: [`.claude/skills/timestamping/SKILL.md`](../.claude/skills/timestamping/SKILL.md)
