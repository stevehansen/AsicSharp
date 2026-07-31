# Verification

Inspecting a container and reporting, check by check, whether its bytes are unaltered — and nothing more than that.

**Status:** current as of the domain-priming pass (2026-07-31) · **Governing issues:** none — foundational domain. [#5](https://github.com/stevehansen/AsicSharp/issues/5) expanded its test coverage.
**Priming skill:** [`.claude/skills/verification/SKILL.md`](../.claude/skills/verification/SKILL.md)

## What it is

The read path: open the ZIP, decide the profile, and run every integrity check as a named `VerificationStep` — mimetype, data file or manifest digests, token decode, TSA signature, hash linkage, optional CAdES signature. The verdict is the conjunction of all steps.

It is **not** a trust decision. Verification answers *"were these bytes altered?"*, never *"should I believe this TSA?"*. It is also **not** container construction (→ [`container.md`](container.md)), **not** the TSA conversation (→ [`timestamping.md`](timestamping.md)), and it *shares* the chain walk with [`renewal.md`](renewal.md), which owns the chain's shape — including the ordering rule the walk depends on.

## Core entities & relationships

```
Verify(bytes) ──▶ mimetype step ──▶ profile routing
                                    ├── ASiC-S: Verify        (data file → token₁)
                                    └── ASiC-E: VerifyExtended (per-file digests → manifest → token₁)
                                                       │
                                    both then walk token₂…tokenₙ (renewal chain)
                                                       │
                                    ──▶ AsicVerifyResult { IsValid, Steps[], Timestamp, …, TimestampChain? }
```

`VerifyTimestampToken` and `VerifyCmsSignature` are the two private primitives; `FailResult` is the early-exit shape. All in [`AsicService.cs`](../src/AsicSharp/Services/AsicService.cs); the result types are in [`Models/AsicResults.cs`](../src/AsicSharp/Models/AsicResults.cs).

## Invariants & rules

- **`Verify` reports, it does not throw.** Every failure — corrupt ZIP, missing entry, oversized entry, undecodable token, unrecognized algorithm OID — is caught and becomes a failed result. The *only* throws are `ArgumentException` for null/empty container bytes and `FileNotFoundException` from `VerifyFile`. Note this swallows `InvalidAsicContainerException` from `ValidateEntrySize`, which the extract path *does* throw.
- **`IsValid` is "every step passed", computed by `steps.All(s => s.Passed)`.** Therefore **adding a step adds a new way for containers that verify today to become invalid.** Treat any new step as a breaking change and reason about existing containers in the wild first.
- **`Error` is the `"; "`-joined `Detail` of every failing step**, and null when valid. It is a diagnostic string, not a stable error code — don't parse it.
- **The hash algorithm used to verify comes from the token's own OID, never from options.** `OidToHashAlgorithmName` maps a closed set and throws on anything else, which the outer catch converts into an invalid result. This is what lets a SHA-512 container verify under default SHA-256 options.
- **No `X509Chain` is ever built for the TSA certificate.** A self-issued TSA yields `IsValid = true`. The certificate is handed to the caller so *they* can make the trust decision. Say "unaltered" or "cryptographically valid" in user-facing text — never "trusted".
- **The optional CAdES step is asymmetric to that rule:** `VerifyCmsSignature` calls `SignedCms.CheckSignature(verifySignatureOnly: false)`, which *does* perform chain validation. So one result object can carry a chain-validated signing certificate next to an entirely unvalidated TSA certificate. Never blur the two (glossary § "certificate").
- **In ASiC-E, a swapped data file fails at the manifest layer, not the token layer.** The token still verifies — its hash of the manifest is untouched. The per-file `Data file: <uri>` digest step is the check that catches it, which is exactly why the manifest bytes must stay frozen.
- **Profile routing: manifest presence outranks the mimetype.** A container whose mimetype says `asic-s` but which contains `META-INF/ASiCManifest.xml` is verified as ASiC-E. The mimetype step's own pass/fail is recorded independently.
- **Step names and ordering are contract.** Tests assert them and the CLI's `verify -v` prints them verbatim as an audit trail. Renaming a step is a user-visible change.

## Key files

| File | Role |
|---|---|
| [`src/AsicSharp/Services/AsicService.cs`](../src/AsicSharp/Services/AsicService.cs) | `Verify`, `VerifyFile`, `VerifyExtended`, `VerifyTimestampToken`, `VerifyCmsSignature`, `FailResult`, `OidToHashAlgorithmName` |
| [`src/AsicSharp/Models/AsicResults.cs`](../src/AsicSharp/Models/AsicResults.cs) | `AsicVerifyResult`, `VerificationStep`, `TimestampChainEntry` |
| [`src/AsicSharp/Exceptions.cs`](../src/AsicSharp/Exceptions.cs) | `AsicVerificationException`, `InvalidAsicContainerException` |
| [`src/AsicSharp.Cli/Program.cs`](../src/AsicSharp.Cli/Program.cs) | `verify` — `-v` prints every step; exit code 1 when invalid |

## Gotchas

- **`DataHash` and `HashAlgorithm` on the same result can disagree.** `HashAlgorithm` is read from the token's OID, but `DataHash` is recomputed with `_options.HashAlgorithm`. Verify a SHA-512-stamped container with default options and you get a SHA-256 hex string labelled `"SHA512"`. Don't present the two together as one fact.
- **`DataBytes` is populated on the ASiC-S path only.** `VerifyExtended` never sets it, so it is null for a perfectly valid ASiC-E container. Use `ExtractAll` there.
- **No completeness check on ASiC-E.** Verification walks the manifest's `DataObjectReference` list; a data file sitting in the ZIP that the manifest never mentions is neither hashed nor reported, and the container still reports valid. Combined with `ExtractAll` walking ZIP entries rather than the manifest, a verify-then-extract-all caller can surface bytes the proof never covered. Open — [`STRIDE.md`](../STRIDE.md) T-9, [#25](https://github.com/stevehansen/AsicSharp/issues/25). Closing it with a failing step would invalidate containers that verify today, so it needs a compatibility decision first.
- **A container with no `.tst` at all is invalid via a single failed step**, not an exception — and `Timestamp` is then null while `IsValid` is false.
- **`FailResult` returns whatever steps were collected before the failure.** A short `Steps` list is normal on early exit; never treat its length as fixed.
- **The whole token path is unreachable from unit tests.** They feed a non-DER placeholder (`CreateFakeTimestampToken` returns plain UTF-8), so `TryDecode` always fails and the signature, hash-match and chain-link assertions never execute. Signature verification is integration-only.
- **`FileNames` is unsanitized manifest text on the ASiC-E path** but `Path.GetFileName`-ed on the ASiC-S path. Sanitize before touching the filesystem.

## Executable references

- [`tests/AsicSharp.Tests/AsicServiceTests.cs`](../tests/AsicSharp.Tests/AsicServiceTests.cs) — 64 facts total, ~25 named `Verify_*`, **the authority on the step model**: `Verify_MissingMimetypeEntry_ShouldReturnFailedMimeStep` and `_WrongMimetypeContent_*` settle that a bad mimetype is a *step*, not a throw; `Verify_ExceedingMaxFileSize_ShouldReturnInvalid` settles that the oversize exception is swallowed here; `Verify_WithEmptyBytes_ShouldThrow` settles the one genuine throw; the four `Verify_AsicE_*` facts settle tampered / missing / malformed manifest handling.
- [`tests/AsicSharp.Tests/IntegrationTests.cs`](../tests/AsicSharp.Tests/IntegrationTests.cs) — `AsicService_RoundTrip_CreateAndVerify` and `AsicService_TamperedData_ShouldFailVerification` are the **only** assertions that a real token's signature and hash linkage are actually checked. CI runs this job `continue-on-error: true`, so its failure does not break the build.
- **Riskiest thinly-asserted behavior:** everything past `Rfc3161TimestampToken.TryDecode` on a genuine token — TSA signature validity, the data/manifest hash match, and chain links — rests entirely on the integration job, which CI allows to fail. That gap is what hid the chain-ordering defect (fixed 2026-07-31, see [`renewal.md`](renewal.md)) for as long as it existed. The ASiC-E per-file digest path has no real-token coverage at all.

## Links

- Glossary: [`UBIQUITOUS_LANGUAGE.md`](../UBIQUITOUS_LANGUAGE.md) § Verification — and its flagged ambiguities for *valid*, *signature*, *certificate*
- Threat model: [`STRIDE.md`](../STRIDE.md) — S-3 (revoked signing cert), T-6 (manifest digest), T-7 (chain tampering), T-9 (ASiC-E completeness, open)
- Related domains: [`container.md`](container.md) (boundary: layout vs. verdict) · [`renewal.md`](renewal.md) (boundary: renewal owns the chain's shape, this domain owns the walk — the code is shared) · [`timestamping.md`](timestamping.md) (boundary: online acquisition vs. offline re-check)
- Priming skill: [`.claude/skills/verification/SKILL.md`](../.claude/skills/verification/SKILL.md)
