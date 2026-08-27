---
name: verification
description: Prime on the AsicSharp Verification domain before working on it — the non-throwing step model, Verify/VerifyExtended, VerificationStep, AsicVerifyResult, per-file manifest digest checks, the CAdES signature check, and the deliberate exclusion of any trust decision. Use when the task touches verifying a container, adding or renaming a verification step, IsValid or Error semantics, hash-algorithm OID mapping, or the verify CLI command. Not for building containers (see container), the TSA request (see timestamping), or the archive-timestamp chain's shape (see renewal).
---

# Verification domain — priming

**Canonical spec:** [`docs/verification.md`](../../../docs/verification.md) — read it for the full invariant list, key files and gotchas. Terms of record: [`UBIQUITOUS_LANGUAGE.md`](../../../UBIQUITOUS_LANGUAGE.md) § Verification, plus its flagged ambiguities for *valid*, *signature*, *certificate*.

Reporting, check by check, whether a container's bytes are unaltered — and nothing beyond that. The chain walk lives here but its *shape* is owned by [`renewal`](../renewal/SKILL.md), which documents a live ordering defect.

## Core invariants (get these right)

- **`Verify` reports, it does not throw.** Every failure becomes a failed `VerificationStep`. The only throws are `ArgumentException` on null/empty bytes and `FileNotFoundException` from `VerifyFile`.
- **`IsValid` = every step passed.** So **adding a *failable* step makes containers that verify today invalid** — treat one as a breaking change.
- **`Manifest completeness` is deliberately always-passing.** It reports ASiC-E ZIP entries with no manifest reference via `AsicVerifyResult.UnreferencedFileNames` without moving the verdict, because failing it would invalidate third-party containers that legitimately carry extra entries. It is the only informational step — if you add another, record it here.
- **`Error` is the `"; "`-joined details of failing steps** — a diagnostic string, never parse it.
- **The verifying hash algorithm comes from the token's OID, never from options.** Unrecognized OIDs throw and become an invalid result.
- **Never a trust decision: no `X509Chain` is built for the TSA cert.** A self-issued TSA yields `IsValid = true`. Say "unaltered" / "cryptographically valid", never "trusted".
- **But the CAdES step *does* chain-validate** (`CheckSignature(verifySignatureOnly: false)`) — one result can carry a validated signing cert beside an unvalidated TSA cert. Never blur them.
- **In ASiC-E a swapped file fails at the manifest digest step, not the token step** — the token still verifies.
- **Manifest presence outranks the mimetype** when routing to the ASiC-E path.
- **Step names and ordering are contract** — asserted by tests, printed verbatim by `verify -v`.
- **`Verify(byte[])` and `Verify(Stream)` share `VerifyContainer(Func<ZipArchive>)`** and must stay step-for-step identical; the stream overload throws on a non-seekable stream. ASiC-E digests come from `ComputeEntryHash` (straight off the archive, so the `Data file: <uri>` detail reports `entry.Length`); the ASiC-S path still materialises `DataBytes`.

## Key files / reuse

- `src/AsicSharp/Services/AsicService.cs` — `Verify`, `VerifyExtended`, `VerifyTimestampToken`, `VerifyCmsSignature`, `FailResult`, `OidToHashAlgorithmName`.
- `src/AsicSharp/Models/AsicResults.cs` — `AsicVerifyResult`, `VerificationStep`, `TimestampChainEntry`.

## Gotchas

- **`DataHash` and `HashAlgorithm` can disagree on the same result** — `DataHash` is recomputed with `options.HashAlgorithm` while `HashAlgorithm` comes from the token. A SHA-512 container yields a SHA-256 hex labelled "SHA512".
- **`DataBytes` is ASiC-S only** — null for a valid ASiC-E container.
- **ASiC-E completeness is reported, not enforced** — an unreferenced ZIP data entry is still never hashed, but it is named in `UnreferencedFileNames` and excluded from `ExtractAll`. `IsValid` ignores it by design; enforce "every byte covered" yourself. Null (not empty) for ASiC-S. Partially mitigated: `STRIDE.md` T-9, #25.
- **`FailResult` returns a truncated `Steps` list** on early exit; length is not fixed.
- **Unit tests cannot reach token decode** (non-DER placeholder tokens), so signature and hash-match verification is integration-only — and CI runs integration `continue-on-error: true`.

**Same-PR rule:** behavior changes here update `docs/verification.md` in the same PR; load-bearing invariant changes update this file too.
