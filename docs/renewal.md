# Renewal

Extending a container's proof of existence by adding an archive timestamp over the newest token, before its algorithms or certificates weaken.

**Status:** current as of the domain-priming pass (2026-07-31) · **Governing issues:** [#2](https://github.com/stevehansen/AsicSharp/issues/2) (timestamp renewal for long-term archival)
**Priming skill:** [`.claude/skills/renewal/SKILL.md`](../.claude/skills/renewal/SKILL.md)

## What it is

`RenewAsync` per ETSI EN 319 162-1 §5.4: hash the raw bytes of the container's newest timestamp token, get a fresh token over that hash, and append it as a new `META-INF/timestamp-NNN.tst` entry. Repeat over the years and the tokens form a chain, each link vouching that its predecessor existed intact at a later date.

This domain owns the chain's **shape** — ordering, naming, what covers what, and how it is appended. The chain **walk** lives inside `Verify`/`VerifyExtended` and is described in [`verification.md`](verification.md); the two share `GetTimestampEntriesInChainOrder` but the loop itself is duplicated, so a change to the walk touches both. It is **not** the TSA conversation (→ [`timestamping.md`](timestamping.md)).

## Core entities & relationships

```
data file (ASiC-S)  ──covered by──▶ token₁  ──covered by──▶ token₂  ──▶ … ──▶ tokenₙ
  or manifest (ASiC-E)                │                       │
                                 timestamp.tst          timestamp-002.tst
```

- **Original timestamp** = token₁ — the only one that says anything about when *the data* existed.
- **Archive timestamp** = token₂…ₙ — each covers exactly one preceding token's raw bytes.
- **`TimestampChainEntry`** ([`Models/AsicResults.cs`](../src/AsicSharp/Models/AsicResults.cs)) is one link: entry path, instant, TSA cert, algorithm, `IsValid`, `Order`.

## Invariants & rules

- **The reported `Timestamp`, `TsaCertificate` and `HashAlgorithm` always come from token₁.** Renewal extends a proof; it never moves it forward. Reporting an archive timestamp as "when the data existed" would be a factual error about the product's core claim.
- **Each archive timestamp covers the raw bytes of the token before it** — not the data, not the manifest, not a concatenation. Token₁ covers the data file (ASiC-S) or the manifest (ASiC-E).
- **The bytes hashed are exactly what `AsicService` writes into the `.tst` entry**, i.e. `token.AsSignedCms().Encode()` from [`timestamping.md`](timestamping.md). Change that encoding and every existing chain breaks.
- **Renewal appends with `ZipArchiveMode.Update`, never by rebuilding the ZIP.** `AddTimestampToContainer` copies the container bytes into a `MemoryStream` and adds one entry, so every previously timestamped byte — including the manifest and the `mimetype` entry's position — stays identical. Rebuilding would re-serialize entries and invalidate every existing token. Asserted by `RenewAsync_ShouldPreserveOriginalContainerContents` and `RenewAsync_PreservesMimetypeFirst`.
- **`TimestampChain` is null for a single-token container**, populated only at 2+ tokens. Deliberate backward compatibility — do not "helpfully" emit a one-element chain.
- **A link's `IsValid` means signature valid *and* hash matched.** An undecodable token still produces a link, with `Timestamp = default` and `IsValid = false`, so the chain never has holes.
- **Naming: `timestamp.tst` → `timestamp-002.tst` → `timestamp-003.tst`.** `GetNextTimestampEntryName` takes the highest parsed sequence number and adds one, treating a lone `timestamp.tst` as number 1. Three-digit, invariant culture.
- **Chain order comes from the parsed sequence number, never from the entry name.** `GetTimestampEntriesInChainOrder` is the single ordering used by `RenewAsync` and both verification paths; `GetTimestampSequence` maps `timestamp.tst` → 1 and `timestamp-NNN.tst` → N, with unrecognized names sorting last by name so the order stays total. **Sorting by name inverts the chain** — `-` is `0x2D` and `.` is `0x2E`, so `timestamp-002.tst` would precede `timestamp.tst`. That was a real defect (fixed 2026-07-31): it made every renewed container fail verification, reported an archive timestamp as the original instant, and caused the 2nd+ renewal to re-stamp the original and fork instead of chaining. Never reintroduce a name-based sort here.
- **Renewal hashes with the *current* `options.HashAlgorithm`**, so a chain may legitimately mix algorithms across links — that is the point of renewing when an algorithm weakens. Verification reads each token's own OID, so mixed chains verify correctly.
- **`RenewAsync` refuses a container with no token** (`InvalidAsicContainerException`) — there is nothing to chain from.

## Key files

| File | Role |
|---|---|
| [`src/AsicSharp/Services/AsicService.cs`](../src/AsicSharp/Services/AsicService.cs) | `RenewAsync` (×3 overloads), `GetTimestampEntriesInChainOrder`, `GetTimestampSequence`, `GetNextTimestampEntryName`, `AddTimestampToContainer`, and the chain loop inside `Verify`/`VerifyExtended` |
| [`src/AsicSharp/Models/AsicResults.cs`](../src/AsicSharp/Models/AsicResults.cs) | `TimestampChainEntry`, `AsicVerifyResult.TimestampChain` |
| [`src/AsicSharp/Services/AsicConstants.cs`](../src/AsicSharp/Services/AsicConstants.cs) | `ArchiveTimestampPrefix`, `TimestampExtension`, `TimestampEntryPath` |
| [`src/AsicSharp.Cli/Program.cs`](../src/AsicSharp.Cli/Program.cs) | `renew` — rewrites the container **in place**, and prints the chain under `verify -v` |

## Gotchas

- **The chain loop is duplicated between `Verify` and `VerifyExtended`**, differing only in the seed bytes (data file vs. manifest) and two step labels. Fix one, fix the other — ordering is now hoisted into `GetTimestampEntriesInChainOrder`, but everything else in the loop is still copied.
- **`asicts renew` overwrites the input file.** `RenewFileAsync` reads, then `File.WriteAllBytes` to the same path. No backup, no `--output`. A failed TSA call leaves the original intact only because the write happens after the call returns.
- **`AsicCreateResult.DataHash` from a renewal is the hash of the previous *token*, not of the data.** Same property, different subject — the CLI labels it "Token hash" for exactly this reason.
- **Containers grow by one entry per renewal, forever.** Small (~2–4 KB each) and tracked as D-4 in [`STRIDE.md`](../STRIDE.md), but there is no pruning and no upper bound.
- **A renewed ASiC-S container's `Extract` still works**, because extraction ignores `META-INF` entirely — renewal never touches the data file.

## Executable references

- [`tests/AsicSharp.Tests/AsicServiceTests.cs`](../tests/AsicSharp.Tests/AsicServiceTests.cs) — 11 `Renew*`/chain facts, **the authority on append semantics, naming and chain order**: `RenewAsync_ShouldPreserveOriginalContainerContents` and `_PreservesMimetypeFirst` settle byte preservation; `_MultipleRenewals_ShouldIncrementEntryNames` settles the `-002`/`-003` sequence; `_WithNoTimestamp_ShouldThrow` settles the refusal; `Verify_SingleTimestamp_TimestampChainShouldBeNull` settles the null-chain rule.
- **Chain order is pinned by three facts added with the ordering fix:** `Verify_RenewedContainer_ChainShouldStartWithTheOriginalTimestamp` and its `_RenewedAsicEContainer_` twin assert `EntryName` order on both verification paths, and `RenewAsync_SecondRenewal_ShouldCoverTheNewestToken` asserts the renewal hashes `timestamp-002.tst` rather than the original. All three fail against a name-based sort. Note that `Verify_RenewedContainer_TimestampChainShouldBePopulated` asserts only `Order`, which is assigned by loop position and therefore tautological — it is *not* an ordering test.
- [`tests/AsicSharp.Tests/IntegrationTests.cs`](../tests/AsicSharp.Tests/IntegrationTests.cs) — `AsicService_RenewTwice_ChainShouldVerifyAndKeepTheOriginalInstant` is the **only** test that exercises real chain-link cryptography (three genuine TSA tokens, every link verified, original instant preserved). Unit tests cannot reach it: their non-DER placeholder token fails `TryDecode` before any hash comparison. CI runs this job `continue-on-error: true`, so **its failure does not break the build** — treat a break here as significant anyway.

## Links

- Glossary: [`UBIQUITOUS_LANGUAGE.md`](../UBIQUITOUS_LANGUAGE.md) § Renewal — and its flagged ambiguity for *entry* (`TimestampChainEntry.EntryName` is a ZIP path, not a chain index)
- Threat model: [`STRIDE.md`](../STRIDE.md) — T-7 (chain tampering), D-4 (unbounded growth)
- Related domains: [`verification.md`](verification.md) (boundary: shape vs. walk, shared code) · [`timestamping.md`](timestamping.md) (boundary: renewal is one more call into it) · [`container.md`](container.md) (boundary: renewal must not disturb the layout)
- Priming skill: [`.claude/skills/renewal/SKILL.md`](../.claude/skills/renewal/SKILL.md)
