---
name: renewal
description: Prime on the AsicSharp Renewal domain before working on it — archive timestamps per ETSI EN 319 162-1 §5.4, RenewAsync, the timestamp chain and TimestampChainEntry, timestamp-NNN.tst naming, and byte-preserving in-place append. Use when the task touches renewing or re-stamping a container, chain ordering or chain-link validity, GetNextTimestampEntryName, AddTimestampToContainer, long-term archival, or the renew CLI command. Not for the first timestamp of a new container (see container and timestamping) or the general step model (see verification).
---

# Renewal domain — priming

**Canonical spec:** [`docs/renewal.md`](../../../docs/renewal.md) — read it for the full invariant list, the defect write-up, key files and gotchas. Terms of record: [`UBIQUITOUS_LANGUAGE.md`](../../../UBIQUITOUS_LANGUAGE.md) § Renewal. Governing issue: #2.

Adding an archive timestamp over the newest token so a proof survives algorithm and certificate ageing. This domain owns the chain's **shape**; the chain **walk** is shared code inside `Verify`/`VerifyExtended` (see [`verification`](../verification/SKILL.md)).

## Core invariants (get these right)

- **Chain order comes from the parsed sequence number, never the entry name.** Use `GetTimestampEntriesInChainOrder`. A name sort inverts the chain — `-` (0x2D) sorts before `.` (0x2E), so `timestamp-002.tst` would precede `timestamp.tst`. That was a real defect (fixed 2026-07-31): renewed containers all failed verification and the 2nd+ renewal forked off the original. Three unit tests plus one integration test now pin it; never reintroduce a name-based sort.
- **`Timestamp` / `TsaCertificate` / `HashAlgorithm` always come from token₁.** Renewal extends a proof, never moves it forward.
- **Each archive timestamp covers the raw bytes of exactly one preceding token**; token₁ covers the data file (ASiC-S) or the manifest (ASiC-E).
- **Append with `ZipArchiveMode.Update`, never rebuild the ZIP** — previously timestamped bytes must stay byte-identical (asserted).
- **`TimestampChain` is null below 2 tokens** — deliberate backward compatibility, don't emit a one-element chain.
- **A link's `IsValid` = signature valid AND hash matched;** an undecodable token still yields a link so the chain has no holes.
- **Naming: `timestamp.tst` → `timestamp-002.tst` → `timestamp-003.tst`**, three digits, invariant culture, max+1.
- **A chain may mix hash algorithms** — renewal uses current options, verification reads each token's own OID. That's the point.

## Key files / reuse

- `src/AsicSharp/Services/AsicService.cs` — `RenewAsync` (×3), `GetTimestampEntriesInChainOrder`, `GetTimestampSequence`, `GetNextTimestampEntryName`, `AddTimestampToContainer`, and **the chain loop duplicated in `Verify` and `VerifyExtended`** (differing only in seed bytes and two labels; only the ordering is shared).
- `src/AsicSharp/Models/AsicResults.cs` — `TimestampChainEntry`. · `AsicConstants.cs` — `ArchiveTimestampPrefix`.

## Gotchas

- **`asicts renew` overwrites the input file in place** — no backup, no `--output`.
- **A renewal's `AsicCreateResult.DataHash` is the previous *token's* hash**, not the data's (CLI labels it "Token hash"); `FileNames`/`FileHashes` are null — renewal touches no data file.
- **Containers grow one entry per renewal, unbounded** (D-4 in `STRIDE.md`).
- **`Verify_RenewedContainer_TimestampChainShouldBePopulated` is not an ordering test** — it asserts `Order`, which is assigned by loop position and so holds for any ordering. Assert `EntryName` instead.
- **Real chain cryptography lives in one integration test** (`AsicService_RenewTwice_…`), and CI lets that job fail. Run it deliberately after touching chain code.

**Same-PR rule:** behavior changes here update `docs/renewal.md` in the same PR; load-bearing invariant changes update this file too.
