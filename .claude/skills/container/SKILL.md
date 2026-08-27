---
name: container
description: Prime on the AsicSharp Container domain before working on it — the ETSI ZIP layout, ASiC-S vs ASiC-E, the mimetype and META-INF entries, ASiCManifest construction, extraction, and GetContainerType format probing. Use when the task touches container structure, BuildContainer/BuildExtendedContainer/BuildAsicManifest, Extract/ExtractAll, entry names, MaxFileSize, Zip Slip, the CAdES signature entry, or the stamp/extract CLI commands. Not for the TSA request itself (see timestamping), the pass/fail verdict (see verification), or archive timestamps (see renewal).
---

# Container domain — priming

**Canonical spec:** [`docs/container.md`](../../../docs/container.md) — read it for the full invariant list, key files and gotchas. Terms of record: [`UBIQUITOUS_LANGUAGE.md`](../../../UBIQUITOUS_LANGUAGE.md) § Container and contents. Governing issues: #3, #7, #1.

The container as a *structure*: ETSI ZIP layout, the two profiles, manifest construction, getting files back out, format probing. Not the TSA call, not the verdict, not the chain.

## Core invariants (get these right)

- **`mimetype` first, `CompressionLevel.NoCompression`, UTF-8 without BOM** — ETSI requirement, enforced on write only; our own `Verify` doesn't check position or compression.
- **ASiC-E timestamps the manifest, never a data file.** `BuildAsicManifest`'s serialization is effectively frozen — changing encoding, declaration or element order changes bytes that were already timestamped.
- **`ValidateFileName` rejects path separators, `mimetype`, and exactly `META-INF`** — but only on create. `META-INF`-*prefixed* names are legal.
- **Extraction sanitizes through `Path.GetFileName`** (Zip Slip, #1); empty result is rejected.
- **`MaxFileSize` guards data entries only** — metadata entries are read unbounded (residual risk in `STRIDE.md`).
- **The CAdES signature covers the data file in ASiC-S but the manifest in ASiC-E** — same entry, different subject.
- **`GetContainerType` never throws** — unreadable or unrecognized returns `None`.
- Never re-spell entry names or MIME types as literals; they live in `AsicConstants`.

## Key files / reuse

- `src/AsicSharp/Services/AsicService.cs` — all `Build*`, `Find*`, `Extract*`, `GetContainerType`, name/size validation, the README consts.
- `src/AsicSharp/Services/AsicConstants.cs` — entry names, MIME types, extensions, ETSI namespace.
- `src/AsicSharp/Models/AsicContainerType.cs` · `Configuration/AsicTimestampOptions.cs` (`MaxFileSize`, `SigningCertificate`).

## Gotchas

- **`Extract` on ASiC-E returns only the first *manifest-referenced* data file** (asserted, intended). Use `ExtractAll` when the profile is unknown.
- **`CreateToStreamAsync` / `ExtractToStreamAsync` are the genuinely streaming ASiC-S paths** and return `AsicStreamCreateResult` (no `ContainerBytes`). Both **throw on a non-seekable stream** — create reads the payload twice, and `ZipArchive` would silently buffer a forward-only read stream. `CreateToStreamAsync` throws `NotSupportedException` if a `SigningCertificate` is set. ASiC-E create and renewal are `byte[]`-only.
- **All container writers share `WriteMimeTypeEntry`/`WriteBytesEntry`/`WriteTextEntry`** — put entry-name or compression changes there, not in one builder.
- **`Extract` and `ExtractAll` filter ASiC-E through the manifest** (shared `FindCoveredDataEntries`) — only referenced files come back, so neither can hand out uncovered bytes, and `Extract` no longer depends on attacker-chosen ZIP order. Falls back to every data entry when the manifest is unparseable; ASiC-S is unfiltered (no manifest). See `UnreferencedFileNames` on the verify side.
- **Nothing enforces one data file for ASiC-S on read.**
- **`.asics`/`.asice` is a CLI default only** — no code reads the extension; detection is mimetype-then-manifest, and manifest presence wins.
- **`AsicCreateResult.DataHash` is the data's hash for ASiC-S but the manifest's for ASiC-E.** `FileHashes` is per-file on both, so prefer it when you mean a file's hash; `FileNames`/`FileHashes` are null after a renewal.
- `META-INF/README.txt` content is asserted by tests — editing it is deliberately test-breaking.

**Same-PR rule:** behavior changes here update `docs/container.md` in the same PR; load-bearing invariant changes update this file too.
