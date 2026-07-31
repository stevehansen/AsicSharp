# Container

The ASiC container itself — what a conformant ZIP looks like, how ASiC-S and ASiC-E differ, and how files get in and out of one.

**Status:** current as of the domain-priming pass (2026-07-31) · **Governing issues:** [#3](https://github.com/stevehansen/AsicSharp/issues/3) (ASiC-E support), [#7](https://github.com/stevehansen/AsicSharp/issues/7) (`GetContainerType`), [#1](https://github.com/stevehansen/AsicSharp/issues/1) (Zip Slip), [#9](https://github.com/stevehansen/AsicSharp/issues/9) (open — `FileNames` on the create result)
**Priming skill:** [`.claude/skills/container/SKILL.md`](../.claude/skills/container/SKILL.md)

## What it is

Everything about the container as a *structure*: the ETSI-mandated ZIP layout, the two profiles (ASiC-S = one data file, ASiC-E = many + a manifest), building the `ASiCManifest.xml`, reading files back out, and probing an unknown byte array for its format. It also owns the optional CAdES `signature.p7s` entry, because what that signature covers is a per-profile structural rule.

It is **not** the TSA conversation (→ [`timestamping.md`](timestamping.md)), **not** the step-by-step integrity verdict (→ [`verification.md`](verification.md)), and **not** the archive-timestamp chain (→ [`renewal.md`](renewal.md)).

## Core entities & relationships

```
Container (ZIP)
├── mimetype                      # first entry, uncompressed — declares the profile
├── <data file>…                  # one (ASiC-S) or many (ASiC-E)
└── META-INF/
    ├── ASiCManifest.xml          # ASiC-E only — one DataObjectReference per data file
    ├── timestamp.tst             # the original timestamp token
    ├── timestamp-NNN.tst         # archive timestamps, added by renewal
    ├── README.txt                # human-readable explainer
    └── signature.p7s             # optional detached CAdES signature
```

In ASiC-S the token covers the data file directly. In ASiC-E it covers **the manifest**, and the manifest carries a hash per data file — so a data file's proof of existence runs through the manifest, never straight to the token.

Entry names, MIME types and the ETSI namespace are all in [`src/AsicSharp/Services/AsicConstants.cs`](../src/AsicSharp/Services/AsicConstants.cs); don't re-spell them as literals.

## Invariants & rules

- **`mimetype` is the first ZIP entry, stored `CompressionLevel.NoCompression`, UTF-8 without BOM.** ETSI EN 319 162-1 requires it so consumers can sniff the profile at a fixed offset without inflating anything. Owned by `BuildContainer` / `BuildExtendedContainer` in [`AsicService.cs`](../src/AsicSharp/Services/AsicService.cs). **Enforced on write only** — this library's own `Verify` fetches the entry by name and never checks its position or compression, so a non-conformant container built elsewhere still passes here.
- **An ASiC-E timestamp covers the manifest, never a data file.** Change how `BuildAsicManifest` serializes (encoding, declaration, attribute order, element order) and you change the bytes that were timestamped — every previously issued container's manifest hash still has to reproduce, so treat the serialization as frozen.
- **The digest algorithm crosses the manifest boundary as an XML URI**, mapped by `HashAlgorithmToXmlUri` / `XmlUriToHashAlgorithmName`. Both mappings are closed sets that **throw** on anything unrecognized — deliberately, so an unknown algorithm can never be silently treated as agreement.
- **A data file may not be named `mimetype`, may not be exactly `META-INF`, and may not contain a path separator.** `ValidateFileName`, create-side only. `META-INF`-*prefixed* names like `META-INFO.txt` are legal and asserted to be.
- **ASiC-E rejects duplicate file names case-insensitively** before any hashing happens — the manifest keys on name, so two entries differing only in case would produce an ambiguous reference.
- **Extraction sanitizes every entry name through `Path.GetFileName`.** Zip Slip defence, fixed in [#1](https://github.com/stevehansen/AsicSharp/issues/1); an entry that sanitizes to empty is rejected outright. Applies to `Extract` and `ExtractAll`.
- **`MaxFileSize` guards data files and data entries only.** Enforced on create (`ValidateFileSize`) and per entry on read (`ValidateEntrySize`). Metadata entries — mimetype, manifest, tokens, signature — are read unbounded; that residual risk is tracked in [`STRIDE.md`](../STRIDE.md).
- **The CAdES signature covers different bytes per profile:** the data file in ASiC-S, the **manifest** in ASiC-E. Same entry name, same code path, different subject — `CreateCmsSignature` is handed `data` in one and `manifestBytes` in the other.
- **`GetContainerType` never throws.** Unreadable bytes, absent mimetype, unrecognized mimetype all return `AsicContainerType.None`. It is a probe, not a validation.
- **`META-INF/README.txt` is a const string in `AsicService`** and tests assert its content. Editing it is a deliberate, test-breaking act; keep the two variants (simple/extended) in step with what the container actually holds.

## Key files

| File | Role |
|---|---|
| [`src/AsicSharp/Services/AsicService.cs`](../src/AsicSharp/Services/AsicService.cs) | `BuildContainer`, `BuildExtendedContainer`, `BuildAsicManifest`, `FindDataEntr*`, `Extract`, `ExtractAll`, `GetContainerType`, `ValidateFileName`, `ValidateEntrySize`, the README consts |
| [`src/AsicSharp/Services/AsicConstants.cs`](../src/AsicSharp/Services/AsicConstants.cs) | Entry names, MIME types, extensions, ETSI namespace |
| [`src/AsicSharp/Models/AsicContainerType.cs`](../src/AsicSharp/Models/AsicContainerType.cs) | `None` / `Simple` / `Extended` |
| [`src/AsicSharp/Configuration/AsicTimestampOptions.cs`](../src/AsicSharp/Configuration/AsicTimestampOptions.cs) | `MaxFileSize`, `SigningCertificate`, `HashAlgorithm` |
| [`src/AsicSharp.Cli/Program.cs`](../src/AsicSharp.Cli/Program.cs) | `stamp` picks the profile purely from argument count; `extract` writes into a directory |

## Gotchas

- **`Extract` on an ASiC-E container silently returns only the first data file.** `FindDataEntry` takes the first non-metadata entry in ZIP order. Asserted by `Extract_OnAsicEContainer_ShouldReturnFirstDataFile` — it's intended, not a bug, but it's a trap. Use `ExtractAll` for anything that might be ASiC-E.
- **`ExtractAll` walks ZIP entries, not the manifest.** It returns data files the manifest never listed — and since verification only walks manifest references, such a file is never covered by the proof of existence and never reported as a problem. A caller that verifies, sees `IsValid`, then `ExtractAll`s can hand out unstamped bytes as though they were timestamped. Open — [`STRIDE.md`](../STRIDE.md) T-9, [#25](https://github.com/stevehansen/AsicSharp/issues/25); also see [`verification.md`](verification.md).
- **Nothing enforces "exactly one data file" for ASiC-S on read.** A ZIP with three data files and an `asic-s` mimetype verifies against whichever one comes first.
- **The `.asics` / `.asice` extension is a CLI default only.** No code reads it; format detection is mimetype-then-manifest. Don't infer the profile from a path.
- **A manifest present with no `mimetype` at all reports `Extended`** (asserted). Manifest presence outranks a missing or wrong mimetype — for both `GetContainerType` and `Verify`'s routing.
- **ASiC-E data files are stored under their raw name and read back under the raw manifest URI.** `AsicVerifyResult.FileNames` is unsanitized manifest text on the ASiC-E path, while the ASiC-S path passes it through `Path.GetFileName`. Sanitize before you touch the filesystem — the CLI's `extract` goes through `ExtractAll`, which does; a caller reading `FileNames` directly gets no such help.
- **`AsicCreateResult.DataHash` means different things per profile:** the data file's hash for ASiC-S, the *manifest's* hash for ASiC-E. Same property, different subject ([#9](https://github.com/stevehansen/AsicSharp/issues/9) tracks the related `FileNames` gap).

## Executable references

- [`tests/AsicSharp.Tests/AsicServiceTests.cs`](../tests/AsicSharp.Tests/AsicServiceTests.cs) — 64 facts, **the authority on container structure**: mimetype ordering and compression, README presence, manifest digests matching file content (`CreateExtendedAsync_ManifestDigestsShouldMatchFileContent`), name validation, `MaxFileSize` on every entry point, all seven `GetContainerType_*` cases, and Zip Slip sanitization.
- [`tests/AsicSharp.Tests/IntegrationTests.cs`](../tests/AsicSharp.Tests/IntegrationTests.cs) — 5 facts, `Category=Integration`, real TSA. The only place a container round-trips through a genuine token.
- **Coverage limit that matters here:** unit tests substitute `ITsaClient` and feed a non-DER placeholder token (`CreateFakeTimestampToken` returns plain UTF-8), so nothing in the 64 facts decodes a token. Structure and hashing are well pinned; anything downstream of `Rfc3161TimestampToken.TryDecode` is not.

## Links

- Glossary: [`UBIQUITOUS_LANGUAGE.md`](../UBIQUITOUS_LANGUAGE.md) § Container and contents, § Signing (optional)
- Threat model: [`STRIDE.md`](../STRIDE.md) — T-1/E-1 (Zip Slip), T-5 (XXE), T-6 (manifest digest), T-9 (ASiC-E completeness, open), unbounded metadata entries
- Related domains: [`timestamping.md`](timestamping.md) (boundary: this domain stores the token, that one obtains it) · [`verification.md`](verification.md) (boundary: this domain defines the layout, that one judges it) · [`renewal.md`](renewal.md) (boundary: renewal adds `.tst` entries without rebuilding the ZIP)
- Priming skill: [`.claude/skills/container/SKILL.md`](../.claude/skills/container/SKILL.md)
