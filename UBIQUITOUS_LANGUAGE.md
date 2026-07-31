# Ubiquitous Language

The agreed vocabulary for ASiC containers and RFC 3161 timestamping. Use these terms in code, XML doc comments, CLI output, and README prose.

## Container and contents

| Term                   | Definition                                                                                                        | Aliases to avoid                              |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| **ASiC Container**     | A ZIP package that binds data files to evidence of when they existed, per ETSI EN 319 162                          | archive, package, bundle, ZIP, `.asics` file  |
| **ASiC-S**             | The container profile holding exactly one data file, timestamped directly                                          | Simple container, single container, basic     |
| **ASiC-E**             | The container profile holding one or more data files, timestamped indirectly through an ASiCManifest               | Extended container, multi-file container      |
| **Data File**          | A payload file the user asked to be timestamped, as opposed to container metadata                                  | payload, content, original data, user file    |
| **ASiCManifest**       | The XML document listing every data file with its hash, and the sole thing an ASiC-E timestamp covers              | manifest file, index, catalogue               |
| **Manifest Reference** | One data file's entry in the ASiCManifest, carrying its name, MIME type and hash                                   | manifest entry, manifest row, data object     |
| **ZIP Entry**          | A named byte stream physically stored in the container, whether data file or metadata                              | container entry, file, member                 |

## Timestamping

| Term                        | Definition                                                                                                   | Aliases to avoid                                  |
| --------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **Proof of Existence**      | The assertion this product sells: that specific bytes existed no later than a stated moment                     | proof of authorship, notarization, certification  |
| **Timestamp Authority**     | The external RFC 3161 service that issues timestamp tokens; abbreviated **TSA**                                 | time server, TSA server, authority, notary        |
| **Timestamp Token**         | The DER-encoded, TSA-signed structure asserting that a given hash existed at a given moment                     | timestamp, token file, `.tst`, stamp              |
| **Timestamp Instant**       | The UTC moment a timestamp token asserts (RFC 3161 `genTime`)                                                   | timestamp, date, time, issued-at                  |
| **Timestamping**            | The act of hashing input, obtaining a timestamp token for that hash, and storing it in a container              | stamping, signing, sealing                        |
| **Hash**                    | The fixed-length fingerprint of a byte sequence that a timestamp token or manifest reference commits to         | digest, checksum, fingerprint, signature          |
| **Nonce**                   | A random value sent with a timestamp request and echoed in the response, proving the response is not a replay   | salt, random, token id                            |
| **TSA Certificate**         | The X.509 certificate whose key signed a timestamp token                                                        | signer certificate, signing certificate, cert     |

## Signing (optional)

| Term                     | Definition                                                                                                    | Aliases to avoid                             |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| **CAdES Signature**      | An optional detached CMS signature over the data file, asserting *who* vouches for it rather than *when* it existed | signature, CMS, p7s, seal                    |
| **Signing Certificate**  | The X.509 certificate whose key produced a CAdES signature                                                        | signer certificate, TSA certificate, cert    |

## Verification

| Term                        | Definition                                                                                                        | Aliases to avoid                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| **Verification**            | The non-throwing inspection of a container that reports every check it performed                                       | validation, checking, authentication               |
| **Verification Step**       | One named, individually pass/fail check contributing to a verification                                                 | check, test, rule, assertion                       |
| **Cryptographic Validity**  | The verdict that every verification step passed — integrity only, saying nothing about whether the TSA is trusted      | validity, valid, trusted, authentic, legally valid |
| **Trust Decision**          | The out-of-band judgement that a given TSA certificate is acceptable; deliberately left to the caller                  | trust check, chain validation, trusted             |

## Renewal

| Term                     | Definition                                                                                                    | Aliases to avoid                                 |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| **Renewal**              | Extending a container's proof of existence before its newest token's algorithms or certificate weaken               | re-stamping, refresh, re-signing, extension      |
| **Original Timestamp**   | The first timestamp token in a container — the one that establishes when the data itself existed                    | first stamp, root timestamp, base timestamp      |
| **Archive Timestamp**    | A timestamp token added by renewal, covering the raw bytes of the token before it                                   | renewal timestamp, new timestamp, re-stamp       |
| **Timestamp Chain**      | The ordered sequence original-then-archive tokens form, each link covering its predecessor                          | chain of trust, certificate chain, history       |
| **Chain Link**           | One token's position in a timestamp chain together with the verdict on whether it covers its predecessor            | chain entry, chain item, link entry              |

## Relationships

- An **ASiC-S** container holds exactly one **Data File**; an **ASiC-E** container holds one or more.
- An **ASiC-E** container has exactly one **ASiCManifest**, holding exactly one **Manifest Reference** per **Data File**.
- The **Original Timestamp** covers the **Data File** in ASiC-S, but the **ASiCManifest** in ASiC-E — never an ASiC-E data file directly.
- A container holds exactly one **Original Timestamp** and zero or more **Archive Timestamps**; together they form a **Timestamp Chain** of two or more links.
- Each **Archive Timestamp** covers the raw bytes of exactly one preceding **Timestamp Token**.
- A **Timestamp Token** carries at most one **TSA Certificate**; a container carries at most one **CAdES Signature**, and therefore at most one **Signing Certificate**.
- **Verification** yields one **Verification Step** per check; **Cryptographic Validity** holds only when every one of them passed.
- The **Timestamp Instant** reported for a container is always the **Original Timestamp**'s — renewal extends the proof, it never moves it forward.

## Example dialogue

> **Dev:** "For ASiC-E, do I get one **Timestamp Token** per **Data File**?"

> **Domain expert:** "No — one token for the whole container. It covers the **ASiCManifest**, and the manifest holds a **Manifest Reference** with a **Hash** per data file. So a data file's proof runs through the manifest, not straight to the token."

> **Dev:** "Then if someone swaps a data file, which check catches it?"

> **Domain expert:** "A **Verification Step** per manifest reference: recompute the hash, compare it to the reference. The token itself still verifies fine — its own hash of the manifest is untouched — so the failure surfaces at the manifest layer, not the token layer."

> **Dev:** "And when verification comes back with **Cryptographic Validity**, can I tell the user the container is trustworthy?"

> **Domain expert:** "You can tell them nothing was altered. Whether the **Timestamp Authority** that issued it is one you accept is a **Trust Decision** — we hand you the **TSA Certificate** and stay out of it."

> **Dev:** "Last one: after **Renewal**, does the **Timestamp Instant** I show move to the **Archive Timestamp**'s time?"

> **Domain expert:** "Never. The archive timestamp only proves the earlier token existed intact at a later date — the **Original Timestamp** is still the proof of when the data existed, so that's the instant you display."

## Flagged ambiguities

- **"timestamp"** collapsed three distinct things: the **Timestamp Instant** (a moment), the **Timestamp Token** (a signed artefact), and **Timestamping** (an act). Name the artefact a token whenever bytes are involved; reserve the bare word for prose where the distinction genuinely doesn't matter.
- **"entry"** was used for a **ZIP Entry**, a **Manifest Reference**, and a **Chain Link** — three unrelated concepts. Note that `TimestampChainEntry.EntryName` is a *ZIP entry path*, so a single type mixes two of the three senses; don't add a third.
- **"valid"** conflated **Cryptographic Validity** with trustworthiness. Verification never builds an `X509Chain`, so a self-issued TSA yields a fully "valid" container. Say "unaltered" or "cryptographically valid" in user-facing text, and keep the **Trust Decision** explicitly the caller's.
- **"signature"** means both the TSA's signature *inside* a timestamp token and the optional **CAdES Signature** *beside* the data file. They answer different questions — *when* versus *who* — and only the second is optional. Never write bare "signature" without saying which.
- **"certificate"** likewise splits into **TSA Certificate** and **Signing Certificate**; both are `X509Certificate2` and both appear on the same verification result, so an unqualified "cert" is always wrong.
- **"hash" vs "digest"** — the same concept under two names, because the ASiCManifest XML uses ETSI-mandated `DigestMethod`/`DigestValue` element names. Canonical term is **Hash**, matching the public API (`DataHash`, `HashAlgorithm`); "digest" is acceptable only when quoting those XML element names.
