# AsicSharp — documentation

This folder holds the **per-domain documentation layer**: one deep living spec per business domain, each paired with a thin agent-priming skill under `.claude/skills/`. The specs capture *current state* — entities, invariants, key files, gotchas — rather than any single change. Build commands, solution structure and repo conventions stay in [`../CLAUDE.md`](../CLAUDE.md); the canonical vocabulary stays in [`../UBIQUITOUS_LANGUAGE.md`](../UBIQUITOUS_LANGUAGE.md).

## Domain index

| Domain | Living spec | Priming skill | Governing issues |
|---|---|---|---|
| **Container** — ETSI ZIP layout, ASiC-S vs ASiC-E, manifest construction, extraction, format probing | [`container.md`](container.md) | [`.claude/skills/container/SKILL.md`](../.claude/skills/container/SKILL.md) | [#3](https://github.com/stevehansen/AsicSharp/issues/3), [#7](https://github.com/stevehansen/AsicSharp/issues/7), [#1](https://github.com/stevehansen/AsicSharp/issues/1), [#9](https://github.com/stevehansen/AsicSharp/issues/9) |
| **Timestamping** — RFC 3161 client, TSA fallback, nonce and signer-cert policy | [`timestamping.md`](timestamping.md) | [`.claude/skills/timestamping/SKILL.md`](../.claude/skills/timestamping/SKILL.md) | — (foundational) |
| **Verification** — non-throwing step model, integrity-only verdict, trust deliberately excluded | [`verification.md`](verification.md) | [`.claude/skills/verification/SKILL.md`](../.claude/skills/verification/SKILL.md) | [#5](https://github.com/stevehansen/AsicSharp/issues/5) |
| **Renewal** — archive timestamps, chain shape and naming, byte-preserving append | [`renewal.md`](renewal.md) | [`.claude/skills/renewal/SKILL.md`](../.claude/skills/renewal/SKILL.md) | [#2](https://github.com/stevehansen/AsicSharp/issues/2) |

The four domains map 1:1 onto the sections of `UBIQUITOUS_LANGUAGE.md`, which is the check that the boundaries are real rather than invented. The optional CAdES signature is documented inside **Container** (what it covers is a per-profile structural rule) with the verification step described in **Verification** — it is too thin to be a domain of its own.

Two boundaries are worth knowing because the code doesn't make them obvious:

- **Verification vs. Renewal** — renewal owns the chain's *shape* (order, naming, what covers what); verification owns the *walk*. The walk physically lives inside `Verify`/`VerifyExtended`, so a change to ordering touches both specs.
- **Container vs. Verification** — container builds the ASiCManifest, verification checks the digests in it. The manifest's serialization is frozen by the first, relied on by the second.

## Other references

- [`../UBIQUITOUS_LANGUAGE.md`](../UBIQUITOUS_LANGUAGE.md) — canonical glossary; specs link *down* into its sections
- [`../CLAUDE.md`](../CLAUDE.md) — build, solution structure, conventions, doc-sync rules
- [`../STRIDE.md`](../STRIDE.md) — threat model; specs cross-reference its findings by ID
- [`../README.md`](../README.md) — user-facing library and CLI documentation

## Adding a new domain

Each domain gets a hybrid pair, split by audience: a deep human-facing living spec at `docs/<domain>.md`, and a thin agent-facing priming skill at `.claude/skills/<domain>/SKILL.md` that links *down* to the spec. Lowercase single-word filenames.

**Living-spec sections:** title + purpose · status / governing issues · what it is (including what it is *not*) · core entities & relationships · invariants & rules · key files · gotchas · executable references · links.

**Priming-skill shape:** frontmatter (`name` matching the directory, `description` naming concrete entities, trigger phrases, and an explicit `Not for X` exclusion) → one line on what it is plus a link to the spec → get-these-right invariants → key files → gotchas.

**Write specs that point at code, not specs that transcribe it.** No property lists, no endpoint tables, no thresholds copied out of source — cite the file and let the reader open it. The test for any line: *if this changes, will the code change too?* If yes, link instead of writing it.

**Give every spec an Executable references section** naming the test files that pin its invariants, which is the authority for which rule, and — plainly — what has **no** test. When prose and a test disagree, the test wins; fix the prose in the same pass.

**Same-PR sync rule:** any change to a domain's behavior updates its living spec in the same PR as the code change — never as a follow-up. If it alters a load-bearing invariant, update the priming skill too. A domain-behavior diff with no matching spec edit is incomplete.

**The iron rule: the skill links, never duplicates.** If content is more than a compact essential, it belongs in the spec and the skill points at it.

Auditing and adding domains is handled by the user-level `domain-priming` skill.
