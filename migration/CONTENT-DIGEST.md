# Content digest contract (schema-1 pack)

Status: defined 2026-11-16 on `claude/go-migration`; implemented and tested in Go
(`go/internal/content/digest.go`, `digest_test.go`). The Python reference is unchanged: it already produces
the release digest defined here, and this document states that value over the pack alone so that any
runtime can recompute it. Closes the open point of contract C11 and of Culvert work item #16.

A pack is the JSON document `tools/export_content.py` writes (`migration/fixtures/content.json`, embedded in
the Go module as `go/internal/content/pack.json`). Two digests are defined over it. They answer different
questions and neither replaces the other.

| digest | answers | size | where it appears |
|---|---|---|---|
| release digest | which content release classified this record | 16 hex digits (64 bits) | `release.digest` in the pack; `content.digest` on every session record and summary |
| pack digest | are these exactly the pack bytes' contents I pinned | 64 hex digits (SHA-256) | computed by the consumer (`content.Pack.Digests.Pack`); not stored in the pack |

## Canonical encoding CJ1

CJ1 encodes a JSON value built only from objects, arrays, strings, integers, `true`, `false` and `null`:

- an object is `{` + members + `}`; members are ordered by key, ascending by Unicode code point (the same
  order as the keys' UTF-8 bytes), separated by `, ` (comma, space); a member is the key as a string, `: `
  (colon, space), the value;
- an array is `[` + items in their order, separated by `, ` + `]`; empty containers are `{}` and `[]`;
- a string is `"` + characters + `"`, in ASCII: `"` and `\` are written `\"` and `\\`; line feed, carriage
  return, tab, backspace and form feed are written `\n`, `\r`, `\t`, `\b`, `\f`; every other character outside
  U+0020..U+007E is written `\uXXXX` with four lowercase hexadecimal digits, a character above U+FFFF as its
  UTF-16 surrogate pair (two `\uXXXX`); `/` is not escaped;
- an integer is its decimal digits with a leading `-` when negative, no leading zeros, no `-0`;
- no other whitespace, no trailing newline; the encoding is ASCII bytes.

This is byte for byte what Python's `json.dumps(value, sort_keys=True)` writes with its defaults.

A document is **outside CJ1 and refused** when it has: a repeated key in one object; a number with a
fraction or an exponent, `-0`, or more than 16 digits; a string that is not valid Unicode (an unpaired
surrogate escape) or that contains U+FFFD; nesting deeper than 16; anything after the document. Schema-1 packs
contain none of these (integers there are risk levels 1..5 and the schema number).

## Release digest (version 1, as the reference computes it)

`H(parts)` is SHA-256 over, for each part in order, the part's CJ1 bytes followed by one zero byte; written
as 64 lowercase hexadecimal digits.

Components (the pack states them in `release.components`; exactly these four keys):

| component | parts | source in the pack |
|---|---|---|
| `host_catalog` | each object of `host_catalog.entries`, whole, in list order | recomputed |
| `application_catalog` | for each object of `applications`, ordered by `name` (code point order): the array `[name, [name, category, subcategory, technology, risk, description, characteristics, standard_ports, secure_ports, implicitly_uses, depends_on, container, aliases]]` | recomputed; an application object must have exactly these 13 fields |
| `risks` | for each key of `risks` in code point order: `[name, [severity, description]]` | recomputed; a risk object must have exactly these 2 fields |
| `families` | the family inventory (family, transports, scope, profile, hint requirement) | **stated only**: a schema-1 pack carries no family inventory, so this value cannot be recomputed from it |

`release.digest` = the first 16 hexadecimal digits of `H([c1, c2, c3, c4])`, where the parts are the four
component values as strings, in code point order of the component names (`application_catalog`, `families`,
`host_catalog`, `risks`).

Not covered by the release digest: `schema`, `vocabulary`, `protocol_names`, `host_catalog.app_domains`,
`host_catalog.web_fronts`, `host_catalog.suffixes`, `release.version`, `release.released`,
`release.reviewed`. The order of the `applications` list is not covered either (the component sorts it); the
order of `host_catalog.entries` is.

## Pack digest (version 1)

    pack digest = SHA-256( "protodetect-content-pack-v1\n" || CJ1(whole pack document) )

written as 64 lowercase hexadecimal digits; the prefix is 28 ASCII bytes ending in one line feed. It covers
every field of the document, including the release block and unknown top-level fields, and does not depend
on the file's whitespace, key order or string escaping. A change of the encoding or of what is hashed gets
a new prefix (`-v2`); the schema number is inside the hashed document.

## What a loader verifies

`content.Parse` (Go; every pack goes through it: the embedded pack, a `--content` file, host-supplied bytes)
refuses a pack when, after the structural validation it already did:

1. the document is outside CJ1;
2. `release.components` is not exactly the four components, each 64 lowercase hex digits;
3. a recomputed component (`host_catalog`, `application_catalog`, `risks`) differs from the stated one;
4. `release.digest` differs from the chain over the four stated components;
5. an application or risk object has a field outside the lists above (it would sit outside every digest but
   the pack digest).

An earlier release run by `--content-version` (`content.EmbeddedRelease`: the release's block and server-name
catalog over the current pack) is checked the same way except in rule 3, where only `host_catalog` is
recomputed: its `application_catalog`, `families` and `risks` are the components the release was published
with (C11, 2026-11-18; `protocol_engine.content._RELEASED_COMPONENTS`), because those tables follow the package
and do not roll back. So the release digest a record pinned to an earlier release carries is reproduced
exactly, while a server-name catalog that no longer matches its release is refused.

It then exposes `Digests{Pack, Release, Components, Recomputed}`. Verification is self-consistency: it
proves the tables are the ones the stated digests describe, not who made the pack. Trust comes from the
consumer comparing `Digests.Pack` with a value it pinned out of band (a build constant, a signed catalog).

## Test vectors

Computed with Python's `json` and `hashlib`, independent of the Go code; asserted in
`go/internal/content/digest_test.go`.

Document (any JSON form of it):

    {"n": 9999999999999999, "b": [1, -2, 0, true, false, null],
     "a": {"z": "", "Z": "q\"\\/\n\t\u0001\u007f", "é": "€ 𝄞", "aa": []}}

| quantity | value |
|---|---|
| CJ1 | `{"a": {"Z": "q\"\\/\n\t\u0001\u007f", "aa": [], "z": "", "\u00e9": "\u20ac \ud834\udd1e"}, "b": [1, -2, 0, true, false, null], "n": 9999999999999999}` |
| SHA-256 of CJ1 | `2919fccc2c9c5488f568daf7ada444f3b38fbd0c1de80a970d2d6a48f162e172` |
| SHA-256 of prefix + CJ1 (the pack digest rule applied to this document) | `bfe5d9552aa34d72ac55d185ed3f79afccbe8991c0a73ab6528feba5ce170377` |
| `H(["x", ["y", [1, null]], {"k": "v"}])` | `77cd6b4c4e0c482824748218f10725708199c628e96dc1c99a9b28804251cc7b` |

Release 2026.11.6 (`migration/fixtures/content.json`, 441,863 bytes; CJ1 is 365,337 bytes):

| quantity | value |
|---|---|
| `application_catalog` | `f96fe05e0855fbec4c13a767f62384f409474c8f19e1e4d202202c1e2e936b41` |
| `families` (stated) | `3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649` |
| `host_catalog` | `f463fce893f7a9d4cd37da585971f6068dd7c112a26975ffba886560b7e5232b` |
| `risks` | `59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85` |
| release digest | `d425b8adc87db36d` |
| pack digest | `db8378c3128f7c51a6cd91e6920e60e3ea29b1b8c0a5b99afe7e942e57102d75` |

## Limits, stated

- The release digest is 64 bits. That identifies a release among the project's own releases; it is not a
  collision-resistant commitment and must not be the value a host pins for integrity. The pack digest is.
- `families` is not recomputable from a schema-1 pack. A pack whose family hash was replaced together with
  `release.digest` passes the loader's self-consistency check; only the pack digest (or a later schema that
  carries the inventory) detects that.
- The reference does not compute or check the pack digest; nothing in the Python tree changed.
