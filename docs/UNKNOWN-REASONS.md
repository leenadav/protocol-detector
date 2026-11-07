# Structured unknown reasons and the minimized-example workflow (D12)

Until D12 a session that was not an identification said `unknown-tcp` / `incomplete` / `insufficient-data`
and carried the engine's sentence in `reasons`. The sentence is still there; what was missing was a closed
vocabulary that tells apart "nothing routed", "a family was selected and rejected the message", "the
message never completed" and "the observation was withdrawn", and a way to turn one such outcome into a
small reproducible example.

## The vocabulary

`protocol_engine/unknown.py` derives, from an observation and the inspector's selected candidate, a
code, its stage, the family whose parser spoke and the engine's sentence:

| code | stage | meaning | typical next step |
|---|---|---|---|
| `no-dispatch` | dispatch | the prefix routed to no supported family | is the protocol in scope? if yes, a dispatch rule or a hint |
| `ambiguous` | dispatch | structurally valid for several families; `candidates` listed | the peer direction decides (session correlation); otherwise a hint |
| `profile-unsupported` | profile | `family` was selected, the message is outside its documented profile | PROTOCOLS.md names the exclusion; extending a profile is an engine change |
| `malformed` | profile | `family` was selected and the bytes violate its structure | minimize and look at the first rejected byte; real traffic or a bug |
| `budget` | budget | a byte, line, header, count or depth budget ended inspection | raise the budget deliberately, or accept the explicit stop |
| `no-payload` | lifecycle | the direction carried no bytes before tracking ended | nothing to classify; the other direction may still identify |
| `incomplete` | lifecycle | bytes arrived, the initial message did not complete before the end (`detail` is the end reason: FIN, idle, EOF, RST, gap) | a capture or timeout question, not a parser question |
| `no-handshake` | lifecycle | no TCP handshake was observed | `--observation asymmetric` or `midstream` (D05) |
| `midstream` | lifecycle | observed midstream, start unobserved (D05) | only recurring-layout families identify midstream |
| `invalidated` | integrity | reassembly or assembly contradiction withdrew the observation (D02) | the capture carries conflicting bytes; never classify them |

The code is a reporting vocabulary derived after the fact: it never changes the verdict, the status or the
behaviour diff (observations are unchanged; the inspector only exposes `resolved_family`, the candidate or the
family a text route resolved to).

## Where it appears

- Session records carry `unknown` with `client`, `server` and, for lifecycle outcomes, `session` entries
  (schemas updated, OUTPUT.md); identifications carry no `unknown` object.
- `protodetect explain --hex … [--udp] [--hint FAMILY] [--minimize] [--json]` (and
  `tools/minimize_example.py`) prints the structured reason of one payload.

## Minimized examples

`--minimize` runs a bounded delta-debugging pass: the shortest prefix with the same outcome signature
(status, code, family, candidates), then ddmin over interior byte ranges down to single bytes. The result
is the smallest input the search found with the same signature, not a proven minimum, and it is printed as
hex with a one-line reproduction (`Inspector().feed(bytes.fromhex(...))`). The workflow for a report:

1. `protodetect explain --file payload.bin` — read the code and family.
2. `--minimize` — attach the minimized hex and the signature to the issue, not the original payload.
3. For `malformed` and `profile-unsupported`, PROTOCOLS.md's profile for `family` says whether the
   rejection is documented; a fixture built from the minimized bytes becomes the regression test.

The tool evaluates the caller's own bytes in process and stores nothing; it is not a capture tool.
