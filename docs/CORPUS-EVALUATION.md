# Independent corpus evaluation (D09)

Two things are easy to confuse: the repository's **synthetic fixture report** (`tools/corpus_report.py`,
docs/CORPUS-REPORT-V065.md), which measures the engine against inputs its own authors wrote, and an
**independent evaluation**, which measures it against captures whose labels were assigned without the
engine. The first is a regression gate. Only the second says anything about accuracy on traffic the
authors did not write. This document describes the infrastructure for the second and states, honestly,
that no independent corpus has been evaluated yet.

## Harness

`tools/evaluate_corpus.py CORPUS` (`make evaluate CORPUS=dir`) reads `CORPUS/manifest.json`, verifies the
SHA-256 of every capture it names (files must live inside the corpus directory), runs each capture through
the same recorded-adapter path as `protodetect analyze` (with per-capture Analyzer options: observation
mode, checksum policy, continuation, hints, fingerprints, certificates) and scores every labelled flow by
its session record:

| outcome | meaning |
|---|---|
| correct | the record names the labelled family (and application, when the label gives one) |
| wrong application | right family, another application (for example `webdav` expected, `web-browsing` found) |
| wrong | another family was identified: a false identification, the case that matters most |
| unidentified | a record exists but ends without an identification (incomplete, unknown, midstream, budget) |
| missing | the engine produced no record for the labelled flow |
| unlabelled | flows the engine reported that the manifest does not label; counted, never scored |

Per family: labelled, correct, wrong, unidentified, missing, false positives (flows of another family
identified as this one), recall and precision. The report (Markdown and JSON) repeats the corpus
provenance, the engine content pin (`version@digest`, D08) and a digest of the label set, and lists the
confusions expected → found. It holds endpoints, labels, counts and digests: no payload, no hostname, no
captured bytes.

## Manifest contract

```json
{
  "corpus": "name", "version": "2026.01", "independent": true,
  "source": "who produced the captures, under what authorization or licence",
  "labelled_by": "who or what assigned the labels, independently of this engine",
  "label_basis": "generating client configuration | test-bed | analyst review",
  "captures": [
    {"file": "http.pcap", "sha256": "<hex>", "options": {"observation": "handshake"},
     "flows": [{"transport": "tcp", "client": ["192.0.2.10", 52000], "server": ["198.51.100.20", 80],
                "family": "http", "application": "web-browsing"}]}
  ]
}
```

`corpus`, `source`, `labelled_by`, `label_basis` and `captures` are required: a corpus without stated
provenance is refused, not evaluated. `independent: true` is a claim the corpus owner makes; when it is
absent or false the report says so in its header. Families must be ones the engine declares
(`protodetect protocols`); labels for traffic outside the engine's scope are a manifest error, not a miss.
A label whose flow the engine never records is a `missing`, not silently dropped.

## Independence requirements

- Labels must not be derived from this engine's output or from its fixtures. Acceptable bases: the client
  or server that generated the traffic, the test-bed configuration, a packet-level review by an analyst who
  did not consult the engine's verdicts.
- The captures must be authorized for this use: synthetic test-bed traffic, or a published dataset under
  a licence that allows local evaluation. This project never captures real user or external traffic
  (AGENTS.md), and the harness does not fetch anything.
- The corpus is kept outside the repository (it is data, not code); the report and the manifest digest are
  what gets committed, so a result can be tied to an exact label set and engine content version.

## Acceptance status: blocked

No independent labelled corpus is available in the environment this work ran in (no network access to
public datasets, and producing one here would make its authors the engine's authors again). The harness is
exercised by `test_corpus_evaluation.py` on a synthetic self-check corpus that labels itself
`independent: false`, which proves the scoring, the provenance checks and the thresholds, and proves
nothing about real-world accuracy. The D09 acceptance (an evaluation of an independent corpus with its
report committed) stays **blocked** until Lee provides or approves a corpus: candidates are a test-bed
capture labelled from the generating clients, or a licensed public dataset whose labels come with it.
Until then no accuracy number from the synthetic report should be quoted as an independent result.
