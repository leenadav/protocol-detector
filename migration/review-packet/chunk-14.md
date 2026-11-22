# chunk-14: Capture and JSON input decoders (capture, ojson/bytes, pyjson)

Tier 1 · about 708 changed lines of code · contracts: C1, C13, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/capture/capture.go go/internal/ojson/bytes.go go/internal/pyjson/pyjson.go` (5 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

pcap/pcapng reader for `analyze` and live (untrusted capture files), the CPython-compatible UTF-8 byte decoder of the ojson parser, and pyjson (CPython `json.dumps` byte compatibility for records). `pyjson.go` is byte-identical to `725cd95`.

## Questions to answer

1. pcapng: are block lengths (trailing copy included), option lengths and snap lengths validated before slicing?
2. Can a capture with many interfaces or sections grow per-interface state without bound?
3. ojson bytes: is the surrogatepass handling exact, and are BOM-stripped offsets reported correctly (the earlier fix)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzDecoderNeverPanics`, `FuzzDecodeIsAFixedPoint`
- `make parity-analyze` (generated captures, rows, exit status, error text): 0 differences
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/capture/capture.go`: whole file (407 lines, new)
- `go/internal/ojson/bytes.go`: whole file (109 lines, new)
- `go/internal/pyjson/pyjson.go`: whole file (192 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/capture/capture_test.go`, `go/internal/pyjson/pyjson_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
