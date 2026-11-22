.PHONY: test presentation-test presentation-check content capabilities evaluate sequences sequences-extended perf-profile manifest demo protocols apps risks sessions proxy-demo benchmark live live-smoke interfaces replay-live check lint fuzz sbom pins requirements policy-lint coverage-matrix docs-counts workflow-lint ci-local package pin-drift go-drift workflow-policy go-check go-check-minimum parity-go go-build parity-analyze parity-decrypt parity-live parity-live-decrypt schema-go bench-gate parity-control parity-server adversarial bench-load go-vendor-check parity-random parity-random-long pcap-oracle mutation-tool mutation
PYTHON ?= python3
INTERFACE ?= en0
DURATION ?= 60

test:
	$(PYTHON) -B -m unittest discover -v

# The presentation application (frontend, server, live bridge, TLS POC) needs the optional decryption extra:
# $(PYTHON) -m pip install -r presentation/requirements-decryption.txt. The core engine stays dependency-free.
# The interpreter is resolved before the directory change, so `PYTHON=.venv/bin/python` (a path relative to the
# repository root) works as documented; a bare command name is left to PATH.
presentation-test:
	@PY="$(PYTHON)"; case "$$PY" in /*) ;; */*) PY="$$PWD/$$PY";; esac; \
	cd presentation && "$$PY" -B -m unittest discover -s tests -v

demo:
	$(PYTHON) -B protocol_demo.py

protocols:
	$(PYTHON) -B protocol_demo.py --list

apps:
	$(PYTHON) -B appid_catalog.py

risks:
	$(PYTHON) -B protodetect.py risks

policy-lint:
	$(PYTHON) -B protodetect.py policy lint policy-example.json --strict

sessions:
	$(PYTHON) -B analyze_pcap.py sample-expanded.pcap --events-only --sessions

proxy-demo:
	$(PYTHON) -B proxy_demo.py

benchmark:
	$(PYTHON) -B benchmark_capture_v022.py --iterations 300 --rounds 5

live:
	$(PYTHON) -B live_capture.py --interface $(INTERFACE) --duration $(DURATION)

interfaces:
	$(PYTHON) -B live_capture.py --interfaces

live-smoke:
	$(PYTHON) -B live_smoke.py
	$(PYTHON) -B live_smoke.py --database mysql
	$(PYTHON) -B live_smoke.py --database mongodb
	$(PYTHON) -B live_smoke.py --radius

replay-live:
	cat sample-expanded.pcap | $(PYTHON) -B live_capture.py --stdin --duration 0

coverage-matrix:
	$(PYTHON) -B tools/coverage_matrix.py --check PROTOCOLS.md

check: lint test pins workflow-policy requirements policy-lint coverage-matrix docs-counts manifest presentation-check inventory keylogs content sequences capabilities content-pack parity
	$(PYTHON) -B -m compileall -q protocol_engine tools *.py

manifest:
	$(PYTHON) -B tools/build_manifest.py --check presentation/SOURCE.json

# Runs the presentation suite when the optional decryption extra is importable, and says so when it is not,
# instead of silently passing: the canonical CI job installs the extra and always runs it.
# Explicit dependency detection: the suite's own exit status is the target's exit status (a failing suite can
# never read as "skipped"); only a missing `cryptography` skips, and says so.
# The presentation suite runs the Go backend when go/bin/protodetect exists, so a binary built before the latest
# engine or content change would be compared instead of the tree (2026-11-18): rebuild it first when Go is here.
presentation-check:
	@if [ -x go/bin/protodetect ] && command -v go >/dev/null 2>&1; then \
	  $(MAKE) --no-print-directory go-build; \
	elif [ -x go/bin/protodetect ]; then \
	  echo "presentation-check: go/bin/protodetect exists but no Go toolchain is on PATH to rebuild it; it may be stale"; \
	fi
	@if $(PYTHON) -c "import cryptography" 2>/dev/null; then \
	  $(MAKE) --no-print-directory presentation-test PYTHON=$(PYTHON); \
	else \
	  echo "presentation-check: skipped here (install .[decryption] to run it); CI runs it unconditionally"; \
	fi

docs-counts:
	$(PYTHON) -B tools/check_docs_counts.py

# Same checks the CI workflow runs, in one command, plus the extended fuzz pass.
ci-local: check fuzz sequences-extended go-vendor-check
	$(PYTHON) -B analyze_pcap.py sample-expanded.pcap --events-only --sessions > /dev/null
	$(PYTHON) -B protodetect.py analyze sample-expanded.pcap --json --sessions | $(PYTHON) -B protodetect.py schema offline-row --validate /dev/stdin

# Build the sdist and wheel (dev tools installed), check the wheel carries only the engine package,
# then install it into an empty environment and classify fixtures from there (never from the tree).
package:
	$(PYTHON) -m build --sdist --wheel --outdir dist
	$(PYTHON) -B tools/check_wheel.py "dist/*.whl"
	rm -rf dist/wheel-env && $(PYTHON) -m venv dist/wheel-env
	dist/wheel-env/bin/python -m pip install --quiet --no-deps --no-index dist/*.whl
	cd dist && wheel-env/bin/python ../tools/wheel_smoke.py

# Workflow lint with a locally installed actionlint (CI fetches a checksum-verified release) and the
# zizmor security audit from the dev toolchain (pedantic persona, offline audits, any finding fails).
workflow-lint:
	actionlint -no-color .github/workflows/*.yml
	zizmor --no-online-audits --no-progress --persona pedantic --min-severity unknown .github/workflows
	$(PYTHON) -B tools/check_workflow_yaml.py --self-test
	$(PYTHON) -B tools/check_workflow_yaml.py

lint:
	ruff check .

pins:
	$(PYTHON) -B tools/check_action_pins.py .github/workflows

# The ci gate lists every ci job; the drift workflow triggers on every workflow file;
# release publishes serialize; a release tag must point at a commit on main.
workflow-policy:
	$(PYTHON) -B tools/check_release_ref.py --self-test
	$(PYTHON) -B tools/check_release_exposure.py --self-test
	$(PYTHON) -B tools/check_release_checks.py --self-test
	$(PYTHON) -B tools/release_audit.py --self-test
	$(PYTHON) -B tools/check_go_drift.py --self-test
	$(PYTHON) -B tools/codeql_gate.py --self-test
	$(PYTHON) -B tools/go_ci.py --self-test
	$(PYTHON) -B tools/go_fuzz_long.py --self-test
	$(PYTHON) -B tools/content_gate.py --self-test
	$(PYTHON) -B tools/merge_readiness.py --self-test
	$(PYTHON) -B tools/perf_history.py --self-test
	$(PYTHON) -B tools/build_go_release.py --self-test
	$(PYTHON) -B tools/release_provenance.py --self-test
	$(PYTHON) -B tools/check_required_checks.py --self-test
	$(PYTHON) -B tools/check_required_checks.py
	$(PYTHON) -B tools/check_ci_consistency.py --self-test
	$(PYTHON) -B tools/check_ci_consistency.py
	$(PYTHON) -B tools/go_lint.py --self-test
	$(PYTHON) -B tools/go_deep.py --self-test
	$(PYTHON) -B tools/go_cover.py --self-test
	$(PYTHON) -B tools/check_workflow_policy.py --self-test
	$(PYTHON) -B tools/check_workflow_policy.py

requirements:
	$(PYTHON) -B tools/check_security_requirements.py

fuzz:
	$(PYTHON) -B tools/fuzz_fixtures.py --iterations 2000

sbom:
	cyclonedx-py environment --output-format json --output-file sbom.cdx.json
	$(PYTHON) -B tools/sbom_summary.py sbom.cdx.json

# Weekly drift gate run locally: every pinned action SHA must still be the commit its tag comment names (network).
pin-drift:
	$(PYTHON) -B tools/check_pin_drift.py --self-test
	$(PYTHON) -B tools/check_pin_drift.py .github/workflows

# Weekly drift gate run locally: the Go that builds the pinned scanners is supported and on its newest patch (network).
go-drift:
	$(PYTHON) -B tools/check_go_drift.py --self-test
	$(PYTHON) -B tools/check_go_drift.py

inventory:
	python3 -B tools/check_inventory.py

keylogs:
	python3 -B tools/check_no_keylogs.py

content:
	python3 -B tools/check_content.py

# Migration M0: the per-family capability inventory must match the registry (Go statuses are kept as recorded)
capabilities:
	python3 -B tools/capabilities.py --check migration/CAPABILITIES.json

# Migration M6: the exported content pack both runtimes load must match the Python content (tools/export_content.py)
content-pack:
	python3 -B tools/export_content.py --check migration/fixtures/content.json
	python3 -B migration/content_history.py --check go/internal/content/history.json

# Migration M1: the Python reference must match the committed differential cases exactly (migration/CONTRACTS.md)
parity:
	python3 -B migration/parity/compare.py --backend python

# Migration M2: the Go module's own gate. go/go.mod's `go` line is the minimum Go the module needs, its
# `toolchain` line the compiler it is built with, implicitly the `go` line when absent (go.dev/doc/toolchain).
# go-check runs on the compiler (ci: go-engine), go-check-minimum on the minimum (ci: go-minimum): one Go per
# target, each GOTOOLCHAIN naming exactly the Go the job installed, so neither switches Go mid-run.
GO_TOOLCHAIN := $(or $(shell sed -n 's/^toolchain \(go.*\)$$/\1/p' go/go.mod),$(shell sed -n 's/^go \(.*\)$$/go\1/p' go/go.mod))
GO_MINIMUM := $(shell sed -n 's/^go \(.*\)$$/go\1/p' go/go.mod)
go-check-minimum:
	cd go && GOTOOLCHAIN=$(GO_MINIMUM) GOFLAGS=-mod=vendor go vet ./...
	cd go && GOTOOLCHAIN=$(GO_MINIMUM) GOFLAGS=-mod=vendor go test -race ./...

# The engine's one module dependency (golang.org/x/crypto, key-log TLS decryption) is vendored in go/vendor, so
# every Go build and test here runs with -mod=vendor and needs no module download (CI runs with GOPROXY=off).
# go-vendor-check re-vendors into build/go-vendor-check (git-ignored, outside the module, replaced on each run) and fails when go/vendor
# differs from what go.mod and go.sum select, or has uncommitted changes. Re-vendoring needs the modules (the
# module cache or a proxy), so CI runs it in a step that can reach them; the builds and tests never do.
go-vendor-check:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=mod go mod vendor -o ../build/go-vendor-check
	cd go && diff -r ../build/go-vendor-check vendor || { echo "go/vendor is out of sync: run (cd go && go mod vendor) and commit it"; exit 1; }
	git diff --quiet --exit-code -- go/go.mod go/go.sum go/vendor || { echo "go/vendor, go.mod or go.sum has uncommitted changes"; exit 1; }
	test -z "$$(git status --porcelain -- go/go.mod go/go.sum go/vendor)" || { echo "go/vendor has untracked or uncommitted files"; exit 1; }
	@echo "go vendor ok: go/vendor matches go.mod and go.sum"

go-check:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) sh -c 'files=$$(find . -name "*.go" -not -path "./vendor/*"); test -z "$$(gofmt -l $$files)" || { gofmt -l $$files; exit 1; }'
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go vet ./...
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test -race ./...
	$(PYTHON) -B migration/mutation/boundaries.py --check
	$(PYTHON) -B migration/mutation/mutation.py --self-test
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/buffer -run NONE -fuzz FuzzAppendNeverExceedsLimits -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/contracts -run NONE -fuzz FuzzObservationJSONNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/reassembly -run NONE -fuzz FuzzFeedInvariants -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/framed -run NONE -fuzz FuzzFramedNeverPanics -fuzztime 20s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/framed -run NONE -fuzz FuzzKasaNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/framed -run NONE -fuzz FuzzGSSNeverPanics -fuzztime 15s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/transport -run NONE -fuzz FuzzDecodeNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/engine -run NONE -fuzz FuzzInspectorNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/engine -run NONE -fuzz FuzzSelectNeverPanics -fuzztime 5s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/signatures -run NONE -fuzz FuzzPatternNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/decrypt -run NONE -fuzz FuzzConnectionNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/capture -run NONE -fuzz FuzzDecoderNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/keylogcap -run NONE -fuzz FuzzAnalyzeNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/livedecrypt -run NONE -fuzz FuzzReplayNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/content -run NONE -fuzz FuzzCanonicalIsAFixedPoint -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/content -run NONE -fuzz FuzzParseNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/analyze -run NONE -fuzz FuzzPresentNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/policy -run NONE -fuzz FuzzPolicyNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/signatures -run NONE -fuzz FuzzDocumentNeverPanics -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/tlsx -run NONE -fuzz FuzzDTLSStaysBounded -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/hpack -run NONE -fuzz FuzzDecoderStaysBounded -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/engine -run NONE -fuzz FuzzHTTP2StaysBounded -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/engine -run NONE -fuzz FuzzHTTPContinuationStaysBounded -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/x509x -run NONE -fuzz FuzzLeafProfileStaysBounded -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/quicx -run NONE -fuzz FuzzValidateStaysBounded -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/protocols/textroute -run NONE -fuzz FuzzKexinitPostureMatchesTheOracle -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/ojson -run NONE -fuzz FuzzDecodeIsAFixedPoint -fuzztime 10s
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test ./internal/livectl -run NONE -fuzz FuzzIngestNeverPanics -fuzztime 10s
	$(MAKE) parity-go
	$(MAKE) parity-analyze
	$(MAKE) parity-decrypt
	$(MAKE) parity-live
	$(MAKE) parity-live-decrypt
	$(MAKE) schema-go
	$(MAKE) parity-control
	$(MAKE) parity-server
	$(MAKE) adversarial
	$(MAKE) parity-random
	$(MAKE) bench-gate

# Migration M8: the Go command-line binary (static, no cgo); go/bin is not tracked
go-build:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor CGO_ENABLED=0 go build -trimpath -o bin/protodetect ./cmd/protodetect

# Migration M8: the Go `analyze` command against the Python reference on generated captures (rows, exit status, error text)
parity-analyze: go-build
	python3 -B migration/parity/analyze_diff.py --binary go/bin/protodetect --count 300 --seed 1

# Migration M8: the Go `decrypt-capture` command against the Python reference on generated TLS captures and key logs
# (in memory only; the reference needs the cryptography extra: presentation/requirements-decryption.lock.txt)
parity-decrypt: go-build
	$(PYTHON) -B migration/parity/decrypt_diff.py --binary go/bin/protodetect --count 300 --seed 1

# Migration M8: the Go `live` command against the Python reference on replayed capture streams (the clock taken from
# the stream, so every event is a function of its bytes; nothing is captured)
parity-live: go-build
	$(PYTHON) -B migration/parity/live_diff.py --binary go/bin/protodetect --count 300 --seed 1

# Migration M8: the Go live decryption worker against the Python reference on replayed scripts (capture chunks, key-log
# text and ticks with their clock values; in memory only; the reference needs the cryptography extra)
parity-live-decrypt: go-build
	$(PYTHON) -B migration/parity/live_decrypt_diff.py --binary go/bin/protodetect --count 300 --seed 1

# Migration C14: the Go live control plane's run state (event log, reducer, retained views, run-scoped reset) against
# the reference's LiveManager on worker lines from generated inputs (the reference needs the cryptography extra)
parity-control: go-build
	$(PYTHON) -B migration/parity/control_diff.py --binary go/bin/protodetect --count 120 --seed 1

# Migration C14/C15: `protodetect serve` against presentation/server.py, request for request (a stand-in tcpdump plays a
# generated capture: nothing is captured; the reference's decryption cases need the cryptography extra)
parity-server: go-build
	$(PYTHON) -B migration/parity/server_diff.py --binary go/bin/protodetect --count 12 --seed 1

# Adversarial identification: inputs built to deceive the detector, judged for honesty and compared between the engines
adversarial: go-build
	$(PYTHON) -B migration/parity/adversarial.py --binary go/bin/protodetect

# Randomized differential (PRO-100): seeded valid-shaped TLS, HTTP, SSH and QUIC openings with random fragmentation,
# truncation, hints and budgets; the Python reference is the oracle and the Go engine must agree on every case
# outside migration/parity/random_allow.json. CI runs the fixed seed; the long run takes any SEED and COUNT, and a
# failing seed reproduces exactly.
RANDOM_SEED ?= 1
RANDOM_COUNT ?= 2000
parity-random: go-build
	$(PYTHON) -B migration/parity/random_diff.py --self-test
	$(PYTHON) -B migration/parity/random_diff.py --binary go/bin/protodetect --count 300 --plant
	$(PYTHON) -B migration/parity/random_diff.py --binary go/bin/protodetect --seed $(RANDOM_SEED) --count $(RANDOM_COUNT)

SEED ?= 1
COUNT ?= 50000
parity-random-long: go-build
	$(PYTHON) -B migration/parity/random_diff.py --binary go/bin/protodetect --seed $(SEED) --count $(COUNT) --report build/random-diff-$(SEED).json

# tshark oracle (PRO-127; nightly, never in go-check): real OpenSSL, curl and quic-go traffic on 127.0.0.1, read by
# gopacket and fed to the engine, compared with tshark. Its own test-only module (go/oracle); needs tshark 4.2.2,
# OpenSSL 3.0.13 and curl 8.5.0 (go/oracle/README.md). ORACLE_REPORT=<file> writes every comparison as JSON.
pcap-oracle:
	cd go/oracle && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=mod go test -count=1 ./...

# Mutation testing (PRO-126; nightly, never a per-PR gate). gremlins is test tooling, pinned in its own module under
# migration/mutation/gremlins and installed into build/, never linked into or vendored with go/.
# MUTATION_BIN=<path> runs a gremlins built elsewhere (the nightly job builds it in its own step, the only one with
# module-proxy access) and skips the install; by default the pinned module is installed into build/mutation-bin.
MUTATION_BIN ?= build/mutation-bin/gremlins

mutation-tool:
	cd migration/mutation/gremlins && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=mod GOBIN=$(CURDIR)/build/mutation-bin go install github.com/go-gremlins/gremlins/cmd/gremlins

build/mutation-bin/gremlins: migration/mutation/gremlins/go.mod migration/mutation/gremlins/go.sum
	$(MAKE) mutation-tool PYTHON=$(PYTHON)

mutation: $(MUTATION_BIN)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(PYTHON) -B migration/mutation/mutation.py run --gremlins $(MUTATION_BIN) --out build/mutation $(MUTATION_ARGS)

# Sustained throughput and memory with 10,000 and 100,000 concurrent flows (synthetic; reported only, never a gate)
bench-load:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test -tags loadbench -run 'TestLoad_' -count=1 -p 1 -v -timeout 30m ./internal/bench/

# Performance gates in Culvert's benchgate convention (migration/STATUS.md, performance budgets): allocations and retained
# bytes per flow are gated, latency is reported
bench-gate:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1 -v ./internal/bench/

# Migration C13: every line the Go binary writes validates against the published schemas (schemas/*.json)
schema-go: go-build
	$(PYTHON) -B migration/parity/schema_go.py --binary go/bin/protodetect --count 200 --seed 1

# Migration M4: the Go backend's results against the Python reference (families it claims; records are M6)
GO_FAMILIES := http,tls,dns,mdns,netbios-ns,llmnr,ssh,smtp,imap,pop3,ftp,nats,irc,sip,rtsp,telnet,postgresql,rfb,bittorrent,memcached,rsync,fins,afp,zmtp,bolt,stomp,giop,x11,spice,mysql,mongodb,tds,tns,cql,kafka,modbus,dnp3,ethernet-ip,iec-104,opcua,s7comm,mqtt,resp,amqp,onc-rpc,diameter,bgp,openvpn,pptp,fastcgi,dcerpc,websocket,xmpp,syslog,git,netbios-ss,tacacs-plus,socks5,wireguard,bacnet,tftp,ntp,l2tp,coap,rip,rtcp,lifx-lan,tuya-lan,netflow,ipfix,sflow,stun,dhcp,radius,snmp,rtp,ssdp,tplink-smarthome,kerberos,ldap,smb1,smb2,rdp,iso-tsap,ikev2,quic,http2,dtls
parity-go:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go run ./cmd/protodetect replay --cases ../migration/fixtures/cases.json --out ../migration/parity/go-results.json
	python3 -B migration/parity/compare.py --results migration/parity/go-results.json --families $(GO_FAMILIES) --report migration/parity/go-report.json
	python3 -B migration/parity/verify_families.py --check migration/CAPABILITIES.json

# Migration M4/M9: Python vs Go engine feed loop on identical bytes, alternating rounds (not part of `check`)
bench-compare:
	BENCH_SCRATCH=$${TMPDIR:-/tmp} python3 -B migration/benchmarks/bench_compare.py --iterations 300 --rounds 5

# D11: separated performance measurements (CPU by layer, bytes to identification, queue wait, memory); local numbers only
perf-profile:
	$(PYTHON) -B tools/perf_profile.py --write docs/PERF-PROFILE-V066.md --json docs/PERF-PROFILE-V066.json

# D10: metamorphic sequence relations over the Analyzer (segmentation, reordering, conflicts, interleaving, FIN order, reuse, expiry)
sequences:
	$(PYTHON) -B tools/sequence_check.py --iterations 1

sequences-extended:
	$(PYTHON) -B tools/sequence_check.py --iterations 8 --seed 1
	$(PYTHON) -B tools/sequence_check.py --iterations 8 --seed 2

# D09: evaluate an independently labelled capture corpus (docs/CORPUS-EVALUATION.md); CORPUS=dir
evaluate:
	$(PYTHON) -B tools/evaluate_corpus.py $(CORPUS) --write $(CORPUS)/REPORT.md --json $(CORPUS)/report.json

# Stage 8: synthetic soak (overload, sparse gaps, late keys, slow consumer, worker crashes); needs the decryption extra.
soak:
	$(PYTHON) -B tools/soak.py --write docs/SOAK-V065.json

# Stage 8: build the wheel, install it with the decryption extra into an empty environment, run the presentation suite from it.
installed-check:
	$(PYTHON) -B tools/installed_check.py

# Stage 8: the corpus report must show no intact false negatives.
corpus:
	$(PYTHON) -B tools/corpus_report.py --write docs/CORPUS-REPORT-V065.md

# Stage 8 release gate: everything a tag must pass locally, in one target (docs/RELEASE-GATE-V065.md).
release-gate: check presentation-test fuzz-smoke corpus soak dist installed-check
	@echo "release gate passed"

fuzz-smoke:
	$(PYTHON) -B tools/fuzz_fixtures.py --iterations 200 --seed 80
