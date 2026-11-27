.PHONY: serve test presentation-test presentation-check content manifest check lint sbom pins requirements requirements-run docs-counts ledgers workflow-lint ci-local pin-drift go-drift workflow-policy go-check go-check-static go-check-race go-check-386 go-check-fuzz go-check-parity go-check-minimum parity-go go-build parity-analyze parity-decrypt parity-live parity-live-decrypt schema-go bench-gate parity-control parity-server adversarial bench-load go-vendor-check parity-random pcap-oracle mutation-tool mutation golden-check property-long keylogs content-pack
PYTHON ?= python3
INTERFACE ?= en0
DURATION ?= 60

# PRO-403: the Python reference engine is removed (its last state is the tag python-final); what Python remains is
# repository tooling (tools/, migration/), the root launchers and the presentation launcher. The launcher tests run
# the Go binary, so it is built first.
test: go-build
	$(PYTHON) -B -m unittest discover -v

# The presentation suite: the Go service's dashboard in a real browser and the launcher. It needs no Python
# package; the browser tests need Node and Playwright (tools/ui-test-deps) and skip without them, which the
# presentation-ui CI job does not allow. The interpreter is resolved before the directory change, so
# `PYTHON=.venv/bin/python` (a path relative to the repository root) works as documented.
presentation-test:
	@PY="$(PYTHON)"; case "$$PY" in /*) ;; */*) PY="$$PWD/$$PY";; esac; \
	cd presentation && "$$PY" -B -m unittest discover -s tests -v

check: lint test pins workflow-policy requirements docs-counts ledgers manifest presentation-check keylogs content content-pack
	$(PYTHON) -B -m compileall -q tools migration presentation *.py

manifest:
	$(PYTHON) -B tools/build_manifest.py --check presentation/SOURCE.json

# The Go binary the browser and launcher tests serve is rebuilt first, so a stale one is never tested. The suite's
# own exit status is the target's exit status (a failing suite never reads as skipped).
presentation-check: go-build
	$(MAKE) --no-print-directory presentation-test PYTHON=$(PYTHON)

docs-counts:
	$(PYTHON) -B tools/check_docs_counts.py

# PRO-347: the generated ledger sections are not hand-edited and every migration/notes/PRO-<n>.md parses.
# `python3 -B tools/build_ledgers.py --write` rebuilds them (after merge, on main).
ledgers:
	$(PYTHON) -B tools/build_ledgers.py --check

# The local gates CI runs, in one command: the repository gate, the Go engine's gate and the vendor check.
ci-local: check go-check go-vendor-check

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
	$(PYTHON) -B tools/ci_scope.py --self-test
	$(PYTHON) -B tools/go_ci.py --self-test
	$(PYTHON) -B tools/go_fuzz_long.py --self-test
	$(PYTHON) -B tools/go_fuzz_smoke.py --self-test
	$(PYTHON) -B tools/go_fuzz_smoke.py --check-matrix .github/workflows/ci.yml
	$(PYTHON) -B tools/content_gate.py --self-test
	$(PYTHON) -B tools/merge_readiness.py --self-test
	$(PYTHON) -B tools/perf_history.py --self-test
	$(PYTHON) -B tools/build_go_release.py --self-test
	$(PYTHON) -B tools/release_provenance.py --self-test
	$(PYTHON) -B tools/check_required_checks.py --self-test
	$(PYTHON) -B tools/build_ledgers.py --self-test
	$(PYTHON) -B tools/check_required_checks.py
	$(PYTHON) -B tools/check_gitleaks_allowlist.py --self-test
	$(PYTHON) -B tools/check_ci_consistency.py --self-test
	$(PYTHON) -B tools/check_ci_consistency.py
	$(PYTHON) -B tools/go_lint.py --self-test
	$(PYTHON) -B tools/go_deep.py --self-test
	$(PYTHON) -B tools/go_cover.py --self-test
	$(PYTHON) -B tools/go_api.py --self-test
	$(PYTHON) -B tools/contract_check.py --self-test
	$(PYTHON) -B tools/osv_scan.py --self-test
	$(PYTHON) -B tools/check_workflow_policy.py --self-test
	$(PYTHON) -B tools/check_workflow_policy.py

# Every security requirement names tests that exist (requirements) and pass when run (requirements-run, which
# needs the pinned Go and go/bin/protodetect for the Python tests: make go-build): SECURITY-REQUIREMENTS.md,
# PRO-403, PRO-546.
requirements:
	$(PYTHON) -B tools/check_security_requirements.py --self-test
	$(PYTHON) -B tools/check_security_requirements.py

requirements-run: go-build
	$(PYTHON) -B tools/check_security_requirements.py --run

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

keylogs:
	python3 -B tools/check_no_keylogs.py

content:
	python3 -B tools/check_content.py

# PRO-411: the content pack is edited directly (go/internal/content/pack.json, history.json, lock.json) with
# tools/content_pack.py; nothing is exported from the Python tables. The check, the tool's self-test, and the
# example batch added in a copy of the tree without protocol_engine/ and protocol_adapters/ (Go content tests
# included, so this needs the pinned Go). Add a batch: python3 -B tools/content_pack.py add BATCH.json
# (docs/CONTENT-BATCHES.md).
content-pack:
	python3 -B tools/content_pack.py check
	python3 -B tools/content_pack.py --self-test --e2e

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

# go-check is the Go engine's whole gate, in four parts that CI runs as separate jobs (tools/go_ci.py go --part):
# go-check-static (gofmt, vet, the mutation boundary checks), go-check-race (`go test -race`), go-check-fuzz
# (every GO_FUZZ_SMOKE target for its seconds; GO_FUZZ_SHARD=I/N runs only shard I of N, as tools/go_fuzz_smoke.py
# assigns them) and go-check-parity (every parity, schema, adversarial, random and bench gate). Locally
# `make go-check` still runs all four, in that order, and stops at the first failing part.
GO_FUZZ_SHARD ?= 1/1
GO_FUZZ_SMOKE := \
	./internal/buffer:FuzzAppendNeverExceedsLimits:10 \
	./internal/contracts:FuzzObservationJSONNeverPanics:10 \
	./internal/reassembly:FuzzFeedInvariants:10 \
	./internal/protocols/framed:FuzzFramedNeverPanics:20 \
	./internal/protocols/framed:FuzzKasaNeverPanics:10 \
	./internal/protocols/framed:FuzzGSSNeverPanics:15 \
	./internal/transport:FuzzDecodeNeverPanics:10 \
	./internal/engine:FuzzInspectorNeverPanics:10 \
	./internal/engine:FuzzSelectNeverPanics:5 \
	./internal/signatures:FuzzPatternNeverPanics:10 \
	./internal/decrypt:FuzzConnectionNeverPanics:10 \
	./internal/capture:FuzzDecoderNeverPanics:10 \
	./internal/keylogcap:FuzzAnalyzeNeverPanics:10 \
	./internal/livedecrypt:FuzzReplayNeverPanics:10 \
	./internal/content:FuzzCanonicalIsAFixedPoint:10 \
	./internal/content:FuzzParseNeverPanics:10 \
	./internal/analyze:FuzzPresentNeverPanics:10 \
	./internal/policy:FuzzPolicyNeverPanics:10 \
	./internal/signatures:FuzzDocumentNeverPanics:10 \
	./internal/signatures:FuzzEstimateBoundsProgram:10 \
	./internal/protocols/tlsx:FuzzDTLSStaysBounded:10 \
	./internal/protocols/hpack:FuzzDecoderStaysBounded:10 \
	./internal/engine:FuzzHTTP2StaysBounded:10 \
	./internal/engine:FuzzHTTPContinuationStaysBounded:10 \
	./internal/protocols/x509x:FuzzLeafProfileStaysBounded:10 \
	./internal/protocols/quicx:FuzzValidateStaysBounded:10 \
	./internal/protocols/textroute:FuzzKexinitPostureMatchesTheOracle:10 \
	./internal/ojson:FuzzDecodeIsAFixedPoint:10 \
	./internal/livectl:FuzzIngestNeverPanics:10 \
	./internal/engine:FuzzEveryParserIsSplitInvariant:20 \
	./internal/engine:FuzzInspectorIsSplitInvariant:10 \
	./internal/engine:FuzzDatagramIsDeterministic:10 \
	./detector:FuzzFlowIsSplitInvariant:10

go-check:
	$(MAKE) go-check-static
	$(MAKE) go-check-race
	$(MAKE) go-check-386
	$(MAKE) go-check-fuzz
	$(MAKE) go-check-parity

go-check-static:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) sh -c 'files=$$(find . -name "*.go" -not -path "./vendor/*"); test -z "$$(gofmt -l $$files)" || { gofmt -l $$files; exit 1; }'
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go vet ./...
	$(PYTHON) -B migration/mutation/boundaries.py --self-test
	$(PYTHON) -B migration/mutation/boundaries.py --check
	$(PYTHON) -B migration/parity/golden.py --self-test
	$(PYTHON) -B migration/mutation/mutation.py --self-test

go-check-race:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test -race ./...

# go-check-386 (PRO-262, ci: go-engine): the protocol parsers' tests on a 32-bit int (GOARCH=386), where a length
# sum such as pos+length can wrap negative and pass a bounds check (SEC-X509-1); `go test -race` on amd64 cannot see
# that. Every package under ./internal/protocols/ runs, new ones included, except GO_386_EXCLUDE: packages that do not
# compile for 386 yet (framed: untyped constants above 2^31 assigned to int). An excluded package that starts to
# compile fails the target, so its exclusion is removed as soon as it can be tested. Offline and vendored.
GO_386_EXCLUDE := framed
go-check-386:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOARCH=386 CGO_ENABLED=0 GOFLAGS=-mod=vendor sh -c '\
	  set -e; all=$$(go list ./internal/protocols/...); run=""; \
	  for pkg in $$all; do skip=""; for name in $(GO_386_EXCLUDE); do \
	    case "$$pkg" in */internal/protocols/$$name) skip=1;; esac; done; \
	    if [ -n "$$skip" ]; then \
	      if go build "$$pkg" 2>/dev/null; then echo "$$pkg now builds for GOARCH=386: remove it from GO_386_EXCLUDE"; exit 1; fi; \
	      echo "go-check-386: excluded (does not build for 386 yet): $$pkg"; \
	    else run="$$run $$pkg"; fi; done; \
	  test -n "$$run" || { echo "go-check-386: no package to test"; exit 1; }; \
	  go test -count=1 $$run'

go-check-fuzz:
	$(PYTHON) -B tools/go_fuzz_smoke.py --toolchain $(GO_TOOLCHAIN) --shard $(GO_FUZZ_SHARD) $(GO_FUZZ_SMOKE)

go-check-parity:
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

# PRO-402: the demo page on the Go engine (protodetect serve on 127.0.0.1, opened in the browser). No Python engine runs.
serve: go-build
	$(PYTHON) -B presentation/launch.py

# PRO-401 (Lee, 2026-11-25: the Python reference is removed): every differential below replays a golden file, the
# generated inputs and the reference's answers frozen by one recording run (migration/parity/golden.py), so none of
# them runs or imports the reference (protocol_engine, protocol_adapters, presentation's Python) or needs the
# cryptography package. `make golden-record` re-records them all with the reference, as long as it exists.
GOLDEN := migration/fixtures/golden

# Migration M8: the Go `analyze` command against the reference's frozen answers on generated captures (rows, exit status,
# error text, and the presentation result of the same capture)
parity-analyze: go-build
	python3 -B migration/parity/analyze_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/analyze.json.gz

# Migration M8: the Go `decrypt-capture` command against the reference's frozen reports on generated TLS captures and
# key logs (synthetic, seeded throwaway keys; nothing is captured)
parity-decrypt: go-build
	$(PYTHON) -B migration/parity/decrypt_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/decrypt.json.gz

# Migration M8: the Go `live` command against the reference's frozen events on replayed capture streams (the clock
# taken from the stream, so every event is a function of its bytes; nothing is captured)
parity-live: go-build
	$(PYTHON) -B migration/parity/live_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/live.json.gz

# Migration M8: the Go live decryption worker against the reference's frozen events on replayed scripts (capture
# chunks, key-log text and ticks with their clock values; in memory only)
parity-live-decrypt: go-build
	$(PYTHON) -B migration/parity/live_decrypt_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/live-decrypt.json.gz

# Migration C14: the Go live control plane's run state (event log, reducer, retained views, run-scoped reset) against
# the reference LiveManager's frozen answers on recorded operation scripts
parity-control: go-build
	$(PYTHON) -B migration/parity/control_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/control.json.gz

# Migration C14/C15: `protodetect serve` against presentation/server.py's frozen answers, request for request (a
# stand-in tcpdump plays the recorded capture: nothing is captured; only the Go service is started)
parity-server: go-build
	$(PYTHON) -B migration/parity/server_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/server.json.gz

# Adversarial identification: inputs built to deceive the detector, judged for honesty, and Go compared with the
# reference's frozen answers
adversarial: go-build
	$(PYTHON) -B migration/parity/adversarial.py --binary go/bin/protodetect --golden $(GOLDEN)/adversarial.json.gz

# Randomized differential (PRO-100): seeded valid-shaped TLS, HTTP, SSH and QUIC openings with random fragmentation,
# truncation, hints and budgets. Since PRO-401 its seed-1 run of 2,000 cases is frozen with the reference's answers
# and replayed here (a planted wrong answer must be caught); Go must agree on every case outside
# migration/parity/random_allow.json and the approved divergences. Fresh random inputs are the Go-only property tests'
# job (go/internal/engine/openings_property_test.go), which need no oracle; `make property-long` runs them long.
parity-random: go-build
	$(PYTHON) -B migration/parity/random_diff.py --self-test --rules-only
	$(PYTHON) -B migration/parity/random_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/random.json.gz --plant
	$(PYTHON) -B migration/parity/random_diff.py --binary go/bin/protodetect --golden $(GOLDEN)/random.json.gz

# The long randomized run, Go only (PRO-401; it replaced the Python-oracle parity-random-long): the opening property
# tests with CHECKS draws each and a PROPERTY_SEED (0: rapid picks one and prints it; a failure prints the seed and
# a failfile that reproduce it). Nightly; never a per-PR gate.
PROPERTY_SEED ?= 0
CHECKS ?= 50000
property-long:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go test -count=1 -run 'Opening|Openings|Hints|TightBudgets' -v ./internal/engine/ -rapid.checks=$(CHECKS) -rapid.seed=$(PROPERTY_SEED)

# PRO-403: the golden files can no longer be re-recorded here, because the reference that answered them is gone.
# Re-recording (each differential's --record mode, migration/parity/golden.py) needs a checkout of the tag
# python-final with the cryptography extra; golden-check replays them all.
golden-check: parity-analyze parity-decrypt parity-live parity-live-decrypt parity-control parity-server schema-go adversarial parity-random
	$(PYTHON) -B migration/parity/golden.py --self-test
	$(PYTHON) -B migration/mutation/boundaries.py --check

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

# Migration C13: every line the Go binary writes validates against the published schemas (schemas/*.json), on the
# recorded generated captures
schema-go: go-build
	$(PYTHON) -B migration/parity/schema_go.py --binary go/bin/protodetect --golden $(GOLDEN)/schema.json.gz

# Migration M4: the Go backend's results against the Python reference (families it claims; records are M6)
GO_FAMILIES := http,tls,dns,mdns,netbios-ns,llmnr,ssh,smtp,imap,pop3,ftp,nats,irc,sip,rtsp,telnet,postgresql,rfb,bittorrent,memcached,rsync,fins,afp,zmtp,bolt,stomp,giop,x11,spice,mysql,mongodb,tds,tns,cql,kafka,modbus,dnp3,ethernet-ip,iec-104,opcua,s7comm,mqtt,resp,amqp,onc-rpc,diameter,bgp,openvpn,pptp,fastcgi,dcerpc,websocket,xmpp,syslog,git,netbios-ss,tacacs-plus,socks5,wireguard,bacnet,tftp,ntp,l2tp,coap,rip,rtcp,lifx-lan,tuya-lan,netflow,ipfix,sflow,stun,dhcp,radius,snmp,rtp,ssdp,tplink-smarthome,kerberos,ldap,smb1,smb2,rdp,iso-tsap,ikev2,quic,http2,dtls
parity-go:
	cd go && GOTOOLCHAIN=$(GO_TOOLCHAIN) GOFLAGS=-mod=vendor go run ./cmd/protodetect replay --cases ../migration/fixtures/cases.json --out ../migration/parity/go-results.json
	python3 -B migration/parity/compare.py --results migration/parity/go-results.json --families $(GO_FAMILIES) --report migration/parity/go-report.json
	python3 -B migration/parity/verify_families.py --check migration/CAPABILITIES.json
