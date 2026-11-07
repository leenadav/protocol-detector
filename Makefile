.PHONY: test presentation-test presentation-check content evaluate sequences sequences-extended perf-profile manifest demo protocols apps risks sessions proxy-demo benchmark live live-smoke interfaces replay-live check lint fuzz sbom pins requirements policy-lint coverage-matrix docs-counts workflow-lint ci-local package
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

check: lint test pins requirements policy-lint coverage-matrix docs-counts manifest presentation-check inventory keylogs content sequences
	$(PYTHON) -B -m compileall -q protocol_engine tools *.py

manifest:
	$(PYTHON) -B tools/build_manifest.py --check presentation/SOURCE.json

# Runs the presentation suite when the optional decryption extra is importable, and says so when it is not,
# instead of silently passing: the canonical CI job installs the extra and always runs it.
# Explicit dependency detection: the suite's own exit status is the target's exit status (a failing suite can
# never read as "skipped"); only a missing `cryptography` skips, and says so.
presentation-check:
	@if $(PYTHON) -c "import cryptography" 2>/dev/null; then \
	  $(MAKE) --no-print-directory presentation-test PYTHON=$(PYTHON); \
	else \
	  echo "presentation-check: skipped here (install .[decryption] to run it); CI runs it unconditionally"; \
	fi

docs-counts:
	$(PYTHON) -B tools/check_docs_counts.py

# Same checks the CI workflow runs, in one command, plus the extended fuzz pass.
ci-local: check fuzz sequences-extended
	$(PYTHON) -B analyze_pcap.py sample-expanded.pcap --events-only --sessions > /dev/null
	$(PYTHON) -B protodetect.py analyze sample-expanded.pcap --json --sessions | $(PYTHON) -B protodetect.py schema offline-row --validate /dev/stdin

# Build the sdist and wheel (dev tools installed) and check the wheel carries only the engine package.
package:
	$(PYTHON) -m build --sdist --wheel --outdir dist
	$(PYTHON) -B tools/check_wheel.py "dist/*.whl"

# Workflow lint with a locally installed actionlint (CI fetches a checksum-verified release).
workflow-lint:
	actionlint -no-color .github/workflows/*.yml

lint:
	ruff check .

pins:
	$(PYTHON) -B tools/check_action_pins.py .github/workflows

requirements:
	$(PYTHON) -B tools/check_security_requirements.py

fuzz:
	$(PYTHON) -B tools/fuzz_fixtures.py --iterations 2000

sbom:
	cyclonedx-py environment --output-format json --output-file sbom.cdx.json
	$(PYTHON) -B tools/sbom_summary.py sbom.cdx.json

inventory:
	python3 -B tools/check_inventory.py

keylogs:
	python3 -B tools/check_no_keylogs.py

content:
	python3 -B tools/check_content.py

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
