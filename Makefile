.PHONY: test demo protocols apps risks sessions proxy-demo benchmark live live-smoke interfaces replay-live check lint fuzz sbom pins requirements policy-lint coverage-matrix docs-counts workflow-lint ci-local package pin-drift
PYTHON ?= python3
INTERFACE ?= en0
DURATION ?= 60

test:
	$(PYTHON) -B -m unittest discover -v

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

check: lint test pins requirements policy-lint coverage-matrix docs-counts
	$(PYTHON) -B -m compileall -q protocol_engine tools *.py

docs-counts:
	$(PYTHON) -B tools/check_docs_counts.py

# Same checks the CI workflow runs, in one command, plus the extended fuzz pass.
ci-local: check fuzz
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

# Weekly drift gate run locally: every pinned action SHA must still be the commit its tag comment names (network).
pin-drift:
	$(PYTHON) -B tools/check_pin_drift.py --self-test
	$(PYTHON) -B tools/check_pin_drift.py .github/workflows
