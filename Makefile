.PHONY: test demo protocols apps risks sessions proxy-demo benchmark live live-smoke interfaces replay-live check lint fuzz sbom pins requirements policy-lint coverage-matrix
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

check: lint test pins requirements policy-lint coverage-matrix
	$(PYTHON) -B -m compileall -q protocol_engine tools *.py

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
