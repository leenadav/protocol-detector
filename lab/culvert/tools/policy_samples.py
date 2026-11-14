"""Send the protocol-restriction examples through one build: TLS (allowed) and SSH, junk and pipelined HTTP (blocked)
to the TLS-only host, and SSH to the monitor-mode host."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import runner  # noqa: E402

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18083
for name, fn, _ in runner.POLICY_SCENARIOS:
    seen = fn(port)
    print(name, "| delivered:", seen.get("delivered"), "| origin received client bytes:", seen.get("origin_received_client_bytes"))
