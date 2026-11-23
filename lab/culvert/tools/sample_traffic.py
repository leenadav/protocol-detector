"""Send one of each protocol scenario through one build (default D) so the newest log rows are varied."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import runner  # noqa: E402  (the scenario functions live in the runner)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18083
for name in ("s_junk", "s_postgres", "s_silent", "s_fragmented", "s_pipelined", "s_http_tunnel", "s_smtp", "s_ssh", "s_tls"):
    ok, _ = getattr(runner, name)(port)
    print(name, "ok" if ok else "FAILED")
