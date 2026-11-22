"""PRO-189 (Codex PRO-12, P2): the Python reference with the unknown-buffer budget fix modelled, for the harnesses.

After dispatch fails, the reference's unknown-payload buffer waits for unknown_limit bytes before the stream is
final. When max_bytes is the smaller limit, the budget runs out first and the stream stays "detecting" until it
closes, although the docstring of Inspector._unknown_observation says a miss waits for "more bytes, the budget
or EOF". Go finalizes when the budget is spent (go/internal/engine/inspector.go, unknownFull). The reference is
frozen, so a harness that sees a mismatch reruns it under `modelled()`, which adds exactly that condition, and
accepts the case only when Go then matches it exactly. Nothing else about the reference changes.
"""

import contextlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol_engine.engine import Inspector  # noqa: E402
from protocol_engine.model import Config  # noqa: E402

LABEL = "PRO-189"


@contextlib.contextmanager
def modelled():
    """The reference, with a spent byte budget finalizing the unknown buffer (Go's unknownFull)."""
    original = Inspector._unknown_observation

    def patched(self, reason, final=True, data=None):
        if (not final and data is None and self._unknown is not None
                and self.metrics.bytes_inspected >= self.config.max_bytes):
            final = True
        return original(self, reason, final, data)

    Inspector._unknown_observation = patched
    try:
        yield
    finally:
        Inspector._unknown_observation = original


def self_test():
    """The model changes only the budget case: 64 of max_bytes 64 against a 512-byte buffer becomes final."""
    payload = bytes([0xDE, 0xAD, 0x00, 0x7F]) * 40

    def statuses(config, model):
        with modelled() if model else contextlib.nullcontext():
            inspector = Inspector(config=config)
            events = [event for chunk in (payload[:30], payload[30:]) for event in inspector.feed(chunk)]
        return [event.observation.status for event in events]

    small = Config(max_bytes=64, heuristics=True, heuristic_bytes=512)
    large = Config(max_bytes=4096, heuristics=True, heuristic_bytes=64)
    if statuses(small, False) != []:
        raise AssertionError("the reference no longer waits on a spent budget; the PRO-189 model is stale")
    if statuses(small, True) != ["unknown"]:
        raise AssertionError("the PRO-189 model does not finalize a spent budget")
    if statuses(large, True) != statuses(large, False) or statuses(large, False) != ["unknown"]:
        raise AssertionError("the PRO-189 model changes a buffer that fills before the budget")
    if Inspector._unknown_observation.__name__ != "_unknown_observation":
        raise AssertionError("the PRO-189 model leaked out of its context")


if __name__ == "__main__":
    self_test()
    print("pro189 model: ok")
