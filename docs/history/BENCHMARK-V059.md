# Benchmark v0.59: SMB transport protection posture

Local CPU work, not production SWG latency. Baseline is the engine head
c353de2 (v0.58 plus the AGENTS.md coordination update) in a worktree. The A/B
flows of `benchmark_ab.py` do not include SMB; the changed path is the SMB2/3
NEGOTIATE response, measured directly (fresh Inspector, best of five runs of
3000):

| Message | v0.58 (us) | v0.59 (us) |
|---|---|---|
| SMB 3.0.2 NEGOTIATE response (`SMB2_RESPONSE`) | 26.8 | 28.5 |
| SMB 3.1.1 NEGOTIATE response with preauth and encryption contexts (`SMB311_RESPONSE`) | 33.6 | 39.6 |

The additions are a capability-bit test or one context-table lookup per
response and two or three more evidence rows; the context walk keeps its
existing budget (at most 128 contexts within the frame).
