# ADR 0001 — Byte ownership, lifetimes and resource bounds in the Go implementation

Status: accepted for M2 (2026-11-07). Revisit when concurrency is introduced (M9).

## Context

The Python reference copies freely (bytes objects are immutable) and bounds work per direction
(`Config`) and per adapter (`byte_limit`, `max_connections`, event-log length). A Go port that slices
into caller buffers or pools memory can leak earlier payloads, alias mutated input, or retain more than
its stated limits. The plan (§4, M2) requires an enforceable ownership contract and limits with a stated
scope before any parser is translated.

## Decision

1. **Input slices belong to the caller.** Every API that takes `[]byte` (`Append`, future `Feed`,
   `Inspect`, decoders) may read it only for the duration of the call. The caller may reuse the slice
   the moment the call returns. Tests mutate the input after the call and assert the component's state
   did not change (`buffer.TestInputIsCopiedNotRetained`; the same test is required for every parser
   that retains anything).
2. **Retained bytes are copied into owned memory** under a `buffer.Bounded` (per direction) that charges
   a `buffer.Account` (aggregate, per flow table / capture / worker). There is no third place to keep
   bytes. Discard and Release zero the bytes they give up, so a later consumer of the backing array can
   never read an earlier payload.
3. **Views are transient.** `Bytes()` and any parser-facing slice are valid only until the next
   mutating call on the same buffer; they are never stored in an observation, event or error. Evidence
   values are fresh strings bounded by the profile's field limits.
4. **Output events are immutable values.** `contracts.Event` and `contracts.Observation` are passed by
   value; slices inside them (`OfferedALPN`, `Evidence`) are created once by the publisher and never
   appended to afterwards. Consumers may keep events indefinitely without pinning engine memory.
5. **Every limit states its scope.** `errs.Exceeded(scope, limit, detail)` is the only way to report a
   budget; the scope is one of direction, flow, capture, worker, process. A per-direction limit is
   never the only limit: the owner of a flow table also holds an `Account`. Budget exhaustion yields a
   `budget_exhausted` observation or a `budget` error, never a positive verdict (C8).
6. **No pooling in M2–M4.** `sync.Pool` or slab allocators are introduced only after a profile shows
   allocation cost on the measured workloads (M9), and only with the zero-on-release rule above.
7. **Single-threaded by construction until M9.** No goroutine per packet, no channels in the engine or
   the adapters; the future per-flow owner model (one owner per stable flow identity, bounded queues,
   immutable shared content) is decided in a later ADR with measurements, not assumed now.
8. **Errors carry no input.** `errs.Error.Detail` is a fixed sentence or a bounded identifier; payload
   bytes, hostnames and key material never enter errors, logs, metrics labels or fixtures (C17).
9. **Time is injected.** Components take a `clock.Clock`; engine and adapters never read the host clock,
   so replay and the differential harness are deterministic.

## Consequences

- One extra copy per retained byte compared with slicing into capture buffers. Accepted: correctness and
  isolation first; M9 measures the cost against the Python baseline on the same host.
- Parsers must be written against transient views and cannot cache sub-slices across calls; this is a
  design constraint for M4/M5 reviewers to check.
- The aggregate account makes "many short / half-open flows" workloads (M3 exit gate) testable: retained
  memory is a number the tests read, not an inference from RSS.
