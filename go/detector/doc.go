// Package detector is the public, in-process API of the protocol detector for a host that already owns
// ordered byte streams, such as a forward proxy relaying a CONNECT tunnel (working plan
// docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md, work items #8–#13).
//
// Ownership. The host owns sockets, TLS, policy, timeouts and forwarding. This package performs no I/O,
// starts no goroutines, reads no files and never changes a deadline. It observes bytes the host has
// already read; it never tells the host how many bytes to forward, and nothing it returns is a
// permission. Every outcome other than OutcomeIdentified means "no identification"; none of them is an
// allow.
//
// Shape. An Engine is built once from a validated Config (an immutable profile of allowed families and
// per-direction budgets) and admits flows up to Config.MaxFlows. A Flow holds one inspector per direction
// (client-to-server and server-to-client), so server-first protocols progress without waiting for the
// client. Feed, EndDirection, Expire, Snapshot and Close may be called from different goroutines; a
// flow-local mutex serializes them, and no lock is shared between flows. Input slices are borrowed for
// the duration of a call; anything retained is copied by the engine and bounded by the budgets.
//
// Failure containment. A panic inside the engine during any call is recovered at this boundary: the
// flow is quarantined (its inspectors are released and never re-entered), the call returns
// ErrQuarantined and the flow's outcome becomes OutcomeFailed with ReasonPanic. The panic value is not
// kept, because it may contain input bytes. Fatal runtime errors (out of memory, concurrent map writes)
// cannot be recovered by any Go code and are outside this contract.
//
// Results. Snapshot returns a detached copy that shares no memory with the engine. Outcomes, reasons,
// directions and evidence classes are closed vocabularies with All/Valid/String; they may be used as
// metric labels. Detail strings, evidence values and hostnames are record fields only, never labels.
// Hostname-class evidence (TLS SNI, HTTP Host, SMTP client identity, SOCKS target) is typed so the host
// can pseudonymize it at one point. Values of evidence fields this package has not classified are
// withheld rather than passed through.
//
// Scope of this first slice. Results come from the stream inspector only: no hints, no content-pack
// application attribution, no TLS fingerprints or certificates, and no host-opened shift phases. The
// family that identified the stream's first message decides the profile check; a phase a parser opens
// itself (for example after an HTTP upgrade) is reported inside the same observation.
package detector
