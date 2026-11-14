package detector

// Direction is one side of a flow.
type Direction uint8

const (
	// ClientToServer carries the bytes the connecting client sends.
	ClientToServer Direction = iota
	// ServerToClient carries the bytes the server sends back.
	ServerToClient
)

var allDirections = []Direction{ClientToServer, ServerToClient}

// AllDirections lists every Direction.
func AllDirections() []Direction { return append([]Direction(nil), allDirections...) }

// Valid reports whether d is a known direction.
func (d Direction) Valid() bool { return d == ClientToServer || d == ServerToClient }

func (d Direction) String() string {
	switch d {
	case ClientToServer:
		return "client_to_server"
	case ServerToClient:
		return "server_to_client"
	}
	return "invalid"
}

// Outcome is what one direction's observation amounts to. It is a closed vocabulary; only
// OutcomeIdentified carries an identification, and no outcome is a permission.
type Outcome string

const (
	// OutcomeDetecting: more bytes are needed.
	OutcomeDetecting Outcome = "detecting"
	// OutcomeIdentified: the stream satisfied a supported family's structural profile.
	OutcomeIdentified Outcome = "identified"
	// OutcomeUnknown: the prefix is outside the supported families, or a documented exclusion was met.
	OutcomeUnknown Outcome = "unknown"
	// OutcomeMalformed: the bytes violate the selected family's structure.
	OutcomeMalformed Outcome = "malformed"
	// OutcomeIncomplete: the direction ended, expired or was closed before a decision.
	OutcomeIncomplete Outcome = "incomplete"
	// OutcomeBudgetExhausted: a configured byte or call budget ended inspection.
	OutcomeBudgetExhausted Outcome = "budget_exhausted"
	// OutcomeInvalidated: a previous result was retracted.
	OutcomeInvalidated Outcome = "invalidated"
	// OutcomeUnsupported: the selected family or path is not available in this backend.
	OutcomeUnsupported Outcome = "unsupported"
	// OutcomeOutsideProfile: the prefix selected, or the stream resolved to, a family the engine's profile
	// does not allow. Inspection stops there, usually BEFORE that family's structure is validated, so this
	// is not an identification of the named family: a host must never treat it as a positive match.
	OutcomeOutsideProfile Outcome = "outside_profile"
	// OutcomeFailed: the engine failed (a recovered panic); the flow is quarantined.
	OutcomeFailed Outcome = "failed"
)

var allOutcomes = []Outcome{OutcomeDetecting, OutcomeIdentified, OutcomeUnknown, OutcomeMalformed, OutcomeIncomplete,
	OutcomeBudgetExhausted, OutcomeInvalidated, OutcomeUnsupported, OutcomeOutsideProfile, OutcomeFailed}

// AllOutcomes lists every Outcome.
func AllOutcomes() []Outcome { return append([]Outcome(nil), allOutcomes...) }

// Valid reports whether o is in the closed vocabulary.
func (o Outcome) Valid() bool { return contains(allOutcomes, o) }

func (o Outcome) String() string { return string(o) }

// Reason says which layer produced an outcome. It is a closed vocabulary; the engine's own sentence, when
// there is one, is in Detail.
type Reason string

const (
	// ReasonNone: no decision yet.
	ReasonNone Reason = "none"
	// ReasonEngine: the stream inspector decided; Detail holds its reason sentence.
	ReasonEngine Reason = "engine"
	// ReasonNotPorted: the selected family or an option is not ported to this backend.
	ReasonNotPorted Reason = "not_ported"
	// ReasonOutsideProfile: the family is not in the engine's profile.
	ReasonOutsideProfile Reason = "outside_profile"
	// ReasonEnded: the host ended the direction (EndDirection).
	ReasonEnded Reason = "ended"
	// ReasonExpired: the host expired the observation window (Expire).
	ReasonExpired Reason = "expired"
	// ReasonClosed: the host closed the flow before the direction decided.
	ReasonClosed Reason = "closed"
	// ReasonPanic: the engine panicked; the flow is quarantined.
	ReasonPanic Reason = "panic"
)

var allReasons = []Reason{ReasonNone, ReasonEngine, ReasonNotPorted, ReasonOutsideProfile, ReasonEnded, ReasonExpired,
	ReasonClosed, ReasonPanic}

// AllReasons lists every Reason.
func AllReasons() []Reason { return append([]Reason(nil), allReasons...) }

// Valid reports whether r is in the closed vocabulary.
func (r Reason) Valid() bool { return contains(allReasons, r) }

func (r Reason) String() string { return string(r) }

// EndCause is why the host ended a direction.
type EndCause string

const (
	// EndEOF: the peer finished sending (FIN or a clean EOF).
	EndEOF EndCause = "eof"
	// EndReset: the connection was reset or failed.
	EndReset EndCause = "reset"
	// EndAborted: the host stopped relaying for its own reasons (policy, shutdown, timeout).
	EndAborted EndCause = "aborted"
)

var allEndCauses = []EndCause{EndEOF, EndReset, EndAborted}

// AllEndCauses lists every EndCause.
func AllEndCauses() []EndCause { return append([]EndCause(nil), allEndCauses...) }

// Valid reports whether c is in the closed vocabulary.
func (c EndCause) Valid() bool { return contains(allEndCauses, c) }

func (c EndCause) String() string { return string(c) }

func (c EndCause) sentence() string {
	switch c {
	case EndEOF:
		return "Direction ended before identification"
	case EndReset:
		return "Connection reset before identification"
	}
	return "Observation aborted by the host before identification"
}

// EvidenceClass says how an evidence value may be handled.
type EvidenceClass string

const (
	// ClassCategorical: the value is drawn from a protocol or engine vocabulary (a family name, a TLS
	// version, a key-exchange class). Still a record field, not a metric label.
	ClassCategorical EvidenceClass = "categorical"
	// ClassAsserted: free text a peer chose (an offered ALPN identifier, a software banner, an HTTP
	// token). Bounded in length; record field only.
	ClassAsserted EvidenceClass = "asserted"
	// ClassHostname: a host or server name a peer asserted. The host must pass it through its
	// destination pseudonymizer before it leaves the process.
	ClassHostname EvidenceClass = "hostname"
	// ClassWithheld: a field this package has not classified; its value is replaced by "".
	ClassWithheld EvidenceClass = "withheld"
)

var allEvidenceClasses = []EvidenceClass{ClassCategorical, ClassAsserted, ClassHostname, ClassWithheld}

// AllEvidenceClasses lists every EvidenceClass.
func AllEvidenceClasses() []EvidenceClass { return append([]EvidenceClass(nil), allEvidenceClasses...) }

// Valid reports whether c is in the closed vocabulary.
func (c EvidenceClass) Valid() bool { return contains(allEvidenceClasses, c) }

func (c EvidenceClass) String() string { return string(c) }

func contains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
