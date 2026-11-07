package appid

import (
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Structured unknown reasons (protocol_engine/unknown.py, D12).

var stages = map[string]string{"no-dispatch": "dispatch", "ambiguous": "dispatch", "profile-unsupported": "profile", "malformed": "profile",
	"budget": "budget", "no-payload": "lifecycle", "incomplete": "lifecycle", "no-handshake": "lifecycle", "midstream": "lifecycle", "invalidated": "integrity"}

var noDispatch = map[string]bool{"Prefix outside supported protocol families": true, "No supported datagram structure selected": true}

// DirectionFacts is what an inspector knows beyond its observation (resolved family, bytes received).
type DirectionFacts struct {
	ResolvedFamily string // "" for none
	BytesReceived  int
	Known          bool // false when no inspector exists (datagram observations)
}

func unknownCode(o *contracts.Observation, bytesReceived int) string {
	switch o.Status {
	case contracts.Invalidated:
		return "invalidated"
	case contracts.BudgetExhausted:
		return "budget"
	case contracts.Malformed:
		return "malformed"
	case contracts.Unknown:
		for _, e := range o.Evidence {
			if e.Field == "ambiguous_candidates" {
				return "ambiguous"
			}
		}
		if strings.HasPrefix(o.Reason, "Ambiguous") {
			return "ambiguous"
		}
		if noDispatch[o.Reason] {
			return "no-dispatch"
		}
		return "profile-unsupported"
	}
	if bytesReceived == 0 {
		return "no-payload"
	}
	return "incomplete"
}

// Explain ports unknown.explain; nil for an identification.
func Explain(o *contracts.Observation, facts DirectionFacts) map[string]interface{} {
	if o == nil || o.Status == contracts.Identified {
		return nil
	}
	candidate := ""
	bytesReceived := 1
	if facts.Known {
		candidate = facts.ResolvedFamily
		bytesReceived = facts.BytesReceived
	} else if o.Status == contracts.Detecting && o.Reason == "Waiting for stream prefix" {
		bytesReceived = 0
	}
	code := unknownCode(o, bytesReceived)
	out := map[string]interface{}{"code": code, "stage": stages[code], "family": nil, "detail": o.Reason}
	profileCode := code == "profile-unsupported" || code == "malformed" || code == "budget"
	if profileCode && candidate != "" && candidate != "unknown" && candidate != "text" && candidate != "git_text" && candidate != "tpkt" {
		out["family"] = candidate
	}
	if code == "ambiguous" {
		for _, e := range o.Evidence {
			if e.Field == "ambiguous_candidates" {
				out["candidates"] = strings.Split(e.Value, ",")
			}
		}
	}
	if out["family"] == nil && profileCode {
		for _, e := range o.Evidence {
			if e.Field == "candidate_hint" {
				out["family"] = e.Value
				break
			}
		}
	}
	return out
}

// SessionUnknown ports unknown.session_unknown; nil for identified/correlated verdicts or when nothing applies.
func SessionUnknown(v *Verdict, client, server *contracts.Observation, clientFacts, serverFacts DirectionFacts, mode string, handshake bool) map[string]interface{} {
	if v.Status == "identified" || v.Status == "correlated" {
		return nil
	}
	out := map[string]interface{}{}
	var first interface{}
	if len(v.Reasons) > 0 {
		first = v.Reasons[0]
	}
	if !handshake && mode == "handshake" {
		out["session"] = map[string]interface{}{"code": "no-handshake", "stage": "lifecycle", "family": nil, "detail": first}
	} else if mode == "midstream" && v.Status == "midstream" {
		out["session"] = map[string]interface{}{"code": "midstream", "stage": "lifecycle", "family": nil, "detail": first}
	}
	if item := Explain(client, clientFacts); item != nil {
		out["client"] = item
	}
	if item := Explain(server, serverFacts); item != nil {
		out["server"] = item
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
