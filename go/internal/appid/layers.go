package appid

import (
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// DecryptionNote is layers.DECRYPTION_NOTE.
const DecryptionNote = "Plaintext was authenticated with supplied secrets (record AEAD); this is not peer identity or product verification."

// LayeredView is layered_view for a session without a decoder: the wire verdict the caller computed is the
// outer layer unless an observation carries decrypted evidence.
func LayeredView(pack *content.Pack, transport string, client, server *contracts.Observation, verdict *Verdict, captureQuality string) map[string]interface{} {
	view, _ := LayeredViewWith(pack, transport, client, server, verdict, 0, false, Bytes{}, Bytes{}, nil, captureQuality)
	return view
}

// splitObservation is layers.split_observation: the wire part and the decrypted part of one direction, by
// evidence provenance; inner is nil without decrypted evidence.
func splitObservation(o *contracts.Observation) (outer, inner *contracts.Observation) {
	if o == nil {
		return nil, nil
	}
	var innerEvidence, outerEvidence []contracts.Evidence
	for _, e := range o.Evidence {
		if strings.HasPrefix(e.Source, "decrypted") {
			innerEvidence = append(innerEvidence, e)
		} else {
			outerEvidence = append(outerEvidence, e)
		}
	}
	if len(innerEvidence) == 0 {
		return o, nil
	}
	has := func(list []contracts.Evidence, field string) bool {
		for _, e := range list {
			if e.Field == field {
				return true
			}
		}
		return false
	}
	in, out := *o, *o
	in.Encryption, in.OfferedALPN, in.Evidence = nil, nil, innerEvidence
	if !has(innerEvidence, "hostname") {
		in.Hostname = nil
	}
	if !has(innerEvidence, "application") {
		in.Application = nil
	}
	out.ApplicationProtocol, out.Evidence, out.Hostname = nil, outerEvidence, nil
	for _, e := range outerEvidence {
		if e.Field == "hostname" {
			value := e.Value
			out.Hostname = &value
			break
		}
	}
	if !has(outerEvidence, "application") {
		out.Application = nil
	}
	out.Reason = "TLS envelope (plaintext classified separately)"
	return &out, &in
}

func verdictProtocol(v *Verdict) *string {
	if v == nil {
		return nil
	}
	if v.ClientProtocol != nil && *v.ClientProtocol != "" {
		return v.ClientProtocol
	}
	return v.ServerProtocol
}

// LayeredViewWith ports protocol_adapters/layers.layered_view: the layered view of one session from its two
// directional observations (merged or wire-only) and the effective verdict it chose. verdict is the wire
// verdict when the caller has one (nil: computed here); decryption is the decoder's metadata (nil: no decoder).
func LayeredViewWith(pack *content.Pack, transport string, client, server *contracts.Observation, verdict *Verdict, serverPort int, hasPort bool,
	clientBytes, serverBytes Bytes, decryption map[string]interface{}, captureQuality string) (map[string]interface{}, *Verdict) {
	outerClient, innerClient := splitObservation(client)
	outerServer, innerServer := splitObservation(server)
	outer := verdict
	if verdict == nil || innerClient != nil || innerServer != nil {
		outer = SessionVerdict(pack, outerClient, outerServer, transport, serverPort, hasPort, clientBytes, serverBytes, true)
	}
	var inner *Verdict
	if innerClient != nil || innerServer != nil {
		inner = SessionVerdict(pack, innerClient, innerServer, transport, serverPort, hasPort, clientBytes, serverBytes, true)
	}
	decryptionOK := true
	if decryption != nil {
		state, _ := decryption["state"].(string)
		decryptionOK = state == "decrypting" || state == "complete"
	}
	innerIdentified := inner != nil && inner.Identified(pack) && decryptionOK
	effective := outer
	if innerIdentified {
		effective = inner
	}
	var encryption *string
	for _, o := range []*contracts.Observation{outerClient, outerServer} {
		if o != nil && o.Encryption != nil && *o.Encryption != "" {
			encryption = o.Encryption
			break
		}
	}
	attr := effective.Attribution
	if attr == nil {
		attr = outer.Attribution
	}
	if attr == nil && inner != nil {
		attr = inner.Attribution
	}
	var activityValue interface{}
	if innerIdentified {
		activityValue = "authenticated-plaintext"
	} else if attr != nil {
		activityValue = attr["activity"]
	}
	outerProtocol := verdictProtocol(outer)
	var innerProtocol *string
	if innerIdentified {
		innerProtocol = verdictProtocol(inner)
	}
	var chain []string
	add := func(l *string) {
		if l != nil && *l != "" && !containsString(chain, *l) {
			chain = append(chain, *l)
		}
	}
	add(encryption)
	if outerProtocol != nil && (encryption == nil || *outerProtocol != *encryption) {
		add(outerProtocol)
	}
	add(innerProtocol)
	if effective.Identified(pack) {
		app := effective.App
		add(&app)
	}
	if chain == nil {
		chain = []string{}
	}
	var encryptionView interface{}
	if encryption != nil {
		alpn := map[string]bool{}
		asserted := false
		for _, o := range []*contracts.Observation{outerClient, outerServer} {
			if o == nil {
				continue
			}
			for _, a := range o.OfferedALPN {
				alpn[a] = true
			}
			for _, e := range o.Evidence {
				if e.Field == "hostname" {
					asserted = true
				}
			}
		}
		var names []string
		for a := range alpn {
			names = append(names, a)
		}
		sort.Strings(names)
		if names == nil {
			names = []string{}
		}
		var version interface{}
		if decryption != nil {
			version = decryption["version"]
		}
		encryptionView = map[string]interface{}{"protocol": *encryption, "offered_alpn": names, "server_name_asserted": asserted, "version": version}
	}
	outerProtoValue := outerProtocol
	if outerProtoValue == nil || *outerProtoValue == "" {
		outerProtoValue = encryption
	}
	var provider, affiliation interface{}
	if attr != nil {
		provider, affiliation = attr["provider"], attr["kind"]
	}
	var innerView, decryptionView interface{}
	if inner != nil {
		innerView = map[string]interface{}{"protocol": verdictProtocol(inner), "app": inner.App, "status": inner.Status,
			"source": "decrypted", "authenticated": decryptionOK}
	}
	if decryption != nil {
		decryptionView = map[string]interface{}{"state": decryption["state"], "reason_code": decryption["reason_code"],
			"authenticated_records": decryption["authenticated_records"]}
	}
	basis := identityBasis(pack, effective, outerClient, outerServer)
	if innerIdentified {
		basis = "authenticated_plaintext"
	}
	view := map[string]interface{}{
		"version":    1,
		"transport":  transport,
		"outer":      map[string]interface{}{"protocol": outerProtoValue, "app": outer.App, "status": outer.Status},
		"encryption": encryptionView,
		"inner":      innerView,
		"application": map[string]interface{}{"name": effective.App, "category": effective.Category, "status": effective.Status,
			"basis": basis, "provider": provider, "affiliation": affiliation, "activity": activityValue},
		"decryption":      decryptionView,
		"capture_quality": captureQuality,
		"chain":           chain,
		"claims":          claims(outerClient, outerServer),
	}
	if decryption != nil {
		view["note"] = DecryptionNote
	}
	return view, effective
}

func identityBasis(pack *content.Pack, v *Verdict, observations ...*contracts.Observation) string {
	if v == nil || !v.Identified(pack) {
		return "none"
	}
	if containsString(v.Reasons, HostReason) {
		return "client_assertion"
	}
	if v.BaseApp != nil {
		return "configured_rule"
	}
	for _, o := range observations {
		if o == nil {
			continue
		}
		for _, e := range o.Evidence {
			if e.Strength == "configured_mapping" || e.Strength == "configured_signature" {
				return "configured_rule"
			}
		}
	}
	return "structural"
}

func claims(observations ...*contracts.Observation) []map[string]interface{} {
	seen := map[[3]string]bool{}
	out := []map[string]interface{}{}
	for _, o := range observations {
		if o == nil {
			continue
		}
		for _, e := range o.Evidence {
			if e.Strength == "asserted" || e.Strength == "offered" || e.Strength == "derived" {
				key := [3]string{e.Field, e.Source, e.Strength}
				if !seen[key] {
					seen[key] = true
					out = append(out, map[string]interface{}{"field": e.Field, "source": e.Source, "strength": e.Strength})
				}
			}
		}
	}
	return out
}
