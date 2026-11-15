// Package appid ports protocol_engine/appid.py: one or two directional observations become a session
// verdict (a catalog application or a session outcome) with category, risk and port-usage metadata.
// It adds no parsing. Custom signatures and RuleIndex mappings are not ported (the Go engine never sets
// Observation.Application), so the configured-rule branches are absent by construction.
package appid

import (
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Verdict mirrors appid.Verdict.
type Verdict struct {
	App             string
	Category        string
	Subcategory     string
	Technology      string
	Risk            int
	Characteristics []string
	BaseApp         *string
	ImplicitlyUses  []string
	PortUsage       string
	Status          string
	ClientProtocol  *string
	ServerProtocol  *string
	Encryption      *string
	Reasons         []string
	ShiftedFrom     *string
	Risks           []string
	Attribution     map[string]interface{}
}

// Identified reports whether the verdict names an application rather than an outcome.
func (v *Verdict) Identified(pack *content.Pack) bool { return !pack.Outcomes[v.App] }

// Reason sentences shared with Python.
const (
	HostReason     = "Application named by the built-in server-name catalog from a client-asserted server name (not authenticated)"
	webFrontReason = "Server name is the provider's public web presence (client-asserted); no service activity is asserted"
	activityReason = "Provider affiliation comes from the client-asserted server name; the service's own activity was not observed"
)

var unmatched = map[contracts.Status]bool{contracts.Unknown: true, contracts.Malformed: true, contracts.BudgetExhausted: true}

var webdavMethods = map[string]bool{"PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true, "MOVE": true, "LOCK": true, "UNLOCK": true, "REPORT": true, "SEARCH": true}
var rpcHTTPMethods = map[string]bool{"RPC_CONNECT": true, "RPC_IN_DATA": true, "RPC_OUT_DATA": true}
var contentApplications = map[string]string{"ipp": "ipp", "ocsp": "ocsp", "soap": "soap"}
var rpcApplications = map[string]string{"portmap": "portmapper", "nfs": "nfs", "mount": "nfs", "nlm": "nfs", "nsm": "nfs", "nfs-acl": "nfs"}
var hostCarriers = map[string]bool{"ssl": true, "quic": true, "web-browsing": true}

func label(o *contracts.Observation) *string {
	if o.ApplicationProtocol != nil {
		return o.ApplicationProtocol
	}
	return o.Encryption
}

func evidence(o *contracts.Observation, field string) (string, bool) {
	for _, e := range o.Evidence {
		if e.Field == field {
			return e.Value, true
		}
	}
	return "", false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func shiftedFrom(pack *content.Pack, o *contracts.Observation) *string {
	carrier, ok := evidence(o, "shift_from")
	if !ok {
		return nil
	}
	if boundary, _ := evidence(o, "shift"); boundary == "http-connect" {
		s := "http-proxy"
		return &s
	}
	name := pack.ApplicationName(carrier, "")
	if name == "" {
		name = carrier
	}
	return &name
}

func candidates(o *contracts.Observation) map[string]bool {
	if o.Status != contracts.Unknown {
		return nil
	}
	if value, ok := evidence(o, "ambiguous_candidates"); ok {
		out := map[string]bool{}
		for _, c := range strings.Split(value, ",") {
			out[c] = true
		}
		return out
	}
	return nil
}

func webApplication(o *contracts.Observation) string {
	method, _ := evidence(o, "http_method")
	if method == "" {
		method, _ = evidence(o, "http2_method")
	}
	if method == "CONNECT" {
		if p, _ := evidence(o, "http2_protocol"); p == "websocket" {
			return "websocket"
		}
		return "http-proxy"
	}
	if webdavMethods[method] {
		return "webdav"
	}
	if rpcHTTPMethods[method] {
		return "ms-rpc-over-http"
	}
	http2Content, _ := evidence(o, "http2_content_type")
	contentType := http2Content
	if contentType == "" {
		contentType, _ = evidence(o, "http_content_type")
	}
	if method == "POST" && (http2Content == "grpc" || contentType == "grpc-web") {
		return "grpc"
	}
	accept2, _ := evidence(o, "http2_accept")
	accept1, _ := evidence(o, "http_accept")
	if contentType == "dns" || accept2 == "dns" || accept1 == "dns" {
		return "dns-over-https"
	}
	if app, ok := contentApplications[contentType]; ok && (method == "" || method == "POST" || contentType == "ocsp") {
		return app
	}
	return "web-browsing"
}

func application(pack *content.Pack, o *contracts.Observation, transport string) *content.Application {
	base := pack.ApplicationName(deref(o.ApplicationProtocol), deref(o.Encryption))
	switch base {
	case "web-browsing":
		base = webApplication(o)
	case "sun-rpc":
		if program, ok := evidence(o, "rpc_program"); ok {
			if mapped, ok := rpcApplications[program]; ok {
				base = mapped
			}
		}
	case "dns":
		if qt, _ := evidence(o, "dns_query_type"); qt == "nb" || qt == "nbstat" {
			base = "netbios-ns"
		}
	case "stun":
		if method, ok := evidence(o, "stun_method"); ok && method != "binding" {
			base = "turn"
		}
	}
	if o.Application != nil {
		if base == "" {
			base = "unknown-" + transport
		}
		return pack.CustomApplication(*o.Application, base)
	}
	if base == "" {
		return nil
	}
	if hostCarriers[base] && o.Hostname != nil && *o.Hostname != "" {
		if name := pack.ApplicationForHost(*o.Hostname); name != "" {
			if ech, _ := evidence(o, "tls_ech"); ech != "outer" {
				return pack.HostApplication(name, base)
			}
		}
	}
	return pack.Applications[base]
}

func portUsage(app *content.Application, transport string, serverPort int, hasPort bool) string {
	if !hasPort || !app.HasPorts() {
		return "unknown"
	}
	if app.UsesPort(transport, serverPort) {
		return "standard"
	}
	return "nonstandard"
}

func activity(o *contracts.Observation) string {
	if o == nil {
		return "unobserved"
	}
	for _, e := range o.Evidence {
		if strings.HasPrefix(e.Source, "decrypted") && e.Field == "application_protocol" {
			return "authenticated-plaintext"
		}
	}
	if o.ApplicationProtocol != nil && strings.HasPrefix(*o.ApplicationProtocol, "http") && o.Encryption == nil {
		return "http-request"
	}
	return "unobserved"
}

func attribution(pack *content.Pack, o *contracts.Observation) map[string]interface{} {
	if o == nil || o.Hostname == nil || *o.Hostname == "" {
		return nil
	}
	if ech, _ := evidence(o, "tls_ech"); ech == "outer" {
		return nil
	}
	provider, kind, ok := pack.AttributionForHost(*o.Hostname)
	if !ok {
		return nil
	}
	return map[string]interface{}{"provider": provider, "kind": kind, "family": pack.Applications[provider].Subcategory,
		"activity": activity(o), "asserted_by": "client-server-name"}
}

func build(pack *content.Pack, app *content.Application, transport string, serverPort int, hasPort bool, status string,
	client, server *contracts.Observation, reasons []string, shifted *string, attr map[string]interface{}) *Verdict {
	implicitly := append([]string{}, app.ImplicitlyUses...)
	usage := portUsage(app, transport, serverPort, hasPort)
	if shifted != nil && *shifted != app.Name {
		if !containsString(implicitly, *shifted) {
			implicitly = append(implicitly, *shifted)
		}
		if carrier, ok := pack.Applications[*shifted]; usage != "standard" && ok {
			if portUsage(carrier, transport, serverPort, hasPort) == "standard" {
				usage = "standard"
			}
		}
	}
	v := &Verdict{App: app.Name, Category: app.Category, Subcategory: app.Subcategory, Technology: app.Technology, Risk: app.Risk,
		Characteristics: append([]string{}, app.Characteristics...), BaseApp: app.Container, ImplicitlyUses: implicitly, PortUsage: usage,
		Status: status, Reasons: reasons, ShiftedFrom: shifted, Risks: []string{}, Attribution: attr}
	if client != nil && client.Status == contracts.Identified {
		v.ClientProtocol = label(client)
	}
	if server != nil && server.Status == contracts.Identified {
		v.ServerProtocol = label(server)
	}
	if client != nil && client.Encryption != nil {
		v.Encryption = client.Encryption
	} else if server != nil && server.Encryption != nil {
		v.Encryption = server.Encryption
	}
	return v
}

func outcome(pack *content.Pack, name, status string, reasons []string) *Verdict {
	app := pack.Applications[name]
	return &Verdict{App: name, Category: app.Category, Subcategory: app.Subcategory, Technology: app.Technology, Risk: app.Risk,
		Characteristics: append([]string{}, app.Characteristics...), ImplicitlyUses: []string{}, PortUsage: "unknown", Status: status,
		Reasons: reasons, Risks: []string{}}
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Bytes is an optional byte count (Python None vs int).
type Bytes struct {
	N     int
	Known bool
}

// SessionVerdict ports appid.session_verdict including flow risks.
func SessionVerdict(pack *content.Pack, client, server *contracts.Observation, transport string, serverPort int, hasPort bool,
	clientBytes, serverBytes Bytes, handshakeComplete bool) *Verdict {
	v := sessionVerdict(pack, client, server, transport, serverPort, hasPort, clientBytes, serverBytes, handshakeComplete)
	v.Risks = FlowRisks(v, client, server)
	return v
}

func sessionVerdict(pack *content.Pack, client, server *contracts.Observation, transport string, serverPort int, hasPort bool,
	clientBytes, serverBytes Bytes, handshakeComplete bool) *Verdict {
	unknownName := "unknown-" + transport
	var reasons []string
	if !handshakeComplete {
		return outcome(pack, "incomplete", "no_handshake", []string{"Transport handshake not completed before tracking ended"})
	}
	var identified []*contracts.Observation
	for _, o := range []*contracts.Observation{client, server} {
		if o != nil && o.Status == contracts.Identified {
			identified = append(identified, o)
		}
	}
	if len(identified) > 0 {
		chosen := identified[0]
		app := application(pack, chosen, transport)
		if app == nil {
			reasons = append(reasons, "Identified protocol has no catalog entry: "+pyStr(label(chosen)))
			return outcome(pack, unknownName, string(chosen.Status), reasons)
		}
		if len(identified) == 2 {
			other := application(pack, identified[1], transport)
			if other != nil && other.Name != app.Name && !containsString(app.ImplicitlyUses, other.Name) {
				reasons = append(reasons, "Server direction identified as "+other.Name)
			}
		}
		reasons = append(reasons, chosen.Reason)
		attr := attribution(pack, chosen)
		if _, hostNamed := pack.AppDomains[app.Name]; hostNamed && app.Container != nil {
			reasons = append(reasons, HostReason)
			if attr != nil && attr["activity"] == "unobserved" {
				reasons = append(reasons, activityReason)
			}
		} else if attr != nil && attr["kind"] == "provider-web" {
			reasons = append(reasons, webFrontReason)
		}
		for _, o := range []*contracts.Observation{client, server} {
			if o != nil && o.Status == contracts.Invalidated {
				reasons = append(reasons, "One direction was invalidated: "+o.Reason)
			}
		}
		shifted := shiftedFrom(pack, chosen)
		if shifted == nil && len(identified) == 2 {
			shifted = shiftedFrom(pack, identified[1])
		}
		return build(pack, app, transport, serverPort, hasPort, "identified", client, server, reasons, shifted, attr)
	}
	var observations []*contracts.Observation
	for _, o := range []*contracts.Observation{client, server} {
		if o != nil {
			observations = append(observations, o)
		}
	}
	var sets []map[string]bool
	for _, o := range observations {
		if c := candidates(o); len(c) > 0 {
			sets = append(sets, c)
		}
	}
	if len(sets) == 2 {
		var common []string
		for name := range sets[0] {
			if sets[1][name] {
				common = append(common, name)
			}
		}
		if len(common) == 1 {
			if app, ok := pack.Applications[common[0]]; ok {
				reasons = append(reasons, "Bidirectional correlation of ambiguous directions: "+joinSorted(sets[0])+" with "+joinSorted(sets[1]))
				return build(pack, app, transport, serverPort, hasPort, "correlated", client, server, reasons, nil, nil)
			}
		}
	}
	var unmatchedObs []*contracts.Observation
	for _, o := range observations {
		if unmatched[o.Status] {
			unmatchedObs = append(unmatchedObs, o)
		}
	}
	if len(unmatchedObs) > 0 {
		for _, o := range unmatchedObs {
			reasons = append(reasons, o.Reason)
		}
		return outcome(pack, unknownName, string(unmatchedObs[0].Status), reasons)
	}
	var invalidated []*contracts.Observation
	for _, o := range observations {
		if o.Status == contracts.Invalidated {
			invalidated = append(invalidated, o)
		}
	}
	if len(invalidated) > 0 {
		for _, o := range invalidated {
			reasons = append(reasons, o.Reason)
		}
		return outcome(pack, "not-applicable", "invalidated", reasons)
	}
	payload := true
	if clientBytes.Known || serverBytes.Known {
		total := 0
		if clientBytes.Known {
			total += clientBytes.N
		}
		if serverBytes.Known {
			total += serverBytes.N
		}
		payload = total > 0
	}
	if payload && len(observations) > 0 {
		for _, o := range observations {
			if o.Status == contracts.Incomplete || o.Status == contracts.Detecting {
				reasons = append(reasons, o.Reason)
			}
		}
		if len(reasons) == 0 {
			reasons = []string{"Payload without completed profile"}
		}
		return outcome(pack, "insufficient-data", string(observations[0].Status), reasons)
	}
	status := "no_payload"
	if len(observations) > 0 {
		status = string(observations[0].Status)
	}
	return outcome(pack, "incomplete", status, []string{"No application payload observed"})
}

func pyStr(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

func joinSorted(set map[string]bool) string {
	var names []string
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// MidstreamOutcome ports appid.midstream_outcome (D05).
func MidstreamOutcome(pack *content.Pack, transport, family string) *Verdict {
	return outcome(pack, "incomplete", "midstream", []string{"Connection observed midstream: the segment matched the " + family +
		" layout, but that profile is written for the initial message and is not accepted without an observed start"})
}

// UnobservedStartOutcome ports appid.unobserved_start_outcome (D05).
func UnobservedStartOutcome(pack *content.Pack, transport, reason string) *Verdict {
	return outcome(pack, "incomplete", "midstream", []string{"Connection observed midstream and no message boundary matched a supported layout; an unsupported " +
		"protocol cannot be told from an unobserved start (" + reason + ")"})
}

// Fields ports verdict_fields: the flat JSON-friendly mapping of a session record.
func (v *Verdict) Fields() map[string]interface{} {
	var attr interface{}
	if v.Attribution != nil {
		attr = v.Attribution
	}
	return map[string]interface{}{"app": v.App, "category": v.Category, "subcategory": v.Subcategory, "technology": v.Technology,
		"risk": v.Risk, "characteristics": v.Characteristics, "base_app": v.BaseApp, "implicitly_uses": v.ImplicitlyUses,
		"port_usage": v.PortUsage, "engine_status": v.Status, "client_protocol": v.ClientProtocol, "server_protocol": v.ServerProtocol,
		"encryption": v.Encryption, "reasons": v.Reasons, "shifted_from": v.ShiftedFrom, "risks": v.Risks, "attribution": attr}
}
