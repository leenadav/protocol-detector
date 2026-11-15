package appid

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

func pack(t *testing.T) *content.Pack {
	t.Helper()
	p, err := content.Load("../../../migration/fixtures/content.json")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func str(s string) *string { return &s }

func identifiedHTTP(host string, rows ...contracts.Evidence) *contracts.Observation {
	o := contracts.Initial("tcp")
	o.Status, o.ApplicationProtocol, o.Reason = contracts.Identified, str("http/1.1"), "HTTP start-line and headers validated; body and later requests not inspected"
	o.Evidence = append([]contracts.Evidence{{Field: "application_protocol", Value: "http/1.1", Source: "wire", Strength: "structural"}}, rows...)
	if host != "" {
		o.Hostname = str(host)
		o.Evidence = append(o.Evidence, contracts.Evidence{Field: "hostname", Value: host, Source: "wire:http_host", Strength: "asserted"})
	}
	return &o
}

func tlsHello(host string, rows ...contracts.Evidence) *contracts.Observation {
	o := contracts.Initial("tcp")
	o.Status, o.Encryption, o.Reason = contracts.Identified, str("tls"), "ClientHello structure validated; SNI/ALPN are client assertions, not decrypted content"
	o.Evidence = append([]contracts.Evidence{{Field: "encryption", Value: "tls", Source: "wire", Strength: "structural"}}, rows...)
	if host != "" {
		o.Hostname = str(host)
		o.Evidence = append(o.Evidence, contracts.Evidence{Field: "hostname", Value: host, Source: "wire:tls_sni", Strength: "asserted"})
	}
	return &o
}

func status(s contracts.Status, reason string) *contracts.Observation {
	o := contracts.Initial("tcp")
	o.Status, o.Reason = s, reason
	return &o
}

func TestIdentifiedDirectionWinsAndPortsAreChecked(t *testing.T) {
	p := pack(t)
	v := SessionVerdict(p, identifiedHTTP("a.example"), nil, "tcp", 8000, true, Bytes{36, true}, Bytes{0, true}, true)
	if v.App != "web-browsing" || v.Status != "identified" || v.PortUsage != "nonstandard" || *v.ClientProtocol != "http/1.1" {
		t.Fatalf("%+v", v)
	}
	if len(v.Risks) != 2 || v.Risks[0] != "cleartext-credential-protocol" || v.Risks[1] != "nonstandard-port" {
		t.Fatalf("risks %v", v.Risks)
	}
	v = SessionVerdict(p, identifiedHTTP(""), nil, "tcp", 80, true, Bytes{36, true}, Bytes{}, true)
	if v.PortUsage != "standard" || len(v.Risks) != 1 {
		t.Fatalf("standard port: %+v", v)
	}
}

func TestHostnameNamesAServiceButNeverAuthenticates(t *testing.T) {
	p := pack(t)
	v := SessionVerdict(p, tlsHello("www.youtube.com"), nil, "tcp", 443, true, Bytes{517, true}, Bytes{}, true)
	if v.App != "youtube" || v.BaseApp == nil || *v.BaseApp != "ssl" || !containsString(v.Reasons, HostReason) {
		t.Fatalf("%+v", v)
	}
	if v.Attribution["kind"] != "service" || v.Attribution["activity"] != "unobserved" || !containsString(v.Reasons, activityReason) {
		t.Fatalf("attribution %+v", v.Attribution)
	}
	view := LayeredView(p, "tcp", tlsHello("www.youtube.com"), nil, v, "intact")
	if view["application"].(map[string]interface{})["basis"] != "client_assertion" {
		t.Fatalf("basis %+v", view["application"])
	}
	// An outer encrypted ClientHello makes the visible name the provider's public front: never mapped.
	ech := tlsHello("www.youtube.com", contracts.Evidence{Field: "tls_ech", Value: "outer", Source: "wire:client_hello", Strength: "offered"})
	v = SessionVerdict(p, ech, nil, "tcp", 443, true, Bytes{517, true}, Bytes{}, true)
	if v.App != "ssl" || v.Attribution != nil || !containsString(v.Risks, "tls-encrypted-client-hello") {
		t.Fatalf("ech: %+v", v)
	}
	// A provider web front affiliates without asserting the service.
	v = SessionVerdict(p, tlsHello("www.openai.com"), nil, "tcp", 443, true, Bytes{517, true}, Bytes{}, true)
	if v.App != "ssl" || v.Attribution["kind"] != "provider-web" || !containsString(v.Reasons, webFrontReason) {
		t.Fatalf("web front: %+v", v)
	}
}

func TestOutcomesInOrder(t *testing.T) {
	p := pack(t)
	cases := []struct {
		name           string
		client, server *contracts.Observation
		handshake      bool
		bytes          Bytes
		app, status    string
	}{
		{"no handshake", status(contracts.Detecting, "x"), nil, false, Bytes{0, true}, "incomplete", "no_handshake"},
		{"unknown beats invalidated", status(contracts.Unknown, "Prefix outside supported protocol families"), status(contracts.Invalidated, "conflict"), true, Bytes{5, true}, "unknown-tcp", "unknown"},
		{"invalidated", status(contracts.Invalidated, "conflict"), status(contracts.Incomplete, "fin"), true, Bytes{5, true}, "not-applicable", "invalidated"},
		{"payload without profile", status(contracts.Incomplete, "fin"), nil, true, Bytes{5, true}, "insufficient-data", "incomplete"},
		{"no payload", status(contracts.Incomplete, "fin"), nil, true, Bytes{0, true}, "incomplete", "incomplete"},
		{"malformed", status(contracts.Malformed, "Invalid header name"), nil, true, Bytes{5, true}, "unknown-tcp", "malformed"},
	}
	for _, c := range cases {
		v := SessionVerdict(p, c.client, c.server, "tcp", 80, true, c.bytes, Bytes{0, true}, c.handshake)
		if v.App != c.app || v.Status != c.status {
			t.Fatalf("%s: got %s/%s want %s/%s", c.name, v.App, v.Status, c.app, c.status)
		}
		if v.Identified(p) {
			t.Fatalf("%s: outcome counted as identified", c.name)
		}
	}
	malformed := SessionVerdict(p, status(contracts.Malformed, "x"), nil, "tcp", 80, true, Bytes{5, true}, Bytes{}, true)
	if !containsString(malformed.Risks, "malformed-protocol") {
		t.Fatal("malformed risk")
	}
}

func TestAmbiguityIsResolvedOnlyByBothDirections(t *testing.T) {
	p := pack(t)
	amb := func(cands string) *contracts.Observation {
		o := status(contracts.Unknown, "Command shared by FTP and POP3; the server greeting decides")
		o.Evidence = []contracts.Evidence{{Field: "ambiguous_candidates", Value: cands, Source: "wire", Strength: "context"}}
		return o
	}
	v := SessionVerdict(p, amb("ftp,pop3"), amb("smtp,ftp"), "tcp", 21, true, Bytes{5, true}, Bytes{5, true}, true)
	if v.App != "ftp" || v.Status != "correlated" {
		t.Fatalf("%+v", v)
	}
	v = SessionVerdict(p, amb("ftp,pop3"), nil, "tcp", 21, true, Bytes{5, true}, Bytes{}, true)
	if v.App != "unknown-tcp" {
		t.Fatalf("one direction resolved ambiguity: %+v", v)
	}
	u := SessionUnknown(v, amb("ftp,pop3"), nil, DirectionFacts{ResolvedFamily: "", BytesReceived: 5, Known: true}, DirectionFacts{}, "handshake", true)
	if u["client"].(map[string]interface{})["code"] != "ambiguous" {
		t.Fatalf("unknown %+v", u)
	}
}

func TestWebApplicationRefinement(t *testing.T) {
	p := pack(t)
	row := func(f, v string) contracts.Evidence {
		return contracts.Evidence{Field: f, Value: v, Source: "wire:headers", Strength: "asserted"}
	}
	method := func(m string) contracts.Evidence {
		return contracts.Evidence{Field: "http_method", Value: m, Source: "wire:request_line", Strength: "structural"}
	}
	for _, c := range []struct {
		rows []contracts.Evidence
		app  string
	}{
		{[]contracts.Evidence{method("POST"), row("http_content_type", "dns")}, "dns-over-https"},
		{[]contracts.Evidence{method("PROPFIND")}, "webdav"},
		{[]contracts.Evidence{method("RPC_IN_DATA")}, "ms-rpc-over-http"},
		{[]contracts.Evidence{method("POST"), row("http_content_type", "ipp")}, "ipp"},
		{[]contracts.Evidence{method("GET"), row("http_content_type", "soap")}, "web-browsing"},
		{[]contracts.Evidence{method("GET"), row("http_accept", "dns")}, "dns-over-https"},
	} {
		v := SessionVerdict(p, identifiedHTTP("", c.rows...), nil, "tcp", 80, true, Bytes{10, true}, Bytes{}, true)
		if v.App != c.app {
			t.Fatalf("%v: got %s want %s", c.rows, v.App, c.app)
		}
	}
}

func TestExplainCodes(t *testing.T) {
	for _, c := range []struct {
		obs   *contracts.Observation
		facts DirectionFacts
		code  string
		fam   interface{}
	}{
		{status(contracts.Unknown, "Prefix outside supported protocol families"), DirectionFacts{Known: true}, "no-dispatch", nil},
		{status(contracts.Malformed, "Invalid header name"), DirectionFacts{ResolvedFamily: "http", Known: true, BytesReceived: 9}, "malformed", "http"},
		{status(contracts.BudgetExhausted, "Byte budget exhausted"), DirectionFacts{ResolvedFamily: "", Known: true, BytesReceived: 9}, "budget", nil},
		{status(contracts.Incomplete, "fin"), DirectionFacts{Known: true, BytesReceived: 0}, "no-payload", nil},
		{status(contracts.Incomplete, "fin"), DirectionFacts{Known: true, BytesReceived: 3}, "incomplete", nil},
		{status(contracts.Invalidated, "conflict"), DirectionFacts{Known: true, BytesReceived: 3}, "invalidated", nil},
		{status(contracts.Unknown, "Several questions without multicast DNS markers are outside the DNS profile"), DirectionFacts{ResolvedFamily: "dns", Known: true, BytesReceived: 30}, "profile-unsupported", "dns"},
	} {
		out := Explain(c.obs, c.facts)
		if out["code"] != c.code || out["family"] != c.fam || out["stage"] != stages[c.code] {
			t.Fatalf("%s: %+v", c.obs.Reason, out)
		}
	}
	if Explain(identifiedHTTP(""), DirectionFacts{}) != nil {
		t.Fatal("identification explained")
	}
}
