package framed

import (
	"errors"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

var (
	testOIDKRB5    = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	testOIDNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

func ntlmssp(kind byte, size int) []byte {
	out := make([]byte, size)
	copy(out, "NTLMSSP\x00")
	out[8] = kind
	return out
}

func krbEncrypted(size int) []byte {
	return ber(0x30, cat(ber(0xa0, ber(2, []byte{0x12})), ber(0xa2, ber(4, make([]byte, size)))))
}

func krbPrincipalNames(count int) []byte {
	var names []byte
	for i := 0; i < count; i++ {
		names = append(names, ber(0x1b, []byte("n"))...)
	}
	return ber(0x30, cat(ber(0xa0, ber(2, []byte{1})), ber(0xa1, ber(0x30, names))))
}

// apReq is a GSS InitialContextToken with TOK_ID 01 00 and an AP-REQ whose ap-options and sname are given.
func apReq(options []byte, names int) []byte {
	ticket := ber(0x61, ber(0x30, cat(ber(0xa0, ber(2, []byte{5})), ber(0xa1, ber(0x1b, []byte("EXAMPLE.ORG"))),
		ber(0xa2, krbPrincipalNames(names)), ber(0xa3, krbEncrypted(40)))))
	message := ber(0x6e, ber(0x30, cat(ber(0xa0, ber(2, []byte{5})), ber(0xa1, ber(2, []byte{14})), ber(0xa2, ber(3, options)),
		ber(0xa3, ticket), ber(0xa4, krbEncrypted(40)))))
	return ber(0x60, cat(ber(6, testOIDKRB5), []byte{1, 0}, message))
}

func spnegoInit(mechs [][]byte, token []byte) []byte {
	var list []byte
	for _, oid := range mechs {
		list = append(list, ber(6, oid)...)
	}
	fields := ber(0xa0, ber(0x30, list))
	if token != nil {
		fields = cat(fields, ber(0xa2, ber(4, token)))
	}
	return ber(0x60, cat(ber(6, oidSPNEGO), ber(0xa0, ber(0x30, fields))))
}

func saslBind(mechanism string, credentials []byte) []byte {
	return ber(0x30, cat(ber(2, []byte{1}), ber(0x60, cat(ber(2, []byte{3}), ber(4, nil),
		ber(0xa3, cat(ber(4, []byte(mechanism)), ber(4, credentials)))))))
}

func TestClassifyToken(t *testing.T) {
	flags := []byte{0, 0x20, 0, 0, 0}
	for _, tc := range []struct {
		name string
		blob []byte
		want gssToken
	}{
		{"raw ntlm", ntlmssp(1, 32), gssToken{Kind: "ntlmssp", Mechanism: "ntlm", NTLMMessage: "negotiate"}},
		{"direct kerberos", apReq(flags, 1), gssToken{Kind: "kerberos", Mechanism: "kerberos"}},
		{"init, mechs only", spnegoInit([][]byte{testOIDNTLMSSP, testOIDKRB5}, nil), gssToken{Kind: "spnego-init", Mechanism: "ntlm"}},
		{"init, token decides", spnegoInit([][]byte{testOIDNTLMSSP}, apReq(flags, 8)), gssToken{Kind: "spnego-init", Mechanism: "kerberos"}},
		{"init, ntlm token", spnegoInit([][]byte{testOIDKRB5}, ntlmssp(3, 64)),
			gssToken{Kind: "spnego-init", Mechanism: "ntlm", NTLMMessage: "authenticate"}},
		{"init, opaque token keeps the list", spnegoInit([][]byte{testOIDKRB5}, []byte("opaque")), gssToken{Kind: "spnego-init", Mechanism: "kerberos"}},
		{"response, state only", ber(0xa1, ber(0x30, ber(0xa0, ber(0x0a, []byte{2})))),
			gssToken{Kind: "spnego-response", Mechanism: "spnego-other", State: "reject"}},
		{"other mechanism", ber(0x60, cat(ber(6, []byte{0x2a, 3}), []byte("x"))), gssToken{Kind: "gss-other", Mechanism: "other"}},
	} {
		got, err := classifyToken(tc.blob)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
}

func TestClassifyTokenRejects(t *testing.T) {
	flags := []byte{0, 0x20, 0, 0, 0}
	var nine [][]byte
	for i := 0; i < 9; i++ {
		nine = append(nine, testOIDNTLMSSP)
	}
	for _, tc := range []struct {
		name   string
		blob   []byte
		status string
		reason string
	}{
		{"empty", nil, "malformed", "Empty authentication token"},
		{"over budget", make([]byte, gssMaxToken+1), "budget", "Authentication token exceeds the inspection limit"},
		{"unknown layout", []byte{0x30, 0}, "malformed", "neither GSS-API, SPNEGO nor NTLMSSP"},
		{"ntlm type", ntlmssp(4, 32), "malformed", "NTLMSSP message type"},
		{"ntlm short", []byte("NTLMSSP\x00\x01"), "malformed", "shorter than its signature and type"},
		{"nine mechanisms", spnegoInit(nine, nil), "budget", "mechType list exceeds the inspection limit"},
		{"empty mechanism list", spnegoInit(nil, nil), "malformed", "Empty SPNEGO mechType list"},
		{"flags too short", apReq([]byte{0, 0x20, 0, 0}, 1), "malformed", "KerberosFlags BIT STRING"},
		{"flags padding bits set", apReq([]byte{4, 0x20, 0, 0, 0, 0x0f}, 1), "malformed", "KerberosFlags BIT STRING"},
		{"nine name components", apReq(flags, 9), "malformed", "exceeds the name component budget"},
		{"no name component", apReq(flags, 0), "malformed", "has no name component"},
		{"unknown TOK_ID", ber(0x60, cat(ber(6, testOIDKRB5), []byte{9, 0})), "malformed", "needs a known TOK_ID"},
		{"missing TOK_ID", ber(0x60, ber(6, testOIDKRB5)), "malformed", "needs a known TOK_ID"},
		{"bad carried kerberos", spnegoInit([][]byte{testOIDNTLMSSP}, ber(0x60, cat(ber(6, testOIDKRB5), []byte{9, 0}))),
			"malformed", "needs a known TOK_ID"},
		{"empty response", ber(0xa1, ber(0x30, nil)), "malformed", "Empty NegTokenResp"},
		{"negState 4", ber(0xa1, ber(0x30, ber(0xa0, ber(0x0a, []byte{4})))), "malformed", "Invalid SPNEGO negState"},
	} {
		_, err := classifyToken(tc.blob)
		var pe *parsing.Error
		if !errors.As(err, &pe) || pe.Kind != tc.status || !strings.Contains(pe.Message, tc.reason) {
			t.Errorf("%s: got %v", tc.name, err)
		}
	}
}

func feedAll(t *testing.T, p *Parser, data []byte) (*parsing.Result, error) {
	t.Helper()
	for i := range data { // byte at a time
		if _, err := p.Feed(data[i : i+1]); err != nil {
			return nil, err
		}
	}
	if !p.Done() {
		t.Fatalf("parser not done after %d bytes", len(data))
	}
	return p.Result(), nil
}

func TestLDAPBindCarriesOnlyClosedLabels(t *testing.T) {
	credentials := spnegoInit([][]byte{testOIDKRB5}, ntlmssp(1, 40))
	r, err := feedAll(t, NewLDAP(4096), saslBind("GSS-SPNEGO", credentials))
	if err != nil {
		t.Fatal(err)
	}
	want := []parsing.Row{row("ldap_message", "bind_request", "ldap_message", "structural"), row("ldap_bind", "sasl-gss-spnego", "bind_request", "structural"),
		row("gss_mechanism", "ntlm", "bind_request", "asserted"), row("ntlm_message", "negotiate", "bind_request", "asserted")}
	if r.ProtocolName != "ldap/3" || len(r.Extra) != len(want) {
		t.Fatalf("got %q %+v", r.ProtocolName, r.Extra)
	}
	for i := range want {
		if r.Extra[i] != want[i] {
			t.Errorf("row %d: got %+v want %+v", i, r.Extra[i], want[i])
		}
	}
	// A token under another SASL mechanism is not classified, and a malformed GSS-SPNEGO token rejects the bind.
	if r, err = feedAll(t, NewLDAP(4096), saslBind("GSSAPI", []byte{0x30, 0})); err != nil || len(r.Extra) != 2 {
		t.Errorf("GSSAPI bind: %+v, %v", r, err)
	}
	if _, err = feedAll(t, NewLDAP(4096), saslBind("GSS-SPNEGO", []byte{0x30, 0})); err == nil {
		t.Error("malformed GSS-SPNEGO token accepted")
	}
}

func TestLDAPStartTLSShiftOnlyOnNamedSuccess(t *testing.T) {
	oid := []byte("1.3.6.1.4.1.1466.20037")
	response := func(code byte, name []byte) []byte {
		body := cat(ber(0x0a, []byte{code}), ber(4, nil), ber(4, nil))
		if name != nil {
			body = cat(body, ber(0x8a, name))
		}
		return ber(0x30, cat(ber(2, []byte{1}), ber(0x78, body)))
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		shift bool
	}{{"named success", response(0, oid), true}, {"unnamed success", response(0, nil), false}, {"refused", response(52, oid), false}} {
		r, err := feedAll(t, NewLDAP(4096), tc.data)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if (r.Shift != nil) != tc.shift || r.Scope != "negotiation_response" || r.ProtocolName != "ldap" {
			t.Errorf("%s: shift %+v scope %q protocol %q", tc.name, r.Shift, r.Scope, r.ProtocolName)
		}
	}
	request := ber(0x30, cat(ber(2, []byte{1}), ber(0x77, ber(0x80, oid))))
	if r, err := feedAll(t, NewLDAP(4096), request); err != nil || r.Shift != nil {
		t.Errorf("StartTLS request must not shift: %+v, %v", r, err)
	}
}

func TestLDAPOIDGrammar(t *testing.T) {
	for text, want := range map[string]bool{"1.3.6.1": true, "0.0": true, "2.1234567890": true, "1": false, "3.1": false, "1.02": false,
		"1.12345678901": false, "1..2": false, "1.2.": false, "": false, "1" + strings.Repeat(".1", 30): true, "1" + strings.Repeat(".1", 31): false} {
		if got := ldapOID([]byte(text)); got != want {
			t.Errorf("ldapOID(%q) = %v", text, got)
		}
	}
}

// FuzzGSSNeverPanics: the classifier and the LDAP message validator return a result or an error for any bytes,
// and a classified token carries only closed labels.
func FuzzGSSNeverPanics(f *testing.F) {
	f.Add(apReq([]byte{0, 0x20, 0, 0, 0}, 1))
	f.Add(spnegoInit([][]byte{testOIDNTLMSSP, testOIDKRB5}, ntlmssp(1, 32)))
	f.Add(ber(0xa1, ber(0x30, cat(ber(0xa0, ber(0x0a, []byte{1})), ber(0xa1, ber(6, testOIDNTLMSSP)), ber(0xa2, ber(4, ntlmssp(2, 56)))))))
	f.Add(saslBind("GSS-SPNEGO", spnegoInit([][]byte{testOIDKRB5}, apReq([]byte{0, 0x20, 0, 0, 0}, 2))))
	kinds := map[string]bool{"ntlmssp": true, "kerberos": true, "spnego-init": true, "spnego-response": true, "gss-other": true}
	mechanisms := map[string]bool{"kerberos": true, "ntlm": true, "negoex": true, "spnego-other": true, "other": true}
	messages := map[string]bool{"": true, "negotiate": true, "challenge": true, "authenticate": true}
	f.Fuzz(func(t *testing.T, data []byte) {
		token, err := classifyToken(data)
		if err == nil && (!kinds[token.Kind] || !mechanisms[token.Mechanism] || !messages[token.NTLMMessage]) {
			t.Fatalf("open label in %+v", token)
		}
		_, _ = ldapMessage(data)
		_, _ = ldapMessage(saslBind("GSS-SPNEGO", data))
	})
}
