package childapp

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/policy"
)

// SEC-CHILD-2: a child match never moves a request out from under the catalog application that owns its host.

// TestResultCarriesHostOwner: the verdict of a child match on a host that google-base or ms-base claims names
// that owner, and a server-name verdict names its own application.
func TestResultCarriesHostOwner(t *testing.T) {
	s := embeddedSet(t)
	for _, c := range []struct {
		req                   Request
		app, container, owner string
	}{
		{Request{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/me/sendMail"}, "outlook-sending", "outlook-web", "ms-base"},
		{Request{Host: "gmail.googleapis.com", Method: "POST", Path: "/gmail/v1/users/me/messages/send"}, "gmail-sending", "gmail", "google-base"},
		{Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload", ContentType: "application/octet-stream",
			HeaderNames: []string{"Dropbox-API-Arg"}}, "dropbox-uploading", "dropbox", "dropbox"},
		{Request{Host: "graph.microsoft.com", Method: "GET", Path: "/v1.0/me"}, "ms-base", "", "ms-base"},
		{Request{Host: "mail.google.com", Method: "GET", Path: "/"}, "gmail", "", "gmail"},
		{Request{Host: "example.org"}, "", "", ""},
	} {
		res := s.Classify(c.req)
		if res.App != c.app || res.Container != c.container || res.HostOwner != c.owner {
			t.Errorf("%s %s: app %q container %q owner %q, want %q %q %q", c.req.Host, c.req.Path, res.App, res.Container,
				res.HostOwner, c.app, c.container, c.owner)
		}
		v := s.Verdict(res)
		if c.app == "" {
			continue
		}
		if v == nil || v.HostOwner == nil || *v.HostOwner != c.owner {
			t.Errorf("%s %s: verdict host owner %v, want %q", c.req.Host, c.req.Path, v, c.owner)
		}
	}
}

// TestPolicyContainersMatchHostOwner is the SEC-CHILD-2 reproduction: deny containers:[ms-base] or
// containers:[google-base] must still deny Graph sendMail, Gmail send and a Drive upload once a child matched.
func TestPolicyContainersMatchHostOwner(t *testing.T) {
	s := embeddedSet(t)
	doc := []byte(`{"version": 1, "default": "allow", "rules": [
		{"name": "no-ms", "action": "deny", "match": {"containers": ["ms-base"]}},
		{"name": "no-google", "action": "deny", "match": {"containers": ["google-base"]}}]}`)
	pol, err := policy.FromJSONWithChildren(doc, pack(t), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		req  Request
		want string
	}{
		{Request{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/me/sendMail"}, "deny"},
		{Request{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/users/x/sendMail"}, "deny"},
		{Request{Host: "gmail.googleapis.com", Method: "POST", Path: "/gmail/v1/users/me/messages/send"}, "deny"},
		{Request{Host: "www.googleapis.com", Method: "POST", Path: "/upload/drive/v3/files?uploadType=media",
			ContentType: "application/octet-stream", RequestBodyBytes: 4096, ResponseBodyBytes: 10}, "deny"},
		{Request{Host: "graph.microsoft.com", Method: "GET", Path: "/v1.0/me"}, "deny"},
		{Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload", ContentType: "application/octet-stream",
			HeaderNames: []string{"Dropbox-API-Arg"}}, "allow"},
		{Request{Host: "mail.google.com", Method: "GET", Path: "/"}, "allow"}, // gmail's own host, not google-base's
	} {
		res := s.Classify(c.req)
		v := s.Verdict(res)
		if v == nil {
			t.Fatalf("%+v: no verdict", c.req)
		}
		if got := pol.Evaluate(v, "tcp", 443, true, nil, ""); got.Action != c.want {
			t.Errorf("%s %s (app %s, owner %s): %s, want %s", c.req.Host, c.req.Path, res.App, res.HostOwner, got.Action, c.want)
		}
	}
}

// TestSuffixRuleStaysInsideItsOwner: a host_suffixes rule claimed through google-base never fires on a more
// specific host the catalog gives another application (maps.googleapis.com is google-maps').
func TestSuffixRuleStaysInsideItsOwner(t *testing.T) {
	doc := header + `{"name": "google-drive-x", "container": "google-drive", "description": "d", "depends_on": ["google-base"],
		"evidence": ["https://example.org/doc"], "rules": [{"host_suffixes": ["googleapis.com"], "methods": ["POST"]}]}]}`
	s, err := Load([]byte(doc), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res := s.Classify(Request{Host: "www.googleapis.com", Method: "POST", Path: "/x"}); res.App != "google-drive-x" || res.HostOwner != "google-base" {
		t.Fatalf("google-base host: %+v", res)
	}
	res := s.Classify(Request{Host: "maps.googleapis.com", Method: "POST", Path: "/x"})
	if res.App != "google-maps" || res.Container != "" || res.Basis != BasisServerName || res.HostOwner != "google-maps" {
		t.Fatalf("another owner's host was moved to a child: %+v", res)
	}
}

// TestChildRiskNeverBelowOwner: the default risk is the highest of the container's and of every application
// owning a host the child's rules name, and an explicit lower risk is refused.
func TestChildRiskNeverBelowOwner(t *testing.T) {
	p := pack(t)
	// gmail is risk 2, telegram (owner of api.telegram.org) risk 4.
	body := func(risk string) string {
		return header + `{"name": "gmail-x", "container": "gmail", "description": "d", "depends_on": ["telegram"]` + risk +
			`, "evidence": ["https://example.org/doc"], "rules": [{"hosts": ["api.telegram.org"], "methods": ["POST"]}]}]}`
	}
	if p.Applications["gmail"].Risk >= p.Applications["telegram"].Risk {
		t.Fatalf("fixture assumption broken: gmail %d telegram %d", p.Applications["gmail"].Risk, p.Applications["telegram"].Risk)
	}
	s, err := Load([]byte(body("")), p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Child("gmail-x").Risk; got != p.Applications["telegram"].Risk {
		t.Fatalf("default risk %d, want the host owner's %d", got, p.Applications["telegram"].Risk)
	}
	if _, err := Load([]byte(body(`, "risk": 3`)), p, Options{}); err == nil {
		t.Fatal("a risk below the host owner's was accepted")
	}
	if _, err := Load([]byte(header+
		`{"name": "dropbox-x", "container": "dropbox", "description": "d", "risk": 2, "evidence": ["https://e.org"],
		"rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`), p, Options{}); err == nil {
		t.Fatal("a risk below the container's was accepted")
	}
	if _, err := Load([]byte(body(`, "risk": 5`)), p, Options{}); err != nil {
		t.Fatalf("a higher risk was refused: %v", err)
	}
	// Every built-in child is at least as risky as each owner it can match under.
	s = embeddedSet(t)
	for _, c := range s.Children() {
		for owner := range c.owners {
			if c.Risk < p.Applications[owner].Risk {
				t.Errorf("%s risk %d below owner %s %d", c.Name, c.Risk, owner, p.Applications[owner].Risk)
			}
		}
	}
}

// TestPolicyOwnerKeyedRulesHoldOnChild is the SEC-CHILD-7 reproduction: a child match keeps every rule keyed on its
// host owner's identity. Graph sendMail is outlook-sending (collaboration/email) on ms-base's host
// (general-internet/internet-utility, pervasive), so deny apps:[ms-base], subcategories:[internet-utility] or
// characteristics:[pervasive] must still deny it, as each did before child apps existed.
func TestPolicyOwnerKeyedRulesHoldOnChild(t *testing.T) {
	s := embeddedSet(t)
	sendMail := Request{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/me/sendMail"}
	gmailSend := Request{Host: "gmail.googleapis.com", Method: "POST", Path: "/gmail/v1/users/me/messages/send"}
	driveUpload := Request{Host: "www.googleapis.com", Method: "POST", Path: "/upload/drive/v3/files?uploadType=media",
		ContentType: "application/octet-stream", RequestBodyBytes: 4096, ResponseBodyBytes: 10}
	dropboxUpload := Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload",
		ContentType: "application/octet-stream", HeaderNames: []string{"Dropbox-API-Arg"}}
	mailWeb := Request{Host: "mail.google.com", Method: "GET", Path: "/"}
	for _, c := range []struct {
		match string
		req   Request
		want  string
	}{
		{`{"apps": ["ms-base"]}`, sendMail, "deny"},
		{`{"apps": ["google-base"]}`, gmailSend, "deny"},
		{`{"apps": ["google-base"]}`, driveUpload, "deny"},
		{`{"apps": ["dropbox"]}`, dropboxUpload, "deny"}, // the container owns the host: apps:[dropbox] keeps uploads
		{`{"subcategories": ["internet-utility"]}`, sendMail, "deny"},
		{`{"categories": ["general-internet"]}`, gmailSend, "deny"},
		{`{"technologies": ["client-server"]}`, sendMail, "deny"},
		{`{"characteristics": ["pervasive"]}`, sendMail, "deny"},
		{`{"characteristics": ["pervasive"]}`, driveUpload, "deny"},
		// The owner's identity and the child's combine: a child characteristic with the owner's subcategory.
		{`{"subcategories": ["internet-utility"], "characteristics": ["transfers-files"]}`, sendMail, "deny"},
		// The child's own identity still matches.
		{`{"apps": ["outlook-sending"]}`, sendMail, "deny"},
		{`{"subcategories": ["email"]}`, sendMail, "deny"},
		// Never wider than the two identities: another owner's name, or no owner at all.
		{`{"apps": ["google-base"]}`, sendMail, "allow"},
		{`{"apps": ["ms-base"]}`, mailWeb, "allow"},
		{`{"subcategories": ["internet-utility"]}`, mailWeb, "allow"},
		{`{"characteristics": ["pervasive"]}`, dropboxUpload, "allow"},
	} {
		doc := []byte(`{"version": 1, "default": "allow", "rules": [{"name": "r", "action": "deny", "match": ` + c.match + `}]}`)
		pol, err := policy.FromJSONWithChildren(doc, pack(t), s)
		if err != nil {
			t.Fatal(err)
		}
		res := s.Classify(c.req)
		v := s.Verdict(res)
		if v == nil {
			t.Fatalf("%+v: no verdict", c.req)
		}
		if got := pol.Evaluate(v, "tcp", 443, true, nil, ""); got.Action != c.want {
			t.Errorf("%s on %s %s (app %s, owner %s): %s, want %s", c.match, c.req.Host, c.req.Path, res.App, res.HostOwner,
				got.Action, c.want)
		}
	}
}
