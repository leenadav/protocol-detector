package childapp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

func pack(t testing.TB) *content.Pack {
	t.Helper()
	p, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func embeddedSet(t testing.TB) *Set {
	t.Helper()
	s, err := Embedded(pack(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEmbeddedComponentLoads(t *testing.T) {
	s := embeddedSet(t)
	if len(s.Children()) == 0 || s.Release.Version == "" || len(s.Digest) != 64 {
		t.Fatalf("component not loaded: %d children, release %q", len(s.Children()), s.Release.Version)
	}
	for _, c := range s.Children() {
		if !strings.HasPrefix(c.Name, c.Container+"-") || len(c.Evidence) == 0 || c.ImplicitlyUses[0] != c.Container {
			t.Errorf("child %s: container %s, evidence %v, implicitly_uses %v", c.Name, c.Container, c.Evidence, c.ImplicitlyUses)
		}
		if a := s.Application(c.Name); a == nil || a.Container == nil || *a.Container != c.Container {
			t.Errorf("child %s has no catalog record over its container", c.Name)
		}
	}
}

func TestClassifyExamples(t *testing.T) {
	s := embeddedSet(t)
	cases := []struct {
		name      string
		req       Request
		app, cont string
		basis     string
		reason    string
	}{
		{"gmail upload", Request{SNI: "gmail.googleapis.com", Host: "gmail.googleapis.com", Method: "POST",
			Path: "/upload/gmail/v1/users/me/messages/send?uploadType=multipart", ContentType: "message/rfc822",
			RequestBodyBytes: 4096, ResponseBodyBytes: -1}, "gmail-uploading", "gmail", BasisRequestRule, ReasonChildMatched},
		{"gmail send", Request{Host: "gmail.googleapis.com:443", Method: "POST", Path: "/gmail/v1/users/me/messages/send"},
			"gmail-sending", "gmail", BasisRequestRule, ReasonChildMatched},
		{"gmail attachment", Request{Host: "GMAIL.googleapis.com", Method: "GET", Path: "/gmail/v1/users/me/messages/m1/attachments/a1"},
			"gmail-downloading", "gmail", BasisRequestRule, ReasonChildMatched},
		{"gmail web, no function", Request{SNI: "mail.google.com", Host: "mail.google.com", Method: "GET", Path: "/mail/u/0/"},
			"gmail", "", BasisServerName, ReasonNoChildMatched},
		{"googleapis other path stays google-base", Request{Host: "www.googleapis.com", Method: "GET", Path: "/youtube/v3/videos"},
			"google-base", "", BasisServerName, ReasonNoChildMatched},
		{"wrong method", Request{Host: "content.dropboxapi.com", Method: "DELETE", Path: "/2/files/upload"},
			"dropbox", "", BasisServerName, ReasonNoChildMatched},
		{"dropbox upload session", Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload_session/start"},
			"dropbox-uploading", "dropbox", BasisRequestRule, ReasonChildMatched},
		{"discord websocket", Request{Host: "gateway.discord.gg", Method: "GET", Path: "/?v=10&encoding=json", WebSocket: true},
			"discord-gateway", "discord", BasisRequestRule, ReasonChildMatched},
		{"discord without upgrade", Request{Host: "gateway.discord.gg", Method: "GET", Path: "/"},
			"discord", "", BasisServerName, ReasonNoChildMatched},
		{"unowned host never gets a child", Request{Host: "upload.example.org", Method: "POST", Path: "/upload/gmail/v1/users/me/messages"},
			"", "", BasisNone, ReasonHostUnowned},
		{"no host", Request{Method: "POST", Path: "/x"}, "", "", BasisNone, ReasonNoHost},
		{"invalid host", Request{Host: "bad host", Method: "POST"}, "", "", BasisNone, ReasonHostInvalid},
		{"fronted: SNI of another owner", Request{SNI: "www.example.org", Host: "gmail.googleapis.com", Method: "POST",
			Path: "/gmail/v1/users/me/messages/send"}, "", "", BasisNone, ReasonSNIHostMismatch},
		{"coalesced: SNI of the same owner", Request{SNI: "www.googleapis.com", Host: "gmail.googleapis.com", Method: "POST",
			Path: "/gmail/v1/users/me/messages/send"}, "gmail-sending", "gmail", BasisRequestRule, ReasonChildMatched},
		{"encoded slash refused", Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files%2Fupload"},
			"dropbox", "", BasisServerName, ReasonPathNotCanonical},
		{"dot segment refused", Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/x/../upload"},
			"dropbox", "", BasisServerName, ReasonPathNotCanonical},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.Classify(c.req)
			if got.App != c.app || got.Container != c.cont || got.Basis != c.basis || len(got.Reasons) != 1 || got.Reasons[0] != c.reason {
				t.Fatalf("got %+v", got)
			}
			if got.Release != s.Release.Version || got.PackRelease == "" {
				t.Fatalf("releases not reported: %+v", got)
			}
		})
	}
}

const header = `{"schema": 1, "release": {"version": "2026.11.0", "note": "n", "review": "r"}, "children": [`

func child(rules string) string {
	return header + `{"name": "dropbox-x", "container": "dropbox", "description": "d", "evidence": ["https://example.org/doc"],
		"rules": [` + rules + `]}]}`
}

func TestDirectionAndContentType(t *testing.T) {
	s, err := Load([]byte(child(`{"hosts": ["content.dropboxapi.com"], "direction": "upload", "min_bytes": 1024,
		"content_types": ["application/octet-stream", "multipart/*"]}`)), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	base := Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/x", ContentType: "Multipart/Form-Data; boundary=z"}
	for _, c := range []struct {
		up, down int64
		ct       string
		want     string
	}{
		{2048, -1, "", "dropbox-x"},
		{2048, 10, "", "dropbox-x"},
		{2048, 4096, "", "dropbox"}, // more came down than went up
		{1023, -1, "", "dropbox"},   // under min_bytes
		{-1, -1, "", "dropbox"},     // unknown size never matches a direction
		{4096, -1, "text/plain", "dropbox"},
		{4096, -1, "application/octet-stream", "dropbox-x"},
	} {
		req := base
		req.RequestBodyBytes, req.ResponseBodyBytes = c.up, c.down
		if c.ct != "" {
			req.ContentType = c.ct
		}
		if got := s.Classify(req); got.App != c.want {
			t.Errorf("up %d down %d ct %q: got %s", c.up, c.down, req.ContentType, got.App)
		}
	}
}

func TestLoadRefuses(t *testing.T) {
	p := pack(t)
	bad := map[string]string{
		"unknown key":           child(`{"hosts": ["content.dropboxapi.com"], "methods": ["POST"], "regex": "x"}`),
		"case-folded key":       child(`{"Hosts": ["content.dropboxapi.com"], "methods": ["POST"]}`),
		"repeated key":          child(`{"hosts": ["content.dropboxapi.com"], "hosts": ["api.dropboxapi.com"], "methods": ["POST"]}`),
		"host of another app":   child(`{"hosts": ["mail.google.com"], "methods": ["POST"]}`),
		"unowned host":          child(`{"hosts": ["example.org"], "methods": ["POST"]}`),
		"web front":             child(`{"hosts": ["www.dropboxforum.com"], "methods": ["POST"]}`),
		"no function condition": child(`{"hosts": ["content.dropboxapi.com"]}`),
		"no host":               child(`{"methods": ["POST"]}`),
		"lower-case method":     child(`{"hosts": ["content.dropboxapi.com"], "methods": ["post"]}`),
		"bad pattern":           child(`{"hosts": ["content.dropboxapi.com"], "path_patterns": ["/a/**/b"]}`),
		"wildcard in segment":   child(`{"hosts": ["content.dropboxapi.com"], "path_patterns": ["/a*"]}`),
		"non-canonical prefix":  child(`{"hosts": ["content.dropboxapi.com"], "path_prefixes": ["/a/../b"]}`),
		"bad direction":         child(`{"hosts": ["content.dropboxapi.com"], "direction": "sideways"}`),
		"min_bytes alone":       child(`{"hosts": ["content.dropboxapi.com"], "methods": ["POST"], "min_bytes": 5}`),
		"websocket false":       child(`{"hosts": ["content.dropboxapi.com"], "websocket": false}`),
		"bad content type":      child(`{"hosts": ["content.dropboxapi.com"], "content_types": ["*/*"]}`),
		"name outside container": header + `{"name": "gmail-x", "container": "dropbox", "description": "d",
			"evidence": ["https://e.org"], "rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`,
		"name of a catalog app": header + `{"name": "dropbox", "container": "dropbox", "description": "d",
			"evidence": ["https://e.org"], "rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`,
		"unknown container": header + `{"name": "nope-x", "container": "nope", "description": "d",
			"evidence": ["https://e.org"], "rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`,
		"plain http evidence": header + `{"name": "dropbox-x", "container": "dropbox", "description": "d",
			"evidence": ["http://e.org"], "rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`,
		"risk out of range": header + `{"name": "dropbox-x", "container": "dropbox", "description": "d", "risk": 9,
			"evidence": ["https://e.org"], "rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`,
		"bad version":  strings.Replace(child(`{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}`), "2026.11.0", "2026.13.0", 1),
		"extra data":   child(`{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}`) + "{}",
		"not json":     "{",
		"wrong schema": strings.Replace(child(`{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}`), `"schema": 1`, `"schema": 2`, 1),
	}
	for name, doc := range bad {
		if _, err := Load([]byte(doc), p, Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := header + `{"name": "dropbox-x", "container": "dropbox", "description": "d", "evidence": ["https://e.org"],
		"rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]},
		{"name": "dropbox-x", "container": "dropbox", "description": "d", "evidence": ["https://e.org"],
		"rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`
	if _, err := Load([]byte(dup), p, Options{}); err == nil {
		t.Error("repeated child name accepted")
	}
}

// manyRules builds n children of one rule each on one host, none of which matches method GET except the last.
func manyRules(n int) string {
	var b strings.Builder
	b.WriteString(header)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		method := "POST"
		if i == n-1 {
			method = "GET"
		}
		doc, _ := json.Marshal(map[string]interface{}{"name": fmt.Sprintf("dropbox-c%04d", i), "container": "dropbox", "description": "d",
			"evidence": []string{"https://e.org"}, "rules": []interface{}{map[string]interface{}{
				"host_suffixes": []string{"dropboxapi.com"}, "methods": []string{method}}}})
		b.Write(doc)
	}
	b.WriteString("]}")
	return b.String()
}

func TestWorkCeilingIsReportedNeverSilent(t *testing.T) {
	s, err := Load([]byte(manyRules(100)), pack(t), Options{MaxRuleEvaluations: 10})
	if err != nil {
		t.Fatal(err)
	}
	got := s.Classify(Request{Host: "content.dropboxapi.com", Method: "GET", Path: "/x"})
	if got.Limit != LimitRuleEvaluations || got.Evaluated != 10 || got.App != "dropbox" || got.Container != "" ||
		got.Reasons[0] != ReasonWorkLimit {
		t.Fatalf("ceiling not reported: %+v", got)
	}
	// With room, the last child matches and nothing is reported as a limit.
	roomy := s.WithOptions(Options{MaxRuleEvaluations: 100})
	if got := roomy.Classify(Request{Host: "content.dropboxapi.com", Method: "GET", Path: "/x"}); got.App != "dropbox-c0099" || got.Limit != "" || got.Evaluated != 100 {
		t.Fatalf("got %+v", got)
	}
	long := Request{Host: "content.dropboxapi.com", Method: "GET", Path: "/" + strings.Repeat("a", DefaultMaxPathBytes)}
	if got := roomy.Classify(long); got.Limit != LimitPathBytes || got.Container != "" || got.Evaluated != 0 {
		t.Fatalf("path ceiling not reported: %+v", got)
	}
	if got := roomy.Classify(Request{Host: "content.dropboxapi.com", Method: strings.Repeat("A", 40)}); got.Limit != LimitFieldBytes {
		t.Fatalf("field ceiling not reported: %+v", got)
	}
}

func TestEvaluationOrderIsFileOrderAcrossBuckets(t *testing.T) {
	doc := header + `{"name": "dropbox-a", "container": "dropbox", "description": "d", "evidence": ["https://e.org"],
		"rules": [{"host_suffixes": ["dropboxapi.com"], "methods": ["POST"]}]},
		{"name": "dropbox-b", "container": "dropbox", "description": "d", "evidence": ["https://e.org"],
		"rules": [{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}]}]}`
	s, err := Load([]byte(doc), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Classify(Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/"}); got.App != "dropbox-a" || got.Rule != "dropbox-a#0" {
		t.Fatalf("got %+v", got)
	}
}

func TestVerdictCarriesParentAndChild(t *testing.T) {
	s := embeddedSet(t)
	v := s.Verdict(s.Classify(Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload"}))
	if v == nil || v.App != "dropbox-uploading" || v.BaseApp == nil || *v.BaseApp != "dropbox" || v.Category == "" ||
		v.ImplicitlyUses[0] != "dropbox" || v.Status != "identified" {
		t.Fatalf("verdict %+v", v)
	}
	if v := s.Verdict(s.Classify(Request{Host: "example.org"})); v != nil {
		t.Fatalf("unowned host gave a verdict %+v", v)
	}
	if v := s.Verdict(s.Classify(Request{Host: "content.dropboxapi.com", Method: "PUT", Path: "/"})); v == nil || v.App != "dropbox" || v.BaseApp != nil {
		t.Fatalf("parent verdict %+v", v)
	}
}
