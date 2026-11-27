package childapp

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/policy"
)

// SEC-CHILD-1: a request that is refused, capped or ambiguous must never fall back to the parent as if no child
// applied. gmail.googleapis.com is catalogued under google-base, so that is the parent named here (carrying the
// host owner next to the child's container is SEC-CHILD-2). Each bypass below reaches the same server function as the canonical Gmail upload; it is either
// normalized into the match or reported undetermined, never "none".
const gmailUpload = "/upload/gmail/v1/users/me/messages"

func gmailReq(path, ct string) Request {
	return Request{Host: "gmail.googleapis.com", Method: "POST", Path: path, ContentType: ct}
}

func TestSecChild1BypassesFailClosed(t *testing.T) {
	s := embeddedSet(t)
	cases := []struct {
		name   string
		req    Request
		app    string
		status string
		reason string
		limit  string
	}{
		{"canonical upload", gmailReq(gmailUpload+"?uploadType=media", "message/rfc822"),
			"gmail-uploading", appid.ChildMatched, ReasonChildMatched, ""},
		{"%6f for o is decoded", gmailReq("/upl%6fad/gmail/v1/users/me/messages?uploadType=media", "message/rfc822"),
			"gmail-uploading", appid.ChildMatched, ReasonChildMatched, ""},
		{"upper-case escape of a letter", gmailReq("/upl%6Fad/gmail/v1/users/me/messages?uploadType=media", "message/rfc822"),
			"gmail-uploading", appid.ChildMatched, ReasonChildMatched, ""},
		{"encoded query name", gmailReq(gmailUpload+"?upload%54ype=media", "message/rfc822"),
			"gmail-uploading", appid.ChildMatched, ReasonChildMatched, ""},
		{"encoded query value", gmailReq(gmailUpload+"?uploadType=m%65dia", "message/rfc822"),
			"gmail-uploading", appid.ChildMatched, ReasonChildMatched, ""},
		{"repeated query parameter", gmailReq(gmailUpload+"?uploadType=media&uploadType=media", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonAmbiguous, ""},
		{"repeated through an encoded name", gmailReq(gmailUpload+"?uploadType=json&upload%54ype=media", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonAmbiguous, ""},
		{"malformed content type", gmailReq(gmailUpload+"?uploadType=media", "message/rfc822 x"),
			"google-base", appid.ChildUndetermined, ReasonAmbiguous, ""},
		{"trailing slash on a pattern", Request{Host: "gmail.googleapis.com", Method: "POST", Path: "/gmail/v1/users/me/messages/send/"},
			"google-base", appid.ChildUndetermined, ReasonAmbiguous, ""},
		{"double slash", gmailReq("/upload//gmail/v1/users/me/messages?uploadType=media", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonPathNotCanonical, ""},
		{"dot segment", gmailReq("/upload/./gmail/v1/users/me/messages?uploadType=media", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonPathNotCanonical, ""},
		{"encoded dot", gmailReq("/upload/%2e/gmail/v1/users/me/messages?uploadType=media", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonPathNotCanonical, ""},
		{"malformed escape", gmailReq("/upload/gm%zzail/v1/users/me/messages?uploadType=media", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonPathNotCanonical, ""},
		{"encoded control", gmailReq("/upload/gmail%01/v1/users/me/messages", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonPathNotCanonical, ""},
		{"oversized path", gmailReq(gmailUpload+"/"+strings.Repeat("a", DefaultMaxPathBytes), "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonWorkLimit, LimitPathBytes},
		{"oversized content type", gmailReq(gmailUpload+"?uploadType=media", "message/rfc822;"+strings.Repeat("a", maxContentTypeBytes)),
			"google-base", appid.ChildUndetermined, ReasonFieldTooLong, LimitFieldBytes},
		{"oversized method", Request{Host: "gmail.googleapis.com", Method: strings.Repeat("P", maxMethodBytes+1), Path: gmailUpload},
			"google-base", appid.ChildUndetermined, ReasonFieldTooLong, LimitFieldBytes},
		{"too many query pairs", gmailReq(gmailUpload+"?"+strings.Repeat("a=1&", maxQueryPairs)+"uploadType=media", "message/rfc822"),
			"google-base", appid.ChildUndetermined, ReasonFieldTooLong, LimitFieldBytes},
		{"canonical, no child applies", Request{Host: "gmail.googleapis.com", Method: "GET", Path: "/gmail/v1/users/me/profile"},
			"google-base", appid.ChildNone, ReasonNoChildMatched, ""},
		{"encoded space stays a match input", Request{Host: "gmail.googleapis.com", Method: "GET", Path: "/gmail/v1/users/me/pro%20file"},
			"google-base", appid.ChildNone, ReasonNoChildMatched, ""},
		{"unowned host", Request{Host: "upload.example.org", Method: "POST", Path: "//x"},
			"", appid.ChildNotApplicable, ReasonHostUnowned, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.Classify(c.req)
			if got.App != c.app || got.ChildStatus != c.status || got.Reasons[0] != c.reason || got.Limit != c.limit {
				t.Fatalf("got %+v, want app %q status %q reason %q limit %q", got, c.app, c.status, c.reason, c.limit)
			}
			if got.ChildStatus != appid.ChildMatched && (got.Container != "" || got.Rule != "") {
				t.Fatalf("a child without a match: %+v", got)
			}
			if v := s.Verdict(got); v != nil && v.ChildStatus != got.ChildStatus {
				t.Fatalf("verdict status %q, result %q", v.ChildStatus, got.ChildStatus)
			}
		})
	}
}

// TestSecChild1WorkCeilingIsUndetermined: a rule-evaluation ceiling leaves the function undetermined.
func TestSecChild1WorkCeilingIsUndetermined(t *testing.T) {
	s, err := Load([]byte(manyRules(100)), pack(t), Options{MaxRuleEvaluations: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Classify(Request{Host: "content.dropboxapi.com", Method: "GET", Path: "/x"}); got.ChildStatus != appid.ChildUndetermined || got.Limit != LimitRuleEvaluations {
		t.Fatalf("got %+v", got)
	}
}

// TestSecChild1NoRuleOnHostIsNone: where no child rule names the host, a refusal cannot hide a child.
func TestSecChild1NoRuleOnHostIsNone(t *testing.T) {
	s, err := Load([]byte(child(`{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}`)), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"//x", "/" + strings.Repeat("a", DefaultMaxPathBytes)} {
		if got := s.Classify(Request{Host: "www.dropbox.com", Method: "POST", Path: path}); got.App != "dropbox" || got.ChildStatus != appid.ChildNone {
			t.Fatalf("%.20q: got %+v", path, got)
		}
		if got := s.Classify(Request{Host: "content.dropboxapi.com", Method: "POST", Path: path}); got.ChildStatus != appid.ChildUndetermined {
			t.Fatalf("%.20q on a host with rules: got %+v", path, got)
		}
	}
}

// TestSecChild1AmbiguityOnlyWhenItWouldWin: an ambiguous rule that a definite, more specific rule outranks
// changes nothing; one that would outrank the definite winner makes the child undetermined.
func TestSecChild1AmbiguityOnlyWhenItWouldWin(t *testing.T) {
	doc := header + `{"name": "dropbox-a", "container": "dropbox", "description": "d", "evidence": ["https://e.org"],
		"rules": [{"hosts": ["content.dropboxapi.com"], "path_prefixes": ["/2/files/"]}]},
		{"name": "dropbox-b", "container": "dropbox", "description": "d", "evidence": ["https://e.org"],
		"rules": [{"hosts": ["content.dropboxapi.com"], "path_prefixes": ["/2/"], "query": ["mode=x"]}]}]}`
	s, err := Load([]byte(doc), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Classify(Request{Host: "content.dropboxapi.com", Method: "GET", Path: "/2/files/up?mode=x&mode=x"}); got.App != "dropbox-a" || got.ChildStatus != appid.ChildMatched {
		t.Fatalf("outranked ambiguous rule changed the verdict: %+v", got)
	}
	doc = strings.Replace(doc, `"path_prefixes": ["/2/"]`, `"path_prefixes": ["/2/files/up"]`, 1)
	if s, err = Load([]byte(doc), pack(t), Options{}); err != nil {
		t.Fatal(err)
	}
	if got := s.Classify(Request{Host: "content.dropboxapi.com", Method: "GET", Path: "/2/files/up?mode=x&mode=x"}); got.App != "dropbox" || got.ChildStatus != appid.ChildUndetermined || got.Rule != "" {
		t.Fatalf("ambiguous winner named a child: %+v", got)
	}
}

// TestSecChild1PolicyDeniesUndetermined: "deny gmail-uploading" plus a child_status rule for the possible
// owners of its hosts (its container and depends_on) denies every bypass, and the reference vocabulary still refuses child_status.
func TestSecChild1PolicyDeniesUndetermined(t *testing.T) {
	s := embeddedSet(t)
	p := pack(t)
	doc := []byte(`{"version": 1, "default": "allow", "rules": [
		{"name": "no-gmail-upload", "action": "deny", "match": {"apps": ["gmail-uploading"]}},
		{"name": "no-unknown-gmail-function", "action": "deny", "match": {"apps": ["gmail", "google-base"], "child_status": ["undetermined"]}}]}`)
	pol, err := policy.FromJSONWithChildren(doc, p, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		req  Request
		want string
	}{
		{gmailReq(gmailUpload+"?uploadType=media", "message/rfc822"), "deny"},
		{gmailReq("/upl%6fad/gmail/v1/users/me/messages?uploadType=media", "message/rfc822"), "deny"},
		{gmailReq(gmailUpload+"?uploadType=media&uploadType=media", "message/rfc822"), "deny"},
		{gmailReq("/upload//gmail/v1/users/me/messages?uploadType=media", "message/rfc822"), "deny"},
		{gmailReq("/upload/./gmail/v1/users/me/messages?uploadType=media", "message/rfc822"), "deny"},
		{gmailReq(gmailUpload+"/"+strings.Repeat("a", DefaultMaxPathBytes), "message/rfc822"), "deny"},
		{gmailReq(gmailUpload+"?uploadType=media", strings.Repeat("m", maxContentTypeBytes+1)), "deny"},
		{Request{Host: "gmail.googleapis.com", Method: "GET", Path: "/gmail/v1/users/me/profile"}, "allow"},
		{Request{Host: "gmail.googleapis.com", Method: "GET", Path: "/gmail/v1/users/me/messages/m1/attachments/a1"}, "allow"},
	} {
		v := s.Verdict(s.Classify(c.req))
		if got := pol.Evaluate(v, "tcp", 443, true, nil, ""); got.Action != c.want {
			t.Errorf("%.60s: %s, want %s (%+v)", c.req.Path, got.Action, c.want, s.Classify(c.req))
		}
	}
	if _, err := policy.FromJSON([]byte(`{"rules": [{"action": "deny", "match": {"child_status": ["undetermined"]}}]}`), p); err == nil ||
		!strings.Contains(err.Error(), "unknown match keys: child_status") {
		t.Fatalf("reference parse accepted child_status: %v", err)
	}
	if _, err := policy.FromJSONWithChildren([]byte(`{"rules": [{"action": "deny", "match": {"child_status": ["maybe"]}}]}`), p, s); err == nil {
		t.Fatal("unknown child_status accepted")
	}
}
