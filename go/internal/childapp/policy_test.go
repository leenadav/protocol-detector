package childapp

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/policy"
)

func TestPolicyMatchesParentOrChild(t *testing.T) {
	s := embeddedSet(t)
	p := pack(t)
	doc := []byte(`{"version": 1, "default": "allow", "rules": [
		{"name": "no-dropbox-upload", "action": "deny", "match": {"apps": ["dropbox-uploading"]}},
		{"name": "watch-dropbox", "action": "alert", "match": {"containers": ["dropbox"]}}]}`)
	pol, err := policy.FromJSONWithChildren(doc, p, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		req  Request
		want string
	}{
		{Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload"}, "deny"},
		{Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/download"}, "alert"}, // child of dropbox
		{Request{Host: "www.dropbox.com", Method: "GET", Path: "/home"}, "alert"},                     // the parent itself
		{Request{Host: "mail.google.com", Method: "GET", Path: "/"}, "allow"},
	} {
		v := s.Verdict(s.Classify(c.req))
		if got := pol.Evaluate(v, "tcp", 443, true, nil, ""); got.Action != c.want {
			t.Errorf("%+v: %s, want %s (%v)", c.req, got.Action, c.want, got.Reasons)
		}
	}
	// The reference vocabulary is unchanged: without children, containers and child names are refused.
	if _, err := policy.FromJSON(doc, p); err == nil || !strings.Contains(err.Error(), "dropbox-uploading") {
		t.Fatalf("reference parse accepted a child name: %v", err)
	}
	if _, err := policy.FromJSON([]byte(`{"rules": [{"action": "deny", "match": {"containers": ["dropbox"]}}]}`), p); err == nil ||
		!strings.Contains(err.Error(), "unknown match keys: containers") {
		t.Fatalf("reference parse accepted containers: %v", err)
	}
	if _, err := policy.FromJSONWithChildren([]byte(`{"rules": [{"action": "deny", "match": {"containers": ["nope"]}}]}`), p, s); err == nil {
		t.Fatal("unknown container accepted")
	}
}
