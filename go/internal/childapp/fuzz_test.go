package childapp

import (
	"testing"
)

// FuzzClassifyNeverPanics feeds arbitrary request fields to the built-in component: no panic, the ceiling holds,
// a limit never carries a child, and a child always names its container.
func FuzzClassifyNeverPanics(f *testing.F) {
	s := embeddedSet(f)
	f.Add("gmail.googleapis.com", "gmail.googleapis.com", "POST", "/upload/gmail/v1/users/me/messages", "message/rfc822", int64(10), int64(-1), false)
	f.Add("", "gateway.discord.gg:443", "GET", "/?v=10", "", int64(-1), int64(-1), true)
	f.Add("x", "content.dropboxapi.com.", "POST", "/2/files%2fupload", "multipart/form-data; b=1", int64(0), int64(0), false)
	f.Add("", "a..b", "", "//", ";", int64(-5), int64(1<<62), false)
	f.Fuzz(func(t *testing.T, sni, host, method, path, ct string, up, down int64, ws bool) {
		got := s.Classify(Request{SNI: sni, Host: host, Method: method, Path: path, ContentType: ct,
			RequestBodyBytes: up, ResponseBodyBytes: down, WebSocket: ws})
		if got.Evaluated > DefaultMaxRuleEvaluations || len(got.Reasons) != 1 {
			t.Fatalf("%+v", got)
		}
		if got.Limit != "" && got.Container != "" {
			t.Fatalf("limit with a child: %+v", got)
		}
		if got.Container != "" && (s.Child(got.App) == nil || s.Child(got.App).Container != got.Container) {
			t.Fatalf("child without its container: %+v", got)
		}
	})
}

// FuzzLoadNeverPanics feeds arbitrary component files to the loader.
func FuzzLoadNeverPanics(f *testing.F) {
	p := pack(f)
	f.Add(EmbeddedBytes())
	f.Add([]byte(child(`{"hosts": ["content.dropboxapi.com"], "path_patterns": ["/a/*/**"], "direction": "upload", "min_bytes": 3}`)))
	f.Add([]byte(`{"schema": 1, "release": {}, "children": [null]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Load(data, p, Options{})
		if err == nil && s == nil {
			t.Fatal("nil set without an error")
		}
		if err == nil {
			s.Classify(Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/a/b/c", RequestBodyBytes: 9})
		}
	})
}
