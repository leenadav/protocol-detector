package childapp

import (
	"strings"
	"testing"
)

// TestSecChild3Forms pins the request forms SEC-CHILD-3 (PRO-510) found missing from wave 0, each against App
// Research's vendor evidence (research/child-apps/wave-1.json, sec_child_3): every one names its child now.
func TestSecChild3Forms(t *testing.T) {
	s := embeddedSet(t)
	cases := []struct {
		name string
		req  Request
		app  string
	}{
		// gmail-multipart-resumable: a multipart upload is multipart/related, a resumable start is JSON.
		{"gmail multipart upload", Request{Host: "gmail.googleapis.com", Method: "POST",
			Path: "/upload/gmail/v1/users/me/messages?uploadType=multipart", ContentType: "multipart/related; boundary=b"}, "gmail-uploading"},
		{"gmail resumable start", Request{Host: "gmail.googleapis.com", Method: "POST",
			Path: "/resumable/upload/gmail/v1/users/me/messages/import?uploadType=resumable", ContentType: "application/json"}, "gmail-uploading"},
		{"gmail resumable start without a body type", Request{Host: "gmail.googleapis.com", Method: "POST",
			Path: "/resumable/upload/gmail/v1/users/me/drafts?uploadType=resumable"}, "gmail-uploading"},
		{"gmail drafts.update is PUT", Request{Host: "gmail.googleapis.com", Method: "PUT",
			Path: "/upload/gmail/v1/users/me/drafts/r123?uploadType=multipart", ContentType: "multipart/related; boundary=b"}, "gmail-uploading"},
		{"gmail resumable drafts.update", Request{Host: "gmail.googleapis.com", Method: "PUT",
			Path: "/resumable/upload/gmail/v1/users/me/drafts/r123?uploadType=resumable"}, "gmail-uploading"},
		{"gmail resumable send stays sending", Request{Host: "gmail.googleapis.com", Method: "POST",
			Path: "/resumable/upload/gmail/v1/users/me/messages/send?uploadType=resumable", ContentType: "application/json"}, "gmail-sending"},
		{"youtube resumable start", Request{Host: "youtube.googleapis.com", Method: "POST",
			Path: "/upload/youtube/v3/videos?uploadType=resumable&part=snippet", ContentType: "application/json"}, "youtube-uploading"},
		// google-batch
		{"gmail batch", Request{Host: "gmail.googleapis.com", Method: "POST", Path: "/batch",
			ContentType: "multipart/mixed; boundary=b"}, "gmail-batch"},
		{"drive v3 batch", Request{Host: "www.googleapis.com", Method: "POST", Path: "/batch/drive/v3"}, "google-drive-batch"},
		{"drive v2 batch", Request{Host: "www.googleapis.com", Method: "POST", Path: "/batch/drive/v2"}, "google-drive-batch"},
		// drive-v2
		{"drive v2 insert", Request{Host: "www.googleapis.com", Method: "POST", Path: "/upload/drive/v2/files?uploadType=multipart"}, "google-drive-uploading"},
		{"drive v2 resumable insert", Request{Host: "www.googleapis.com", Method: "POST", Path: "/resumable/upload/drive/v2/files"}, "google-drive-uploading"},
		{"drive v2 update is PUT", Request{Host: "www.googleapis.com", Method: "PUT", Path: "/upload/drive/v2/files/f1?uploadType=media"}, "google-drive-uploading"},
		{"drive v2 download", Request{Host: "www.googleapis.com", Method: "GET", Path: "/drive/v2/files/f1?alt=media"}, "google-drive-downloading"},
		{"drive v2 export", Request{Host: "www.googleapis.com", Method: "GET", Path: "/drive/v2/files/f1/export?mimeType=application/pdf"}, "google-drive-downloading"},
		{"drive v3 upload without uploadType", Request{Host: "www.googleapis.com", Method: "POST", Path: "/upload/drive/v3/files"}, "google-drive-uploading"},
		// graph-beta, graph-case-insensitive, graph-dollar-batch
		{"graph beta sendMail", Request{Host: "graph.microsoft.com", Method: "POST", Path: "/beta/me/sendMail"}, "outlook-sending"},
		{"graph upper-case sendMail", Request{Host: "graph.microsoft.com", Method: "POST", Path: "/V1.0/ME/SENDMAIL"}, "outlook-sending"},
		{"graph lower-case beta onedrive upload", Request{Host: "graph.microsoft.com", Method: "PUT",
			Path: "/BETA/Me/Drive/Items/AbC!12/content"}, "ms-onedrive-uploading"},
		{"graph beta teams post", Request{Host: "graph.microsoft.com", Method: "POST", Path: "/beta/teams/t/channels/c/messages",
			ContentType: "application/json"}, "ms-teams-posting"},
		{"graph $batch", Request{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/$batch", ContentType: "application/json"}, "ms-base-graph-batch"},
		{"graph beta $BATCH", Request{Host: "graph.microsoft.com", Method: "POST", Path: "/beta/$BATCH"}, "ms-base-graph-batch"},
		{"graph encoded $batch", Request{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/%24batch"}, "ms-base-graph-batch"},
		{"graph encoded $value", Request{Host: "graph.microsoft.com", Method: "GET", Path: "/v1.0/me/messages/m/attachments/a/%24value"}, "outlook-downloading"},
		// telegram-case-insensitive
		{"telegram SENDDOCUMENT", Request{Host: "api.telegram.org", Method: "POST", Path: "/bot123:abc/SENDDOCUMENT",
			ContentType: "multipart/form-data; boundary=x"}, "telegram-bot-uploading"},
		{"telegram senddocument", Request{Host: "api.telegram.org", Method: "POST", Path: "/bot123:abc/senddocument",
			ContentType: "multipart/form-data; boundary=x"}, "telegram-bot-uploading"},
		// discord-versions
		{"discord v9 upload", Request{Host: "discord.com", Method: "POST", Path: "/api/v9/channels/1/messages",
			ContentType: "multipart/form-data; boundary=x"}, "discord-uploading"},
		{"discord unversioned post", Request{Host: "discord.com", Method: "POST", Path: "/api/channels/1/messages",
			ContentType: "application/json"}, "discord-posting"},
		{"discord v6 webhook upload", Request{Host: "discord.com", Method: "POST", Path: "/api/v6/webhooks/1/tok",
			ContentType: "multipart/form-data; boundary=x"}, "discord-uploading"},
		{"discord v10 still", Request{Host: "discord.com", Method: "POST", Path: "/api/v10/channels/1/messages",
			ContentType: "application/json"}, "discord-posting"},
		// dropbox-arg: the argument header is not assumed
		{"dropbox upload with arg parameter", Request{Host: "content.dropboxapi.com", Method: "POST",
			Path: "/2/files/upload?arg=%7B%22path%22%3A%22%2Fa%22%7D", ContentType: "text/plain; charset=dropbox-cors-hack"}, "dropbox-uploading"},
		{"dropbox download with arg parameter", Request{Host: "content.dropboxapi.com", Method: "POST",
			Path: "/2/files/download?arg=%7B%7D"}, "dropbox-downloading"},
		{"dropbox encoded path letter", Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/%75pload"}, "dropbox-uploading"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.Classify(c.req)
			if got.App != c.app || got.Basis != BasisRequestRule {
				t.Fatalf("got %+v, want %s", got, c.app)
			}
		})
	}
}

// TestSecChild3Bounds: the widened rules still need their function. Other Graph, Discord and Google paths stay
// with the parent, and non-literal parts stay non-literal.
func TestSecChild3Bounds(t *testing.T) {
	s := embeddedSet(t)
	for _, req := range []Request{
		{Host: "graph.microsoft.com", Method: "GET", Path: "/beta/me/sendMail"},            // wrong method
		{Host: "graph.microsoft.com", Method: "POST", Path: "/v2.0/me/sendMail"},           // not a Graph version
		{Host: "graph.microsoft.com", Method: "GET", Path: "/v1.0/$batch"},                 // batch is POST
		{Host: "discord.com", Method: "POST", Path: "/api/v5/channels/1/messages"},         // discontinued
		{Host: "www.googleapis.com", Method: "POST", Path: "/batch/youtube/v3"},            // not in the evidence
		{Host: "gmail.googleapis.com", Method: "GET", Path: "/upload/gmail/v1/users/me/x"}, // a GET is no upload
		{Host: "api.telegram.org", Method: "POST", Path: "/bot1:a/sendMessage"},            // not an upload method
		{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/%2Eupload"},       // encoded dot: refused
	} {
		if got := s.Classify(req); got.Basis == BasisRequestRule {
			t.Errorf("%s %s: got child %s", req.Method, req.Path, got.App)
		}
	}
}

func TestPathCaseInsensitiveLoad(t *testing.T) {
	ok := `{"hosts": ["content.dropboxapi.com"], "methods": ["POST"], "path_patterns": ["/2/Files/{x}"], "path_case_insensitive": true}`
	set, err := Load([]byte(child(ok)), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{"/2/files/Upload": true, "/2/FILES/x": true, "/2/files": false, "/3/files/x": false} {
		if got := set.Classify(Request{Host: "content.dropboxapi.com", Method: "POST", Path: path}).Basis == BasisRequestRule; got != want {
			t.Errorf("%s: matched %v, want %v", path, got, want)
		}
	}
	for name, rules := range map[string]string{
		"false":   `{"hosts": ["content.dropboxapi.com"], "path_prefixes": ["/2/"], "path_case_insensitive": false}`,
		"string":  `{"hosts": ["content.dropboxapi.com"], "path_prefixes": ["/2/"], "path_case_insensitive": "yes"}`,
		"no path": `{"hosts": ["content.dropboxapi.com"], "methods": ["POST"], "path_case_insensitive": true}`,
		"encoded": `{"hosts": ["content.dropboxapi.com"], "path_prefixes": ["/2/%41"]}`,
	} {
		if _, err := Load([]byte(child(rules)), pack(t), Options{}); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestDecodeSafe(t *testing.T) {
	for in, want := range map[string]string{
		"/a":                "/a",
		"/%24batch":         "/$batch",
		"/%41%7e%5F":        "/A~_",
		"/r%C3%A9sum%C3%A9": "/r%C3%A9sum%C3%A9", // UTF-8 stays encoded
		"/a%3Fb%23c":        "/a%3Fb%23c",        // '?' and '#' stay encoded
		"/a%2":              "/a%2",
		"/a%zz":             "/a%zz",
	} {
		if got := decodeSafe(in); got != want {
			t.Errorf("decodeSafe(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.Contains(decodeSafe("/%2F"), "//") {
		t.Fatal("an encoded slash must never decode")
	}
}
