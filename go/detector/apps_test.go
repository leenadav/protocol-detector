package detector

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
)

func TestAppClassifierParentAndChild(t *testing.T) {
	c, err := NewAppClassifier(AppLimitsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	v := c.Classify(HTTPRequest{SNI: "gmail.googleapis.com", Host: "gmail.googleapis.com", Method: "POST",
		Path: "/upload/gmail/v1/users/me/messages?uploadType=media", ContentType: "message/rfc822", RequestBodyBytes: 900, ResponseBodyBytes: -1})
	if v.App != "gmail-uploading" || v.Container != "gmail" || v.Basis != "request_rule" || !v.Matches("gmail") ||
		!v.Matches("gmail-uploading") || !v.Matches("google-base") || v.HostOwner != "google-base" || v.Matches("gmail-sending") || v.Schema != AppSchemaVersion {
		t.Fatalf("verdict %+v", v)
	}
	if v := c.Classify(HTTPRequest{Host: "mail.google.com", Method: "GET", Path: "/"}); v.App != "gmail" || v.Container != "" || !v.Matches("gmail") {
		t.Fatalf("parent verdict %+v", v)
	}
	if len(c.ChildApps()) == 0 {
		t.Fatal("no child apps")
	}
	if _, err := NewAppClassifier(AppLimitsConfig{MaxRuleEvaluations: -1}); err == nil {
		t.Fatal("negative ceiling accepted")
	}
}

// TestAppClassifierLimitIsReported: a ceiling of one evaluation on a host with several rules is reported.
func TestAppClassifierLimitIsReported(t *testing.T) {
	c, err := NewAppClassifier(AppLimitsConfig{MaxRuleEvaluations: 1})
	if err != nil {
		t.Fatal(err)
	}
	v := c.Classify(HTTPRequest{Host: "gmail.googleapis.com", Method: "GET", Path: "/gmail/v1/users/me/labels"})
	if v.Limit != "child_rule_evaluations" || v.Container != "" || v.App != "google-base" || v.Evaluated != 1 {
		t.Fatalf("verdict %+v", v)
	}
}

func enumOf(t *testing.T, node interface{}) []string {
	var out []string
	for _, x := range node.(map[string]interface{})["enum"].([]interface{}) {
		out = append(out, x.(string))
	}
	sort.Strings(out)
	return out
}

// TestAppVerdictMatchesItsSchema keeps the record, its JSON keys and the closed vocabularies equal to
// go/detector/app-verdict.schema.json.
func TestAppVerdictMatchesItsSchema(t *testing.T) {
	data, err := os.ReadFile("app-verdict.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	c, _ := NewAppClassifier(AppLimitsConfig{})
	record, _ := json.Marshal(c.Classify(HTTPRequest{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload", ContentType: "application/octet-stream", HeaderNames: []string{"Dropbox-API-Arg"}}))
	var fields map[string]interface{}
	_ = json.Unmarshal(record, &fields)
	var keys, required []string
	for k := range fields {
		keys = append(keys, k)
	}
	for _, k := range schema["required"].([]interface{}) {
		required = append(required, k.(string))
	}
	sort.Strings(keys)
	sort.Strings(required)
	if !reflect.DeepEqual(keys, required) {
		t.Fatalf("record keys %v, schema %v", keys, required)
	}
	props := schema["properties"].(map[string]interface{})
	sorted := func(l []string) []string { l = append([]string{}, l...); sort.Strings(l); return l }
	if got := enumOf(t, props["basis"]); !reflect.DeepEqual(got, sorted(AppBases())) {
		t.Errorf("basis %v vs %v", got, AppBases())
	}
	if got := enumOf(t, props["reasons"].(map[string]interface{})["items"]); !reflect.DeepEqual(got, sorted(AppReasons())) {
		t.Errorf("reasons %v vs %v", got, AppReasons())
	}
	if got := enumOf(t, props["child_status"]); !reflect.DeepEqual(got, sorted(AppChildStatuses())) {
		t.Errorf("child statuses %v vs %v", got, AppChildStatuses())
	}
	if got := enumOf(t, props["limit"]); !reflect.DeepEqual(got, sorted(append(AppLimits(), ""))) {
		t.Errorf("limits %v vs %v", got, AppLimits())
	}
}

func TestAppClassifierIsSafeForConcurrentUse(t *testing.T) {
	c, _ := NewAppClassifier(AppLimitsConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if v := c.Classify(HTTPRequest{Host: "content.dropboxapi.com", Method: "POST", Path: "/2/files/upload", ContentType: "application/octet-stream", HeaderNames: []string{"Dropbox-API-Arg"}}); v.App != "dropbox-uploading" {
					t.Errorf("verdict %+v", v)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestMayBeFailsClosedOnUndetermined (SEC-CHILD-1): a deny entry for a child also holds when the request on one of
// the child's hosts was refused, capped or ambiguous; Matches alone does not.
func TestMayBeFailsClosedOnUndetermined(t *testing.T) {
	c, err := NewAppClassifier(AppLimitsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	upload := HTTPRequest{Host: "gmail.googleapis.com", Method: "POST", Path: "/upload/gmail/v1/users/me/messages?uploadType=media", ContentType: "message/rfc822"}
	if v := c.Classify(upload); v.App != "gmail-uploading" || v.ChildStatus != "matched" || !c.MayBe(v, "gmail-uploading") {
		t.Fatalf("canonical upload: %+v", v)
	}
	for _, path := range []string{"/upl%6fad/gmail/v1/users/me/messages?uploadType=media"} {
		bypass := upload
		bypass.Path = path
		if v := c.Classify(bypass); v.App != "gmail-uploading" {
			t.Fatalf("%s: %+v", path, v)
		}
	}
	for _, path := range []string{"/upload//gmail/v1/users/me/messages?uploadType=media", "/upload/gmail/v1/users/me/messages?uploadType=media&uploadType=media"} {
		bypass := upload
		bypass.Path = path
		v := c.Classify(bypass)
		if v.ChildStatus != "undetermined" || v.Matches("gmail-uploading") || !c.MayBe(v, "gmail-uploading") {
			t.Fatalf("%s: %+v (MayBe %v)", path, v, c.MayBe(v, "gmail-uploading"))
		}
		if c.MayBe(v, "dropbox-uploading") || c.MayBe(v, "no-such-child") {
			t.Fatalf("%s: MayBe holds for a child of another owner", path)
		}
	}
	if v := c.Classify(HTTPRequest{Host: "gmail.googleapis.com", Method: "GET", Path: "/gmail/v1/users/me/profile"}); v.ChildStatus != "none" || c.MayBe(v, "gmail-uploading") {
		t.Fatalf("decided request: %+v", v)
	}
}
