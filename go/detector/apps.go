package detector

import (
	"github.com/leenadav/protocol-detector/go/internal/childapp"
)

// AppSchemaVersion is the version of the AppVerdict record (go/detector/app-verdict.schema.json).
const AppSchemaVersion = 1

// HTTPRequest is what a decrypting proxy saw of one HTTP request: the client's TLS server name (empty for
// plaintext), the Host or :authority, the method, the origin-form path (query and fragment are ignored), the
// request Content-Type, and the body sizes in each direction (negative: unknown). WebSocket is an HTTP/1.1
// Upgrade: websocket or an HTTP/2 extended CONNECT for websocket. Values are borrowed for the call only.
type HTTPRequest struct {
	SNI               string
	Host              string
	Method            string
	Path              string
	ContentType       string
	RequestBodyBytes  int64
	ResponseBodyBytes int64
	WebSocket         bool
}

// AppVerdict is the application of one request in the enterprise App-ID model. App is the child application
// (for example dropbox-uploading) when a child rule matched, otherwise the catalog application of the server name
// (for example dropbox), or "" when the server name names none. Container is App's parent when App is a child,
// otherwise "". A rule never establishes an application on its own: it only refines the catalog's.
//
// Basis, Reasons and Limit are closed vocabularies (AppBases, AppReasons, AppLimits) and may be metric labels;
// App, Container and Rule come from the content data. A Limit other than "" means a work ceiling was hit: the
// verdict then names at most the parent, never a child. Nothing here is a permission.
type AppVerdict struct {
	App          string   `json:"app"`
	Container    string   `json:"container"`
	Rule         string   `json:"rule"`
	Basis        string   `json:"basis"`
	Reasons      []string `json:"reasons"`
	Limit        string   `json:"limit"`
	Evaluated    int      `json:"rules_evaluated"`
	ChildRelease string   `json:"child_release"`
	PackRelease  string   `json:"content_release"`
	Schema       int      `json:"schema_version"`
}

// Matches reports whether name is the verdict's application or its container, so one policy entry for a parent
// covers its children ("gmail" matches gmail and gmail-uploading).
func (v AppVerdict) Matches(name string) bool {
	return name != "" && (v.App == name || v.Container == name)
}

// AppBases, AppReasons and AppLimits list the closed vocabularies of AppVerdict.
func AppBases() []string {
	return []string{childapp.BasisNone, childapp.BasisServerName, childapp.BasisRequestRule}
}

// AppReasons lists AppVerdict.Reasons values.
func AppReasons() []string { return childapp.Reasons() }

// AppLimits lists AppVerdict.Limit values other than "".
func AppLimits() []string { return childapp.Limits() }

// AppClassifier maps requests to applications and child applications from the content data built into the
// binary. It is immutable and safe for concurrent use; it performs no I/O after construction.
type AppClassifier struct {
	set *childapp.Set
}

// AppLimitsConfig bounds the per-request work (zero values take the defaults).
type AppLimitsConfig struct {
	MaxRuleEvaluations int
	MaxPathBytes       int
}

// NewAppClassifier loads the built-in content pack and child-app component.
func NewAppClassifier(limits AppLimitsConfig) (*AppClassifier, error) {
	if limits.MaxRuleEvaluations < 0 || limits.MaxPathBytes < 0 || limits.MaxRuleEvaluations > 4096 || limits.MaxPathBytes > 1<<16 {
		return nil, ErrInvalidConfig
	}
	set, err := childapp.Builtin(childapp.Options{MaxRuleEvaluations: limits.MaxRuleEvaluations, MaxPathBytes: limits.MaxPathBytes})
	if err != nil {
		return nil, err
	}
	return &AppClassifier{set: set}, nil
}

// Classify returns the verdict of one request. A panic inside the matcher is recovered and reported as no
// application with the reason "panic"; it never becomes a match.
func (c *AppClassifier) Classify(r HTTPRequest) (v AppVerdict) {
	defer func() {
		if recover() != nil {
			v = AppVerdict{Basis: childapp.BasisNone, Reasons: []string{childapp.ReasonPanic}, Schema: AppSchemaVersion,
				ChildRelease: c.set.Release.Version}
		}
	}()
	res := c.set.Classify(childapp.Request{SNI: r.SNI, Host: r.Host, Method: r.Method, Path: r.Path, ContentType: r.ContentType,
		RequestBodyBytes: r.RequestBodyBytes, ResponseBodyBytes: r.ResponseBodyBytes, WebSocket: r.WebSocket})
	return AppVerdict{App: res.App, Container: res.Container, Rule: res.Rule, Basis: res.Basis,
		Reasons: append([]string{}, res.Reasons...), Limit: res.Limit, Evaluated: res.Evaluated, ChildRelease: res.Release,
		PackRelease: res.PackRelease, Schema: AppSchemaVersion}
}

// ChildApp describes one child application of the built-in data.
type ChildApp struct {
	Name, Container, Description string
	Risk                         int
	Evidence                     []string
}

// ChildApps lists the child applications in evaluation order.
func (c *AppClassifier) ChildApps() []ChildApp {
	var out []ChildApp
	for _, ch := range c.set.Children() {
		out = append(out, ChildApp{Name: ch.Name, Container: ch.Container, Description: ch.Description, Risk: ch.Risk,
			Evidence: append([]string{}, ch.Evidence...)})
	}
	return out
}
