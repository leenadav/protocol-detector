package detector

import (
	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/childapp"
)

// AppSchemaVersion is the version of the AppVerdict record (go/detector/app-verdict.schema.json).
const AppSchemaVersion = 1

// HTTPRequest is what a decrypting proxy saw of one HTTP request: the client's TLS server name (empty for
// plaintext), the Host or :authority, the method, the origin-form path (with its query), the
// request Content-Type, and the body sizes in each direction (negative: unknown). WebSocket is an HTTP/1.1
// Upgrade: websocket or an HTTP/2 extended CONNECT for websocket. The path may carry its query, which query
// conditions read byte for byte. Values are borrowed for the call only.
type HTTPRequest struct {
	SNI               string
	Host              string
	Method            string
	Path              string
	ContentType       string
	RequestBodyBytes  int64
	ResponseBodyBytes int64
	WebSocket         bool
	HeaderNames       []string // names of the request headers present (any case), for rules with header conditions
}

// AppVerdict is the application of one request in the enterprise App-ID model. App is the child application
// (for example dropbox-uploading) when a child rule matched, otherwise the catalog application of the server name
// (for example dropbox), or "" when the server name names none. Container is App's parent when App is a child,
// otherwise "". HostOwner is the catalog application that owns the server name (google-base for
// gmail.googleapis.com, ms-base for graph.microsoft.com), the identity a child refines; it equals App when no child
// matched and is "" when the server name names none. A rule never establishes an application on its own: it only
// refines the catalog's.
//
// Basis, Reasons and Limit are closed vocabularies (AppBases, AppReasons, AppLimits) and may be metric labels;
// App, Container and Rule come from the content data. A Limit other than "" means a work ceiling was hit: the
// verdict then names at most the parent, never a child. Nothing here is a permission.
//
// ChildStatus (AppChildStatuses) says whether the function was decided: "matched" (a child rule decided it), "none"
// (every candidate rule was evaluated on the normalized request and none applies), "not_applicable" (no catalog
// application) or "undetermined". "undetermined" is fail closed: a child rule of the host could apply but the
// request was refused, capped or ambiguous, so App is the parent and the child is unknown. A caller that denies a
// child must also deny "undetermined" for its container (AppClassifier.MayBe does both); Matches alone would fail
// open. A policy of internal/policy.FromJSONWithChildren does this for every deny that names a child (SEC-CHILD-8).
type AppVerdict struct {
	App          string   `json:"app"`
	Container    string   `json:"container"`
	HostOwner    string   `json:"host_owner"`
	Rule         string   `json:"rule"`
	Basis        string   `json:"basis"`
	Reasons      []string `json:"reasons"`
	Limit        string   `json:"limit"`
	ChildStatus  string   `json:"child_status"`
	Evaluated    int      `json:"rules_evaluated"`
	ChildRelease string   `json:"child_release"`
	PackRelease  string   `json:"content_release"`
	Schema       int      `json:"schema_version"`
}

// Matches reports whether name is the verdict's application, its container or the owner of its host, so one
// policy entry for a parent covers its children ("gmail" matches gmail and gmail-uploading) and a child never
// leaves its host owner's entry ("ms-base" matches outlook-sending on graph.microsoft.com; SEC-CHILD-2).
func (v AppVerdict) Matches(name string) bool {
	return name != "" && (v.App == name || v.Container == name || v.HostOwner == name)
}

// AppChildStatuses lists AppVerdict.ChildStatus values.
func AppChildStatuses() []string { return appid.ChildStatuses() }

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
				ChildStatus:  appid.ChildUndetermined,
				ChildRelease: c.set.Release.Version}
		}
	}()
	req := childapp.Request{SNI: r.SNI, Host: r.Host, Method: r.Method, Path: r.Path, ContentType: r.ContentType,
		RequestBodyBytes: r.RequestBodyBytes, ResponseBodyBytes: r.ResponseBodyBytes, WebSocket: r.WebSocket,
		HeaderNames: r.HeaderNames}
	res := c.set.Evaluate(&req)
	// The verdict's one allocation for an ordinary request: its own Reasons slice, never shared (PRO-522).
	return AppVerdict{App: res.App, Container: res.Container, HostOwner: res.HostOwner, Rule: res.Rule, Basis: res.Basis,
		Reasons: []string{res.Reason}, Limit: res.Limit, ChildStatus: res.ChildStatus, Evaluated: res.Evaluated, ChildRelease: res.Release,
		PackRelease: res.PackRelease, Schema: AppSchemaVersion}
}

// MayBe is the fail-closed test for a deny entry: true when v.Matches(name), and also when name is a child
// application of this classifier, v's child is undetermined (refused, capped or ambiguous) and v names an
// application that may own the child's hosts (its container or one it depends on), so the request may be that
// child. Use Matches for allow entries and MayBe for deny entries.
func (c *AppClassifier) MayBe(v AppVerdict, name string) bool {
	if v.Matches(name) {
		return true
	}
	if v.ChildStatus != appid.ChildUndetermined || v.App == "" {
		return false
	}
	child := c.set.Child(name)
	if child == nil {
		return false
	}
	// A child's rule hosts are owned by its container or by an application it depends on.
	if child.Container == v.App {
		return true
	}
	for _, owner := range child.DependsOn {
		if owner == v.App {
			return true
		}
	}
	return false
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
