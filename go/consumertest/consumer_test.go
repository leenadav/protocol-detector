package consumer

import (
	"errors"
	"os"
	"testing"

	"github.com/leenadav/protocol-detector/go/detector"
)

// Observer is the interface a host defines for what it needs (working plan 5.1). The host's thin adapter
// below implements it over the library, so a library API change stays inside the adapter.
type Observer interface {
	Begin(id string) (FlowObserver, error)
}

// FlowObserver is the per-connection half of the host's interface.
type FlowObserver interface {
	Observe(clientToServer bool, data []byte) (done bool)
	Expire()
	Finish() (outcome string, family string)
}

type adapter struct{ engine *detector.Engine }

type flowAdapter struct{ flow *detector.Flow }

var (
	_ Observer     = adapter{}
	_ FlowObserver = flowAdapter{}
)

func (a adapter) Begin(id string) (FlowObserver, error) {
	f, err := a.engine.NewFlow(id)
	if err != nil {
		return nil, err
	}
	return flowAdapter{f}, nil
}

func (f flowAdapter) Observe(clientToServer bool, data []byte) bool {
	d := detector.ServerToClient
	if clientToServer {
		d = detector.ClientToServer
	}
	u, err := f.flow.Feed(d, data)
	return err != nil || u.Done
}

func (f flowAdapter) Expire() { _ = f.flow.Expire() }

func (f flowAdapter) Finish() (string, string) {
	s := f.flow.Close().Direction(detector.ClientToServer)
	return s.Outcome.String(), s.Family
}

func TestConsumerUsesThePublicPackageWithoutRepositoryFiles(t *testing.T) {
	// Run from an empty directory: nothing may depend on the working directory or fixture paths.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	engine, err := detector.New(detector.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	var obs Observer = adapter{engine}
	for _, c := range []struct {
		name, outcome, family string
		client                []byte
		done                  bool // identified SSH keeps watching for KEXINIT evidence until expiry
	}{
		{"http", "identified", "http", []byte("GET / HTTP/1.1\r\nHost: consumer.example.test\r\n\r\n"), true},
		{"ssh", "identified", "ssh", []byte("SSH-2.0-OpenSSH_9.6\r\n"), false},
		{"smtp outside the default profile", "outside_profile", "smtp", []byte("EHLO client.example.test\r\n"), true},
		{"silent", "incomplete", "", nil, false},
	} {
		flow, err := obs.Begin(c.name)
		if err != nil {
			t.Fatal(err)
		}
		if c.client != nil {
			if done := flow.Observe(true, c.client); done != c.done {
				t.Errorf("%s: done=%v, want %v", c.name, done, c.done)
			}
		}
		flow.Expire()
		if outcome, family := flow.Finish(); outcome != c.outcome || family != c.family {
			t.Errorf("%s: %s %q, want %s %q", c.name, outcome, family, c.outcome, c.family)
		}
	}
	if st := engine.Stats(); st.Active != 0 || st.Admitted != 4 {
		t.Errorf("stats %+v", st)
	}
	if _, err := detector.New(detector.Config{}); !errors.Is(err, detector.ErrInvalidConfig) {
		t.Errorf("empty config: %v", err)
	}
}
