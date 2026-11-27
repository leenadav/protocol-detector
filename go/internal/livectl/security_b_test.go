package livectl

import (
	"sync"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// SR-62: concurrent starts create exactly one run, the others are refused at once; status reads have no side
// effect (they never renew the lease); only a heartbeat naming the current run renews it.
func TestSecurityConcurrentStartsCreateOneRunAndStatusIsSideEffectFree(t *testing.T) {
	dir := t.TempDir()
	m := manager(t, dir)
	var wg sync.WaitGroup
	var mu sync.Mutex
	started, refused := 0, 0
	var first *ojson.Object
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, err := m.Start("lo", ojson.FromInt(30), "synthetic", nil)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				started++
				first = snapshot
			} else if err.Error() == "A live capture is already running." {
				refused++
			}
		}()
	}
	wg.Wait()
	if started != 1 || refused != 7 {
		t.Fatalf("%d runs started and %d refused, want 1 and 7", started, refused)
	}
	id := runID(t, first)
	awaitReady(t, dir)
	m.mu.Lock()
	old := time.Now().Add(-10 * time.Second)
	m.lease = old
	m.mu.Unlock()
	for i := 0; i < 5; i++ {
		_ = m.StateView()
		_ = m.Interfaces()
	}
	m.mu.Lock()
	unchanged := m.lease.Equal(old)
	m.mu.Unlock()
	if !unchanged {
		t.Fatal("a status read renewed the lease")
	}
	if m.Heartbeat("not-the-run") || m.Heartbeat(nil) {
		t.Fatal("a heartbeat for another run was accepted")
	}
	if !m.Heartbeat(id) {
		t.Fatal("the run's own heartbeat was refused")
	}
	m.Stop(nil, nil)
	until(t, "the run to stop", func() bool { return phase(m) != "running" })
}
