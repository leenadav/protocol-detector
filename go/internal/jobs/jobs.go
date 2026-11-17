// Package jobs ports presentation/jobs.py: bounded asynchronous worker jobs with admission control (contract
// C15). At most MaxRunning workers run and MaxQueued wait; the rest are refused at once. Each job has a
// lifetime, finished outcomes are kept in bounded number for a bounded time, and cancel and shutdown are
// idempotent. Reading a job's state has no side effect. Views are ojson objects in the reference's key order.
//
// States: queued -> running -> done | failed | cancelled | expired; every terminal state carries a reason.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// Command is argv and standard input for one worker (worker_command in server.py).
type Command func(kind string, payload []byte) (argv []string, stdin []byte, err error)

// AdmissionError is the reference's AdmissionError: the caller answers 429.
type AdmissionError struct{ Message string }

func (e *AdmissionError) Error() string { return e.Message }

type job struct {
	id, kind, state   string
	submitted         float64
	started, finished ojson.Value // nil or float64
	reason            ojson.Value
	result            ojson.Value
	payload           []byte
	process           *exec.Cmd
	cancelProcess     context.CancelFunc
}

// Runner is JobRunner.
type Runner struct {
	command               Command
	MaxRunning, MaxQueued int
	Lifetime              time.Duration
	Retain                int
	RetainSeconds         float64
	Clock                 func() float64
	mu                    sync.Mutex
	cond                  *sync.Cond
	order                 []string // insertion order of jobs (an OrderedDict)
	jobs                  map[string]*job
	queue                 []string
	running               map[string]*job
	closed                bool
	counts                map[string]int64
}

var countKeys = []string{"submitted", "rejected", "done", "failed", "cancelled", "expired"}

// Monotonic is seconds on a monotonic clock that starts at this process's start plus one (the reference reads
// time.monotonic(); only differences of these values mean anything in either).
func Monotonic() func() float64 {
	origin := time.Now()
	return func() float64 { return 1 + time.Since(origin).Seconds() }
}

// New is JobRunner(command_factory, max_running, max_queued, lifetime, retain, retain_seconds).
func New(command Command, maxRunning, maxQueued int, lifetime time.Duration, retain int, retainSeconds float64, clock func() float64) (*Runner, error) {
	if maxRunning < 1 || maxQueued < 0 || lifetime <= 0 || retain < 1 {
		return nil, errors.New("Invalid job runner limits")
	}
	if clock == nil {
		clock = Monotonic()
	}
	r := &Runner{command: command, MaxRunning: maxRunning, MaxQueued: maxQueued, Lifetime: lifetime, Retain: retain,
		RetainSeconds: retainSeconds, Clock: clock, jobs: map[string]*job{}, running: map[string]*job{}, counts: map[string]int64{}}
	r.cond = sync.NewCond(&r.mu)
	return r, nil
}

func tokenURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Submit admits a job or returns an AdmissionError; it never waits for a worker.
func (r *Runner) Submit(kind string, payload []byte) (*ojson.Object, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, &AdmissionError{"The server is shutting down."}
	}
	r.expireRetained()
	if len(r.queue) >= r.MaxQueued && len(r.running) >= r.MaxRunning {
		r.counts["rejected"]++
		return nil, &AdmissionError{"Too many analyses in progress; retry in a moment."}
	}
	j := &job{id: tokenURLSafe(12), kind: kind, state: "queued", submitted: r.Clock(), payload: payload}
	r.jobs[j.id] = j
	r.order = append(r.order, j.id)
	r.queue = append(r.queue, j.id)
	r.counts["submitted"]++
	r.pump()
	return view(j, true), nil
}

// pump starts queued jobs while slots are free (the lock is held).
func (r *Runner) pump() {
	for len(r.queue) > 0 && len(r.running) < r.MaxRunning {
		j := r.jobs[r.queue[0]]
		r.queue = r.queue[1:]
		payload := j.payload
		j.payload = nil
		argv, stdin, err := r.command(j.kind, payload)
		if err != nil {
			r.finish(j, "failed", "worker could not start: "+err.Error())
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		process := exec.CommandContext(ctx, argv[0], argv[1:]...)
		// The worker and anything it starts are one process group, killed together on cancel or expiry; Wait
		// is bounded so a straggler holding the output pipe cannot keep the job running.
		process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		process.Cancel = func() error { return syscall.Kill(-process.Process.Pid, syscall.SIGKILL) }
		process.WaitDelay = 2 * time.Second
		var output limitedBuffer
		process.Stdout = &output
		process.Stdin = bytesReader(stdin)
		if err := process.Start(); err != nil {
			cancel()
			r.finish(j, "failed", "worker could not start: "+startErrorClass(err))
			continue
		}
		j.state, j.started = "running", r.Clock()
		j.process, j.cancelProcess = process, cancel
		r.running[j.id] = j
		go r.run(j, process, ctx, cancel, &output)
	}
}

// startErrorClass is error.__class__.__name__ of the reference's Popen OSError.
func startErrorClass(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOENT:
			return "FileNotFoundError"
		case syscall.EACCES, syscall.EPERM:
			return "PermissionError"
		}
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "FileNotFoundError"
	}
	return "OSError"
}

func (r *Runner) run(j *job, process *exec.Cmd, ctx context.Context, cancel context.CancelFunc, output *limitedBuffer) {
	timer := time.AfterFunc(r.Lifetime, cancel)
	_ = process.Wait() // a stdin copy error is not the worker's status; returncode decides, as in the reference
	expired := !timer.Stop() && ctx.Err() != nil
	cancel()
	state, reason := "done", ojson.Value(nil)
	switch code := returnCode(process); {
	case expired:
		state, reason = "expired", fmt.Sprintf("worker exceeded its %d second lifetime", int(r.Lifetime.Seconds()))
	case code != 0:
		state, reason = "failed", fmt.Sprintf("worker exited with status %d", code)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, j.id)
	if current, ok := r.jobs[j.id]; ok && current == j && j.state == "running" {
		if state == "done" {
			result, err := ojson.Decode(output.Bytes())
			if err != nil {
				state, reason, result = "failed", "worker returned no readable result", nil
			} else if o, ok := result.(*ojson.Object); ok {
				if e, has := o.Get("error"); has {
					state, reason, result = "failed", truncate(pyStr(e), 512), nil
				}
			}
			j.result = result
		}
		r.finish(j, state, reason)
	}
	r.pump()
	r.cond.Broadcast()
}

// returnCode is Popen.returncode: the exit status, or minus the signal that ended the process.
func returnCode(process *exec.Cmd) int {
	if process.ProcessState == nil {
		return -1
	}
	if ws, ok := process.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int(ws.Signal())
	}
	return process.ProcessState.ExitCode()
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n])
}

func pyStr(v ojson.Value) string {
	if s, ok := v.(string); ok {
		return s
	}
	text, _ := ojson.Dumps(v) // workers write strings here; anything else is rendered as JSON
	return text
}

func (r *Runner) finishedCount() int {
	n := 0
	for _, id := range r.order {
		if s := r.jobs[id].state; s != "queued" && s != "running" {
			n++
		}
	}
	return n
}

// finish is _finish (the lock is held).
func (r *Runner) finish(j *job, state string, reason ojson.Value) {
	j.state, j.reason, j.finished = state, reason, r.Clock()
	j.payload = nil
	r.counts[state]++
	for r.finishedCount() > r.Retain {
		for i, id := range r.order {
			if s := r.jobs[id].state; s != "queued" && s != "running" {
				r.remove(i)
				break
			}
		}
	}
}

func (r *Runner) remove(i int) {
	delete(r.jobs, r.order[i])
	r.order = append(r.order[:i:i], r.order[i+1:]...)
}

func (r *Runner) expireRetained() {
	now := r.Clock()
	for i := 0; i < len(r.order); {
		j := r.jobs[r.order[i]]
		if f, ok := j.finished.(float64); ok && now-f > r.RetainSeconds {
			r.remove(i)
			continue
		}
		i++
	}
}

func view(j *job, withResult bool) *ojson.Object {
	out := ojson.NewObject("id", j.id, "kind", j.kind, "state", j.state, "submitted", j.submitted,
		"started", j.started, "finished", j.finished, "reason", j.reason)
	if withResult && j.state == "done" {
		out.Set("result", j.result)
	}
	return out
}

// Get is get(job_id): side-effect free; nil for an unknown or expired job.
func (r *Runner) Get(id string, withResult bool) *ojson.Object {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	if !ok {
		return nil
	}
	return view(j, withResult)
}

// State is a job's state ("" when unknown) and its view.
func (r *Runner) Wait(id string, timeout float64) *ojson.Object {
	deadline := r.Clock() + timeout
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		j, ok := r.jobs[id]
		if !ok {
			return nil
		}
		if j.state != "queued" && j.state != "running" {
			return view(j, true)
		}
		remaining := deadline - r.Clock()
		if remaining <= 0 {
			return view(j, true)
		}
		wake := time.AfterFunc(time.Duration(minFloat(remaining, 0.5)*float64(time.Second)), func() {
			r.mu.Lock()
			r.cond.Broadcast()
			r.mu.Unlock()
		})
		r.cond.Wait()
		wake.Stop()
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// Cancel is cancel(job_id): idempotent; nil for an unknown job.
func (r *Runner) Cancel(id string) *ojson.Object {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	if !ok {
		return nil
	}
	if j.state != "queued" && j.state != "running" {
		return view(j, true)
	}
	for i, q := range r.queue {
		if q == id {
			r.queue = append(r.queue[:i:i], r.queue[i+1:]...)
			break
		}
	}
	if running, ok := r.running[id]; ok {
		delete(r.running, id)
		if running.cancelProcess != nil {
			running.cancelProcess() // kills the worker; its goroutine reaps it
		}
	}
	r.finish(j, "cancelled", "cancelled by the operator")
	r.pump()
	return view(j, true)
}

// Status is status().
func (r *Runner) Status() *ojson.Object {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := ojson.NewObject()
	for _, k := range countKeys {
		counts.Set(k, ojson.FromInt(r.counts[k]))
	}
	return ojson.NewObject("running", ojson.FromInt(int64(len(r.running))), "queued", ojson.FromInt(int64(len(r.queue))),
		"max_running", ojson.FromInt(int64(r.MaxRunning)), "max_queued", ojson.FromInt(int64(r.MaxQueued)),
		"lifetime_seconds", lifetimeValue(r.Lifetime), "counts", counts)
}

// lifetimeValue is the lifetime as the reference was given it: the integer 25, or a float otherwise.
func lifetimeValue(d time.Duration) ojson.Value {
	if d%time.Second == 0 {
		return ojson.FromInt(int64(d / time.Second))
	}
	return d.Seconds()
}

// Shutdown is shutdown(): nothing is left running or queued after it returns.
func (r *Runner) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, id := range r.queue {
		r.finish(r.jobs[id], "cancelled", "server shut down before the job started")
	}
	r.queue = nil
	for id, j := range r.running {
		if j.cancelProcess != nil {
			j.cancelProcess()
		}
		delete(r.running, id)
		if j.state == "running" {
			r.finish(j, "cancelled", "server shut down while the job ran")
		}
	}
	r.cond.Broadcast()
}
