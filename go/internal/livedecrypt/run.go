package livedecrypt

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/decrypt"
	"github.com/leenadav/protocol-detector/go/internal/live"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
)

const stopReason = "Capture stopped before initial message completed"

// maxOperation bounds one replay operation's data: a pipe read never exceeds 64 KiB and the capture budget is
// 2 MiB, so nothing a real run could feed is larger than the budget plus one read.
const maxOperation = Limit + 65536

// worker is one live decryption run: its decoder and where its events go.
type worker struct {
	decoder *Decoder
	out     io.Writer
}

func newWorker(pack *content.Pack, captureID string, out io.Writer) (*worker, error) {
	w := &worker{out: out}
	decoder, err := NewDecoder(pack, captureID, func(e live.Event) { fmt.Fprintln(out, live.JSON(e)) })
	if err != nil {
		return nil, err
	}
	w.decoder = decoder
	return w, nil
}

func (w *worker) progress(elapsed float64) {
	fmt.Fprintln(w.out, live.JSON(w.decoder.Monitor.Summary(elapsed, false, nil, nil)))
	fmt.Fprintln(w.out, `{"type": "decryption", "report": `+w.decoder.Snapshot()+`, "provisional": true}`)
}

// finish publishes the final report and summary after every connection was finalized.
func (w *worker) finish(elapsed float64, stats map[string]int, order []string) {
	quality := "unverified"
	if _, reported := stats["dropped_by_kernel"]; reported {
		quality = "no_kernel_drops_reported"
	}
	rendered := make(map[string]interface{}, len(stats))
	for key, value := range stats {
		rendered[key] = value
	}
	fmt.Fprintln(w.out, `{"type": "decryption", "report": `+w.decoder.Snapshot()+`, "provisional": false, "capture_stats": `+
		pyjson.Dumps(rendered, "stats", func(string) []string { return order })+`, "capture_quality": "`+quality+`"}`)
	fmt.Fprintln(w.out, live.JSON(w.decoder.Monitor.SummaryWithStats(elapsed, true, stats, order)))
}

// code maps a failure to its sanitized code.
func code(err error) string {
	switch e := err.(type) {
	case *KeyLogError:
		return e.Code
	case *decrypt.Error:
		if e.Code == decrypt.BudgetExhausted {
			return "budget"
		}
		return "key_log"
	case *os.PathError, *os.SyscallError, *exec.Error, *json.SyntaxError, *json.UnmarshalTypeError:
		return "key_log"
	}
	return "internal"
}

// fail retracts everything and publishes the failure as a fixed code and sentence: never key-file contents,
// paths or parser input.
func (w *worker) fail(err error) {
	name := code(err)
	reason := ErrorCodes[name]
	_ = w.decoder.Monitor.InvalidateAll(reason, "all_observations_this_capture")
	fmt.Fprintf(w.out, "{\"type\": \"decryption\", \"report\": {\"connections\": [], \"frames\": %d, \"decrypted\": 0}}\n", w.decoder.Frames)
	fmt.Fprintln(w.out, pyjson.Dumps(map[string]interface{}{"type": "error", "reason": reason, "code": name}, "error",
		func(string) []string { return []string{"type", "reason", "code"} }))
}

// Replay drives the worker from a script instead of a capture and a clock (tests and the differential): each
// operation is a kind byte, a big-endian float64 clock value, a big-endian uint32 length and that many bytes.
// K appends key-log text, P feeds a chunk of the pcap stream, T is the periodic tick (idle expiry, a progress
// summary and a provisional report), E ends the capture and publishes the final report and summary.
func Replay(script io.Reader, pack *content.Pack, captureID string, out io.Writer) int {
	w, err := newWorker(pack, captureID, out)
	if err != nil {
		return 1
	}
	defer w.decoder.Release()
	reader := bufio.NewReader(script)
	header := make([]byte, 13)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return 0
		}
		now := math.Float64frombits(binary.BigEndian.Uint64(header[1:9]))
		size := binary.BigEndian.Uint32(header[9:13])
		if size > maxOperation || math.IsNaN(now) || math.IsInf(now, 0) || now < 0 {
			// A declared length is never trusted with an allocation, and a clock value that is not a finite
			// time would be published as one (NaN is not JSON): the script ends here.
			return 0
		}
		// Memory follows the bytes that are really there, not the declared length.
		data, err := io.ReadAll(io.LimitReader(reader, int64(size)))
		if err != nil || len(data) != int(size) {
			return 0
		}
		var failure error
		switch header[0] {
		case 'K':
			failure = w.decoder.Advance(string(data))
		case 'P':
			if failure = w.decoder.Feed(data, now); failure == nil {
				failure = w.decoder.Advance("")
			}
		case 'T':
			if failure = w.decoder.Monitor.Tick(now); failure == nil {
				failure = w.decoder.Advance("")
			}
			if failure == nil {
				w.progress(now)
			}
		case 'E':
			if failure = w.decoder.Advance(""); failure == nil {
				failure = w.decoder.End(stopReason)
			}
			if failure == nil {
				w.finish(now, map[string]int{}, nil)
			}
		}
		if failure != nil {
			w.fail(failure)
			return 1
		}
	}
}

type piece struct {
	packets bool
	data    []byte
	end     bool
}

func pump(r io.Reader, packets bool, out chan<- piece, quit <-chan struct{}) {
	for {
		buffer := make([]byte, 65536)
		n, err := r.Read(buffer)
		if n > 0 {
			select {
			case out <- piece{packets: packets, data: buffer[:n]}:
			case <-quit:
				return
			}
		}
		if err != nil {
			select {
			case out <- piece{packets: packets, end: true}:
			case <-quit:
			}
			return
		}
	}
}

// Run is live.py main(): the key-log path arrives as one JSON line on standard input (never in the argument
// list), tcpdump captures the interface for at most duration seconds, and the worker publishes progress every
// second and a final report. It returns the exit status: 0, or 1 after a failure.
func Run(stdin io.Reader, iface, filter string, duration int, applyLimits bool, pack *content.Pack, out io.Writer) int {
	w, err := newWorker(pack, "", out)
	if err != nil {
		return 1
	}
	defer w.decoder.Release()
	began := time.Now()
	clock := func() float64 { return time.Since(began).Seconds() + 1 }
	started := clock()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if applyLimits {
		seconds := duration/2 + 10
		if seconds < 10 {
			seconds = 10
		}
		limitCPU(uint64(seconds))
	}
	var process *exec.Cmd
	var keys *KeyLog
	defer func() {
		if process != nil && process.ProcessState == nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
		if keys != nil {
			keys.Close()
		}
	}()
	failure := func() error {
		line, err := bufio.NewReaderSize(io.LimitReader(stdin, 4096), 4096).ReadString('\n')
		if err != nil && line == "" {
			return keyLogError("No key-log request.")
		}
		var options struct {
			Path *string `json:"keylog_path"`
		}
		if err := json.Unmarshal([]byte(line), &options); err != nil || options.Path == nil {
			return keyLogError("Invalid key-log request.")
		}
		if keys, err = OpenKeyLog(*options.Path); err != nil {
			return err
		}
		advance := func() error {
			text, err := keys.Read()
			if err != nil {
				return err
			}
			return w.decoder.Advance(text)
		}
		if err := advance(); err != nil {
			return err
		}
		command, err := live.CaptureCommand(iface, filter)
		if err != nil {
			return err
		}
		process = exec.Command(command[0], command[1:]...)
		packets, err := process.StdoutPipe()
		if err != nil {
			return err
		}
		errors, err := process.StderrPipe()
		if err != nil {
			return err
		}
		if err := process.Start(); err != nil {
			process = nil
			return err
		}
		diagnostics := live.NewDiagnostics()
		pieces, quit := make(chan piece), make(chan struct{})
		defer close(quit)
		go pump(packets, true, pieces, quit)
		go pump(errors, false, pieces, quit)
		open, stopped := 2, false
		deadline, tick, stoppingAt := clock()+float64(duration), 0.0, -1.0
		for open > 0 {
			now := clock()
			if (stopped || now >= deadline) && stoppingAt < 0 {
				_ = process.Process.Signal(os.Interrupt)
				stoppingAt = now
			}
			if stoppingAt >= 0 && now-stoppingAt > 3 {
				_ = process.Process.Kill()
				break
			}
			select {
			case <-signals:
				stopped = true
			case <-time.After(200 * time.Millisecond):
			case p := <-pieces:
				switch {
				case p.end:
					open--
				case p.packets:
					if err := w.decoder.Feed(p.data, now); err != nil {
						return err
					}
					if err := w.decoder.Advance(""); err != nil { // one bounded slice per read: the pipe keeps draining
						return err
					}
				default:
					diagnostics.Feed(p.data)
				}
			}
			if now >= tick {
				if err := w.decoder.Monitor.Tick(now); err != nil { // idle expiry happens here
					return err
				}
				if err := advance(); err != nil { // append-only key log; late keys wake waiting connections
					return err
				}
				w.progress(now - started)
				tick = clock() + 1
			}
		}
		exited := make(chan error, 1)
		go func() { exited <- process.Wait() }()
		var status error
		select {
		case status = <-exited:
		case <-time.After(3 * time.Second):
			return fmt.Errorf("tcpdump did not exit")
		}
		diagnostics.End()
		stats, order := diagnostics.Stats()
		if status != nil {
			return &KeyLogError{ErrorCodes["capture_failed"], "capture_failed"}
		}
		if stats["dropped_by_kernel"]+stats["dropped_by_interface"] > 0 {
			return &KeyLogError{ErrorCodes["capture_loss"], "capture_loss"}
		}
		if err := advance(); err != nil {
			return err
		}
		// Finalize every connection still tracked, exactly once, before the final report.
		if err := w.decoder.End(stopReason); err != nil {
			return err
		}
		w.finish(clock()-started, stats, order)
		return nil
	}()
	if failure != nil {
		w.fail(failure)
		return 1
	}
	return 0
}
