package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/livectl"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// runControlReplay drives the live control plane's run state with a script, one operation per line, and
// writes one JSON line per read: the differential harness (migration/parity/control_diff.py) runs the
// reference's LiveManager on the same script. No process is started and nothing is captured.
//
//	J <json>              echo: the document decoded and written again, or {"error": true}
//	N <capture id> <phase> a fresh run (start()'s reset of the retained state), phase is the state shown
//	I <json>              ingest one worker line (an object)
//	E <cursor> <limit>    events_since(cursor, limit), or {"error": message}
//	S                     snapshot()
//	V                     state_view()
//	X <json run id>       reset(run_id) answered as the server does: dict(state_view(), **outcome)
func runControlReplay(stdin io.Reader, stdout io.Writer) int {
	state := livectl.NewState(nil)
	in := bufio.NewReaderSize(stdin, 1<<20)
	out := bufio.NewWriter(stdout)
	defer out.Flush()
	emit := func(v ojson.Value) {
		text, err := ojson.Dumps(v)
		if err != nil {
			text = `{"error": "not JSON compliant"}`
		}
		out.WriteString(text + "\n")
	}
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		if line != "" {
			op, arg, _ := strings.Cut(line, " ")
			switch op {
			case "J":
				v, derr := ojson.Decode([]byte(arg))
				if _, nerr := ojson.Dumps(v); derr != nil || nerr != nil {
					emit(ojson.NewObject("error", true)) // json.loads or json.dumps(allow_nan=False) refused it
				} else {
					emit(v)
				}
			case "N":
				id, phase, _ := strings.Cut(arg, " ")
				state.Begin(id, "lo", phase)
				state.ExpireLease() // the reference harness sets the lease to monotonic 0
			case "I":
				v, derr := ojson.Decode([]byte(arg))
				if o, ok := v.(*ojson.Object); derr == nil && ok {
					state.Ingest(o)
				} else {
					fmt.Fprintln(out, `{"error": "not an event object"}`)
				}
			case "E":
				a, b, _ := strings.Cut(arg, " ")
				cursor, _ := strconv.ParseInt(a, 10, 64)
				limit, _ := strconv.ParseInt(b, 10, 64)
				page, rerr := state.EventsSince(cursor, limit)
				if rerr != nil {
					emit(ojson.NewObject("error", rerr.Error()))
				} else {
					emit(page)
				}
			case "S":
				emit(state.Snapshot())
			case "V":
				emit(state.StateView())
			case "X":
				runID, _ := ojson.Decode([]byte(arg))
				outcome := state.ResetIdle(runID) // the server resets first, then reads the state view
				emit(livectl.Merge(state.StateView(), outcome))
			default:
				fmt.Fprintln(out, `{"error": "unknown operation"}`)
			}
		}
		if err != nil {
			return 0
		}
	}
}
