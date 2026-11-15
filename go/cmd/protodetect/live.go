package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/live"
	"github.com/leenadav/protocol-detector/go/internal/policy"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
)

var liveFlags = map[string]bool{"--stdin": true, "--interfaces": true, "--all-events": true, "--hostnames": true, "--fingerprints": true,
	"--heuristics": true, "--certificates": true, "--json": true, "--replay-clock": true, "--check": true}
var liveValues = map[string]bool{"--interface": true, "-i": true, "--filter": true, "--duration": true, "--max-packets": true,
	"--stats-interval": true, "--max-connections": true, "--byte-limit": true, "--idle-timeout": true, "--udp-hint": true, "--tcp-hint": true,
	"--crc32c-byte-limit": true, "--signatures": true, "--policy": true, "--observation": true, "--checksums": true, "--continuation": true,
	"--content-version": true, "--content": true, "--capture-id": true}

const liveUsage = "usage: protodetect live (--interface NAME | --stdin | --interfaces) [--filter BPF] [--duration SECONDS] [--max-packets N] " +
	"[--stats-interval SECONDS] [--max-connections N] [--byte-limit BYTES] [--idle-timeout SECONDS] [--udp-hint FAMILY] [--tcp-hint FAMILY] " +
	"[--crc32c-byte-limit BYTES] [--all-events] [--hostnames] [--signatures FILE] [--fingerprints] [--heuristics] [--policy FILE] " +
	"[--certificates] [--observation MODE] [--checksums POLICY] [--continuation BYTES] [--content-version VERSION] [--json] " +
	"[--replay-clock] [--capture-id ID] [--check]"

// runLive is protocol_adapters/live_capture.py main(): passive, bounded live inspection. tcpdump owns capture.
// --check validates the options, the signature file and the policy file without capturing (exit status 0, or 64
// for a request this backend does not serve).
func runLive(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func(message string) int {
		fmt.Fprintln(stderr, liveUsage)
		fmt.Fprintln(stderr, "protodetect live: error: "+message)
		return 2
	}
	flags, values := map[string]bool{}, map[string]string{}
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		switch {
		case liveFlags[args[i]]:
			flags[args[i]] = true
		case liveValues[name]:
			if !hasValue {
				if i+1 >= len(args) {
					return usage("argument " + name + ": expected one argument")
				}
				i++
				value = args[i]
			}
			if name == "-i" {
				name = "--interface"
			}
			values[name] = value
		default:
			return usage("unrecognized arguments: " + args[i])
		}
	}
	iface, hasInterface := values["--interface"]
	sources := 0
	for _, chosen := range []bool{hasInterface, flags["--stdin"], flags["--interfaces"]} {
		if chosen {
			sources++
		}
	}
	if sources != 1 {
		return usage("one of the arguments --interface/-i --stdin --interfaces is required")
	}
	cfg := live.RunConfig{Duration: 60, StatsInterval: 10, ReplayClock: flags["--replay-clock"], CaptureID: values["--capture-id"],
		Options: live.Options{MaxConnections: 128, ByteLimit: 65536, IdleTimeout: 60, CRC32CByteLimit: 4096, AllEvents: flags["--all-events"],
			IncludeHostnames: flags["--hostnames"], Fingerprints: flags["--fingerprints"], Heuristics: flags["--heuristics"],
			Certificates: flags["--certificates"], Observation: "handshake", Checksums: "ignore"}}
	for _, numeric := range []struct {
		name   string
		target *float64
	}{{"--duration", &cfg.Duration}, {"--stats-interval", &cfg.StatsInterval}, {"--idle-timeout", &cfg.IdleTimeout}} {
		if v, ok := values[numeric.name]; ok {
			n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				return usage("argument " + numeric.name + ": invalid float value: '" + v + "'")
			}
			*numeric.target = n
		}
	}
	for _, numeric := range []struct {
		name   string
		target *int
	}{{"--max-packets", &cfg.MaxPackets}, {"--max-connections", &cfg.MaxConnections}, {"--byte-limit", &cfg.ByteLimit},
		{"--crc32c-byte-limit", &cfg.CRC32CByteLimit}, {"--continuation", &cfg.Continuation}} {
		if v, ok := values[numeric.name]; ok {
			n, valid := pyInt(v)
			if !valid {
				return usage("argument " + numeric.name + ": invalid int value: '" + v + "'")
			}
			*numeric.target = n
		}
	}
	if v, ok := values["--observation"]; ok {
		if v != "handshake" && v != "asymmetric" && v != "midstream" {
			return usage("argument --observation: invalid choice: '" + v + "' (choose from handshake, asymmetric, midstream)")
		}
		cfg.Observation = v
	}
	if v, ok := values["--checksums"]; ok {
		if v != "ignore" && v != "audit" && v != "verify" {
			return usage("argument --checksums: invalid choice: '" + v + "' (choose from ignore, audit, verify)")
		}
		cfg.Checksums = v
	}
	if v, ok := values["--udp-hint"]; ok {
		if !engine.DatagramHints[v] {
			return usage("argument --udp-hint: invalid choice: '" + v + "' (choose from " + sortedNames(engine.DatagramHints) + ")")
		}
		cfg.UDPHint = v
	}
	if v, ok := values["--tcp-hint"]; ok {
		if !engine.Ported[v] {
			return usage("argument --tcp-hint: invalid choice: '" + v + "' (choose from " + sortedNames(engine.Ported) + ")")
		}
		cfg.TCPHint = v
	}
	signal.Ignore(syscall.SIGPIPE) // a closed output pipe is a write error handled in emit, not a fatal signal
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
	if !finite(cfg.Duration) || cfg.Duration < 0 || cfg.MaxPackets < 0 || !finite(cfg.StatsInterval) || cfg.StatsInterval < 0 ||
		!finite(cfg.IdleTimeout) || cfg.IdleTimeout <= 0 || cfg.MaxConnections < 1 || cfg.MaxConnections > 1024 || cfg.ByteLimit < 64 ||
		cfg.ByteLimit > 65536 || cfg.CRC32CByteLimit < 0 || cfg.CRC32CByteLimit > 1048576 || cfg.Continuation < 0 || cfg.Continuation > cfg.ByteLimit {
		return usage("Invalid limits: connections 1..1024, bytes 64..65536, CRC-32C bytes 0..1048576, continuation 0..bytes, " +
			"finite nonnegative times, idle timeout >0")
	}
	var process *exec.Cmd
	out := &pipeWriter{w: stdout}
	emit := func(e live.Event) {
		if flags["--json"] {
			fmt.Fprintln(out, live.JSON(e))
		} else {
			live.Readable(out, e)
		}
		if out.broken {
			// The reader of our output went away (the reference returns 0 on BrokenPipeError): stop capturing.
			if process != nil && process.Process != nil {
				_ = process.Process.Kill()
			}
			exit(0)
		}
	}
	fail := func(err error) int {
		if flags["--check"] {
			fmt.Fprintln(stderr, osErrorText(err))
			return 1
		}
		emit(live.Event{Kind: "error", Fields: map[string]interface{}{"type": "error", "reason": osErrorText(err)}})
		return 1
	}
	var pack *content.Pack
	var err error
	if path, ok := values["--content"]; ok {
		pack, err = content.Load(path)
	} else {
		pack, err = content.Embedded()
	}
	if err != nil {
		return fail(err)
	}
	if v, ok := values["--content-version"]; ok && v != pack.Release.Version {
		fmt.Fprintf(stderr, "not ported in the Go backend: --content-version %s (the pack is release %s)\n", v, pack.Release.Version)
		return exitNotPorted
	}
	if path, ok := values["--signatures"]; ok {
		text, err := signatures.ReadFile(path)
		if err != nil {
			return fail(err)
		}
		if cfg.Signatures, err = signatures.FromJSON(text, pack); err != nil {
			if strings.Contains(err.Error(), "not ported in the Go backend") {
				fmt.Fprintln(stderr, err.Error())
				return exitNotPorted
			}
			return fail(err)
		}
	}
	if path, ok := values["--policy"]; ok {
		if cfg.Policy, err = policy.FromPath(path, pack); err != nil {
			return fail(err)
		}
	}
	if flags["--check"] {
		return 0
	}
	if flags["--interfaces"] {
		executable, err := exec.LookPath("tcpdump")
		if err != nil {
			return fail(&live.Error{Message: "tcpdump not found"})
		}
		listing := exec.Command(executable, "-D") // a fixed argv, no request data
		listing.Stdout, listing.Stderr = stdout, stderr
		if err := listing.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			return fail(err)
		}
		return 0
	}
	var stream io.Reader = stdin
	var processErrors io.Reader
	var filter interface{}
	if hasInterface {
		bpf := "tcp or udp"
		if v, ok := values["--filter"]; ok {
			bpf = v
		}
		command, err := live.CaptureCommand(iface, bpf)
		if err != nil {
			return fail(err)
		}
		process = exec.Command(command[0], command[1:]...)
		out, err := process.StdoutPipe()
		if err != nil {
			return fail(err)
		}
		errs, err := process.StderrPipe()
		if err != nil {
			return fail(err)
		}
		if err := process.Start(); err != nil {
			return fail(err)
		}
		stream, processErrors, filter = out, errs, command[len(command)-1]
	}
	var interfaceValue interface{}
	if hasInterface {
		interfaceValue = iface
	}
	hintValue := func(v string) interface{} {
		if v == "" {
			return nil
		}
		return v
	}
	emit(live.Event{Kind: "started", Fields: map[string]interface{}{"type": "started",
		"reason": "Passive initial-message inspection; no payload storage or TLS decryption", "interface": interfaceValue, "filter": filter,
		"tcp_hint": hintValue(cfg.TCPHint), "udp_hint": hintValue(cfg.UDPHint), "signatures": cfg.Signatures.Len(),
		"crc32c_byte_limit": cfg.CRC32CByteLimit, "max_reassembly_buffer_bytes": 4 * cfg.ByteLimit * cfg.MaxConnections,
		"content": map[string]interface{}{"version": pack.Release.Version, "digest": pack.Release.Digest}}})
	status, err := live.Run(stream, process, processErrors, pack, cfg, emit)
	if err != nil {
		if process != nil && process.ProcessState == nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
		if strings.Contains(err.Error(), "not ported in the Go backend") {
			fmt.Fprintln(stderr, err.Error())
			return exitNotPorted
		}
		return fail(err)
	}
	return status
}

// exit ends the process (a variable so tests can observe it).
var exit = os.Exit

// pipeWriter remembers a failed write: the reader of standard output closed it.
type pipeWriter struct {
	w      io.Writer
	broken bool
}

func (p *pipeWriter) Write(data []byte) (int, error) {
	if p.broken {
		return len(data), nil
	}
	if _, err := p.w.Write(data); err != nil {
		p.broken = true
	}
	return len(data), nil
}
