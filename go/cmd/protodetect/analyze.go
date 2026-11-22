package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/policy"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
)

// Exit status of a request the Go backend does not serve (the Python adapter then runs the reference).
const exitNotPorted = 64

var analyzeFlags = map[string]bool{"--json": true, "--events-only": true, "--sessions": true, "--hostnames": true, "--fingerprints": true,
	"--heuristics": true, "--certificates": true}
var analyzeValues = map[string]bool{"--signatures": true, "--policy": true, "--observation": true, "--checksums": true, "--continuation": true,
	"--content-version": true, "--udp-hint": true, "--tcp-hint": true, "--crc32c-byte-limit": true, "--content": true}

const analyzeUsage = "usage: protodetect analyze CAPTURE [--json] [--events-only] [--sessions] [--hostnames] [--signatures FILE] [--fingerprints] " +
	"[--heuristics] [--policy FILE] [--certificates] [--observation handshake|asymmetric|midstream] [--checksums ignore|audit|verify] " +
	"[--continuation BYTES] [--content-version VERSION] [--udp-hint FAMILY] [--tcp-hint FAMILY] [--crc32c-byte-limit BYTES] [--content PACK]"

func sortedNames(m map[string]bool) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// pyInt is Python's int(text) as argparse applies it (type=int).
func pyInt(text string) (int, bool) {
	t := strings.TrimFunc(text, unicode.IsSpace)
	digits := strings.TrimLeft(t, "+-")
	if digits == "" || len(t)-len(digits) > 1 || strings.HasPrefix(digits, "_") || strings.HasSuffix(digits, "_") || strings.Contains(digits, "__") {
		return 0, false
	}
	v, err := strconv.Atoi(strings.ReplaceAll(t, "_", ""))
	return v, err == nil
}

// knownRelease reports whether this binary carries the content release (the reference's argparse choices).
func knownRelease(v string) bool {
	for _, r := range content.Releases() {
		if r == v {
			return true
		}
	}
	return false
}

// releaseChoices is argparse's "choose from" list (Python 3.13: each choice quoted).
func releaseChoices() string {
	quoted := []string{}
	for _, r := range content.Releases() {
		quoted = append(quoted, "'"+r+"'")
	}
	return strings.Join(quoted, ", ")
}

// osErrorText renders an I/O error as Python's str(OSError): "[Errno N] Message: 'path'".
func osErrorText(err error) string {
	var pathErr *os.PathError
	var errno syscall.Errno
	if errors.As(err, &pathErr) && errors.As(pathErr.Err, &errno) {
		message := errno.Error()
		if message != "" {
			message = strings.ToUpper(message[:1]) + message[1:]
		}
		return fmt.Sprintf("[Errno %d] %s: '%s'", int(errno), message, pathErr.Path)
	}
	return err.Error()
}

func runAnalyze(args []string, stdout, stderr io.Writer) int {
	usage := func(message string) int {
		fmt.Fprintln(stderr, analyzeUsage)
		fmt.Fprintln(stderr, "protodetect analyze: error: "+message)
		return 2
	}
	flags, values := map[string]bool{}, map[string]string{}
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(arg, "=")
		switch {
		case arg == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case analyzeFlags[arg]:
			flags[arg] = true
		case analyzeValues[name]:
			if !hasValue {
				if i+1 >= len(args) {
					return usage("argument " + name + ": expected one argument")
				}
				i++
				value = args[i]
			}
			values[name] = value
		case strings.HasPrefix(arg, "-") && arg != "-":
			return usage("unrecognized arguments: " + arg)
		default:
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return usage("exactly one capture path is required")
	}
	opts := analyze.Options{JSON: flags["--json"], EventsOnly: flags["--events-only"], Sessions: flags["--sessions"],
		IncludeHostnames: flags["--hostnames"], Fingerprints: flags["--fingerprints"], Heuristics: flags["--heuristics"],
		Certificates: flags["--certificates"], Observation: "handshake", Checksums: "ignore", CRC32CByteLimit: 4096}
	if v, ok := values["--observation"]; ok {
		if v != "handshake" && v != "asymmetric" && v != "midstream" {
			return usage("argument --observation: invalid choice: '" + v + "' (choose from handshake, asymmetric, midstream)")
		}
		opts.Observation = v
	}
	if v, ok := values["--checksums"]; ok {
		if v != "ignore" && v != "audit" && v != "verify" {
			return usage("argument --checksums: invalid choice: '" + v + "' (choose from ignore, audit, verify)")
		}
		opts.Checksums = v
	}
	for _, numeric := range []struct {
		name   string
		target *int
	}{{"--continuation", &opts.Continuation}, {"--crc32c-byte-limit", &opts.CRC32CByteLimit}} {
		if v, ok := values[numeric.name]; ok {
			n, valid := pyInt(v)
			if !valid {
				return usage("argument " + numeric.name + ": invalid int value: '" + v + "'")
			}
			*numeric.target = n
		}
	}
	if v, ok := values["--udp-hint"]; ok {
		if !engine.DatagramHints[v] {
			return usage("argument --udp-hint: invalid choice: '" + v + "' (choose from " + sortedNames(engine.DatagramHints) + ")")
		}
		opts.UDPHint = v
	}
	if v, ok := values["--tcp-hint"]; ok {
		if !engine.Ported[v] {
			return usage("argument --tcp-hint: invalid choice: '" + v + "' (choose from " + sortedNames(engine.Ported) + ")")
		}
		opts.TCPHint = v
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "Capture error: %s\n", osErrorText(err))
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
		// Rollback (content.select): the server-name catalog of an earlier release, laid over the embedded pack.
		if _, external := values["--content"]; external {
			fmt.Fprintf(stderr, "not ported in the Go backend: --content-version %s with --content (the pack is release %s)\n", v, pack.Release.Version)
			return exitNotPorted
		}
		if !knownRelease(v) {
			return usage("argument --content-version: invalid choice: '" + v + "' (choose from " + releaseChoices() + ")")
		}
		if pack, err = content.EmbeddedRelease(v); err != nil {
			return fail(err)
		}
	}
	if path, ok := values["--signatures"]; ok {
		text, err := signatures.ReadFile(path)
		if err != nil {
			return fail(err)
		}
		if opts.Signatures, err = signatures.FromJSON(text, pack); err != nil {
			if strings.Contains(err.Error(), "not ported in the Go backend") {
				fmt.Fprintln(stderr, err.Error())
				return exitNotPorted
			}
			return fail(err)
		}
	}
	if path, ok := values["--policy"]; ok {
		if opts.Policy, err = policy.FromPath(path, pack); err != nil {
			return fail(err)
		}
	}
	if _, err := analyze.Run(positional[0], pack, opts, stdout); err != nil {
		if strings.Contains(err.Error(), "not ported in the Go backend") {
			fmt.Fprintln(stderr, err.Error())
			return exitNotPorted
		}
		return fail(err)
	}
	return 0
}
