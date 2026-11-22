package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
)

// Exit status of a capture the presentation analysis refuses (the reference raises); stdout then holds
// {"error_type": ..., "error": ...}.
const exitRefused = 3

// maxPresentBytes bounds the capture read from standard input (the service's 8 MB upload limit).
const maxPresentBytes = 8 * 1024 * 1024

const presentUsage = "usage: protodetect present [--max-frames N] [--max-sessions N] [--max-events N] [--content PACK] < CAPTURE"

// runPresent is the presentation service's capture worker: a capture on standard input, the result of
// presentation/server.py analyze_bytes on standard output.
func runPresent(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func(message string) int {
		fmt.Fprintln(stderr, presentUsage)
		fmt.Fprintln(stderr, "protodetect present: error: "+message)
		return 2
	}
	limits := analyze.DefaultLimits
	targets := map[string]*int{"--max-frames": &limits.Frames, "--max-sessions": &limits.Sessions, "--max-events": &limits.Events}
	contentPath := ""
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		if _, known := targets[name]; !known && name != "--content" {
			return usage("unrecognized arguments: " + args[i])
		}
		if !hasValue {
			if i+1 >= len(args) {
				return usage("argument " + name + ": expected one argument")
			}
			i++
			value = args[i]
		}
		if name == "--content" {
			contentPath = value
			continue
		}
		n, valid := pyInt(value)
		if !valid {
			return usage("argument " + name + ": invalid int value: '" + value + "'")
		}
		*targets[name] = n
	}
	refuse := func(kind, message string) int {
		fmt.Fprintln(stdout, pyjson.Dumps(map[string]interface{}{"error_type": kind, "error": message}, "refusal",
			func(string) []string { return []string{"error_type", "error"} }))
		return exitRefused
	}
	started := time.Now()
	data, err := io.ReadAll(io.LimitReader(stdin, maxPresentBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "Capture error: %s\n", err)
		return 1
	}
	if len(data) > maxPresentBytes {
		return refuse("ValueError", "Capture exceeds 8 MB.")
	}
	var pack *content.Pack
	if contentPath != "" {
		pack, err = content.Load(contentPath)
	} else {
		pack, err = content.Embedded()
	}
	if err != nil {
		fmt.Fprintf(stderr, "Capture error: %s\n", osErrorText(err))
		return 1
	}
	text, err := analyze.Present(data, pack, limits, func() float64 { return float64(time.Since(started).Nanoseconds()) / 1e6 })
	if err != nil {
		if refused, ok := err.(*analyze.PresentError); ok {
			return refuse(refused.Type, refused.Message)
		}
		if strings.Contains(err.Error(), "not ported in the Go backend") {
			fmt.Fprintln(stderr, err.Error())
			return exitNotPorted
		}
		fmt.Fprintf(stderr, "Capture error: %s\n", err)
		return 1
	}
	fmt.Fprintln(stdout, text)
	return 0
}
