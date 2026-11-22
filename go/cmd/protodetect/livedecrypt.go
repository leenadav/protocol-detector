package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/livedecrypt"
)

const liveDecryptUsage = "usage: protodetect live-decrypt --interface NAME --filter BPF --duration SECONDS [--no-limits] < {\"keylog_path\": PATH}\n" +
	"       protodetect live-decrypt --replay [--capture-id ID] < SCRIPT"

// runLiveDecrypt is presentation/poc_decryption/live.py: bounded live capture with key-log decoding. The key-log
// path arrives on standard input, never in the argument list; a failure is a fixed code and sentence.
func runLiveDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func(message string) int {
		fmt.Fprintln(stderr, liveDecryptUsage)
		fmt.Fprintln(stderr, "protodetect live-decrypt: error: "+message)
		return 2
	}
	flags, values := map[string]bool{}, map[string]string{}
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		switch name {
		case "--replay", "--no-limits":
			flags[name] = true
		case "--interface", "--filter", "--duration", "--capture-id", "--content":
			if !hasValue {
				if i+1 >= len(args) {
					return usage("argument " + name + ": expected one argument")
				}
				i++
				value = args[i]
			}
			values[name] = value
		default:
			return usage("unrecognized arguments: " + args[i])
		}
	}
	var pack *content.Pack
	var err error
	if path, ok := values["--content"]; ok {
		pack, err = content.Load(path)
	} else {
		pack, err = content.Embedded()
	}
	if err != nil {
		fmt.Fprintf(stderr, "Capture error: %s\n", osErrorText(err))
		return 1
	}
	if flags["--replay"] {
		return livedecrypt.Replay(stdin, pack, values["--capture-id"], stdout)
	}
	iface, hasInterface := values["--interface"]
	filter, hasFilter := values["--filter"]
	duration, valid := pyInt(values["--duration"])
	if !hasInterface || !hasFilter || !valid {
		return usage("the following arguments are required: --interface, --filter, --duration")
	}
	return livedecrypt.Run(stdin, iface, filter, duration, !flags["--no-limits"], pack, stdout)
}
