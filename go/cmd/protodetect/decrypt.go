package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/keylogcap"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
)

const decryptUsage = "usage: protodetect decrypt-capture [--content PACK] < REQUEST   (8-byte big-endian capture length, the capture, the key log as UTF-8)"

// maxDecryptRequest bounds standard input: the capture limit, the key-log limit in UTF-8, the length prefix.
const maxDecryptRequest = 8 + keylogcap.MaxCapture + 4*262144 + 1024

// runDecrypt is the presentation service's decryption worker: a capture and its key log on standard input, the
// report of poc_decryption.capture.analyze_capture on standard output. Secrets arrive on standard input only
// (never in arguments or the environment) and no secret, payload or name is written anywhere.
func runDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	contentPath := ""
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		if name != "--content" || (!hasValue && i+1 >= len(args)) {
			fmt.Fprintln(stderr, decryptUsage)
			return 2
		}
		if !hasValue {
			i++
			value = args[i]
		}
		contentPath = value
	}
	request, err := io.ReadAll(io.LimitReader(stdin, maxDecryptRequest+1))
	if err != nil || len(request) < 8 || len(request) > maxDecryptRequest {
		fmt.Fprintln(stderr, "Capture error: invalid decryption request")
		return 1
	}
	size := binary.BigEndian.Uint64(request)
	if size > uint64(len(request)-8) || !utf8.Valid(request[8+size:]) {
		fmt.Fprintln(stderr, "Capture error: invalid decryption request")
		return 1
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
	text, err := keylogcap.Analyze(request[8:8+size], string(request[8+size:]), pack)
	if err != nil {
		if refused, ok := err.(*keylogcap.Refusal); ok {
			fmt.Fprintln(stdout, pyjson.Dumps(map[string]interface{}{"error_type": refused.Type, "error": refused.Message, "code": refused.Code},
				"refusal", func(string) []string { return []string{"error_type", "error", "code"} }))
			return exitRefused
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
