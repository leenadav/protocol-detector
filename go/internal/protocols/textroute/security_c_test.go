package textroute_test

import (
	"fmt"
	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/protocols/textroute"
)

func scIRC(line string) (string, error) {
	p := textroute.NewIRC(8192)
	if _, err := p.Feed([]byte(line)); err != nil {
		return "", err
	}
	if !p.Done() {
		return "", fmt.Errorf("not done")
	}
	return parsertest.Rendered(*p.Result()), nil
}

// SR-52 (IRC part): an IRC line identifies only within its grammar: at most 512 bytes with CRLF and at most 15
// parameters; nicknames, hosts and texts are never emitted.
func TestIRCLinesStayWithinTheirGrammarAndNeverLeak(t *testing.T) {
	params := func(n int) string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("P%d", i)
		}
		return strings.Join(out, " ")
	}
	got, err := scIRC(":secrethost.example 005 secretnick " + params(14) + "\r\n")
	if err != nil || !strings.Contains(got, "irc") {
		t.Fatalf("15 parameters: %s %v", got, err)
	}
	if strings.Contains(got, "secret") {
		t.Fatalf("a name was emitted: %s", got)
	}
	if got, err := scIRC(":secrethost.example 005 secretnick " + params(15) + "\r\n"); err == nil {
		t.Fatalf("16 parameters identified: %s", got)
	}
	head := ":secrethost.example 372 secretnick :"
	if _, err := scIRC(head + strings.Repeat("x", 510-len(head)) + "\r\n"); err != nil {
		t.Fatalf("a 512-byte line was refused: %v", err)
	}
	if got, err := scIRC(head + strings.Repeat("x", 511-len(head)) + "\r\n"); err == nil {
		t.Fatalf("a 513-byte line identified: %s", got)
	}
	if got, err := scIRC("NICK secretnick\r\n"); err != nil || strings.Contains(got, "secretnick") {
		t.Fatalf("NICK: %s %v", got, err)
	}
}
