package serve

import (
	"bufio"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// This file is http.server.BaseHTTPRequestHandler as the reference's Handler uses it (Python 3.13): HTTP/1.0
// responses, one request per connection, the request line and headers read under the same limits, the
// same error pages. A request is parsed exactly as the reference parses it so that a malformed one is
// answered (or dropped) the same way; the routes then see the same path, headers and body.

const (
	maxLine      = 65536 // http.client._MAXLINE
	maxHeaders   = 100   // http.client._MAXHEADERS
	socketWait   = 15 * time.Second
	serverHeader = "protodetect-go"
)

var phrases = map[int][2]string{
	200: {"OK", "Request fulfilled, document follows"},
	202: {"Accepted", "Request accepted, processing continues off-line"},
	400: {"Bad Request", "Bad request syntax or unsupported method"},
	403: {"Forbidden", "Request forbidden -- authorization will not help"},
	404: {"Not Found", "Nothing matches the given URI"},
	413: {"Content Too Large", "Content is too large"},
	414: {"URI Too Long", "URI is too long"},
	429: {"Too Many Requests", `The user has sent too many requests in a given amount of time ("rate limiting")`},
	431: {"Request Header Fields Too Large", "The server is unwilling to process the request because its header fields are too large"},
	501: {"Not Implemented", "Server does not support this operation"},
	505: {"HTTP Version Not Supported", "Cannot fulfill request"},
}

const errorPage = "<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        <title>Error response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n        <p>Error code: %d</p>\n        <p>Message: %s.</p>\n        <p>Error code explanation: %d - %s.</p>\n    </body>\n</html>\n"

// timedConn is socket.settimeout(15): every read and write waits at most that long.
type timedConn struct{ net.Conn }

func (c timedConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(socketWait))
	return c.Conn.Read(p)
}

func (c timedConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(socketWait))
	return c.Conn.Write(p)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded)
}

// header is one parsed header (name and value as ISO-8859-1 bytes).
type header struct{ name, value string }

// request is what the handler reads from one connection.
type request struct {
	conn    net.Conn
	in      *bufio.Reader
	out     *bufio.Writer
	command string
	path    string
	version string // "HTTP/0.9" for a two-word request: then no status line or headers are written
	headers []header
}

// get is self.headers.get(name): the first header of that name, case-insensitively.
func (r *request) get(name string) (string, bool) {
	for _, h := range r.headers {
		if strings.EqualFold(h.name, name) {
			return h.value, true
		}
	}
	return "", false
}

// readLine is rfile.readline(limit).
func readLine(in *bufio.Reader, limit int) (string, error) {
	var b []byte
	for len(b) < limit {
		c, err := in.ReadByte()
		if err != nil {
			return string(b), err
		}
		b = append(b, c)
		if c == '\n' {
			break
		}
	}
	return string(b), nil
}

// pySplit is str.split() on ISO-8859-1 text: runs of whitespace, none at the ends.
func pySplit(s string) []string {
	space := func(c byte) bool {
		return c == ' ' || (c >= '\t' && c <= '\r') || (c >= 0x1c && c <= 0x1f) || c == 0x85 || c == 0xa0
	}
	var words []string
	for i := 0; i < len(s); {
		for i < len(s) && space(s[i]) {
			i++
		}
		j := i
		for j < len(s) && !space(s[j]) {
			j++
		}
		if j > i {
			words = append(words, s[i:j])
		}
		i = j
	}
	return words
}

// sendError is send_error(code, message, explain).
func (r *request) sendError(code int, message, explain string) {
	p := phrases[code]
	if message == "" {
		message = p[0]
	}
	if explain == "" {
		explain = p[1]
	}
	body := fmt.Sprintf(errorPage, code, html.EscapeString(message), code, html.EscapeString(explain))
	body = strings.NewReplacer("&#39;", "'", "&#34;", `"`).Replace(body) // html.escape(quote=False)
	r.statusLine(code, message)
	r.header("Connection", "close")
	r.header("Content-Type", "text/html;charset=utf-8")
	r.header("Content-Length", strconv.Itoa(len(body)))
	r.endHeaders()
	if r.command != "HEAD" {
		r.out.WriteString(body)
	}
}

// statusLine is send_response(code, message): the status line, Server and Date.
func (r *request) statusLine(code int, message string) {
	if message == "" {
		message = phrases[code][0]
	}
	if r.version != "HTTP/0.9" {
		fmt.Fprintf(r.out, "HTTP/1.0 %d %s\r\n", code, toLatin1(message))
	}
	r.header("Server", serverHeader)
	r.header("Date", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
}

func (r *request) header(name, value string) {
	if r.version != "HTTP/0.9" {
		fmt.Fprintf(r.out, "%s: %s\r\n", name, value)
	}
}

func (r *request) endHeaders() {
	if r.version != "HTTP/0.9" {
		r.out.WriteString("\r\n")
	}
}

// toLatin1 encodes UTF-8 text of code points below 256 as ISO-8859-1 bytes (the status line's encoding).
func toLatin1(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xff {
			r = '?'
		}
		b = append(b, byte(r))
	}
	return string(b)
}

// parse is handle_one_request up to the method call: false when the request was answered or dropped.
func (r *request) parse() bool {
	raw, err := readLine(r.in, maxLine+1)
	if (err != nil && err != io.EOF) || raw == "" {
		return false // a closed or timed-out connection gets no answer
	}
	if len(raw) > maxLine {
		r.version = "" // handle_one_request clears request_version before answering 414
		r.sendError(414, "", "")
		return false
	}
	r.version = "HTTP/0.9"
	line := strings.TrimRight(raw, "\r\n")
	words := pySplit(line)
	if len(words) == 0 {
		return false
	}
	if len(words) >= 3 {
		version := words[len(words)-1]
		bad := func() bool {
			r.version = "" // "Send the error response with a status line and headers."
			r.sendError(400, "Bad request version ("+pyRepr(version)+")", "")
			return false
		}
		if !strings.HasPrefix(version, "HTTP/") {
			return bad()
		}
		number := strings.SplitN(version, "/", 2)[1]
		parts := strings.Split(number, ".")
		if len(parts) != 2 {
			return bad()
		}
		var major, minor int
		for i, part := range parts {
			if part == "" || len(part) > 10 {
				return bad()
			}
			for k := 0; k < len(part); k++ {
				if part[k] < '0' || part[k] > '9' {
					return bad() // isdigit() admits ² ³ ¹, which int() then refuses: the same answer
				}
			}
			n, _ := strconv.Atoi(part)
			if i == 0 {
				major = n
			} else {
				minor = n
			}
		}
		_ = minor
		r.version = version
		if major >= 2 {
			r.sendError(505, "Invalid HTTP version ("+number+")", "")
			return false
		}
		r.version = version
	}
	if len(words) < 2 || len(words) > 3 {
		r.version = ""
		r.sendError(400, "Bad request syntax ("+pyRepr(line)+")", "")
		return false
	}
	command, path := words[0], words[1]
	if len(words) == 2 && command != "GET" {
		r.version = ""
		r.sendError(400, "Bad HTTP/0.9 request type ("+pyRepr(command)+")", "")
		return false
	}
	r.command, r.path = command, path
	if strings.HasPrefix(r.path, "//") {
		r.path = "/" + strings.TrimLeft(r.path, "/")
	}
	if len(words) == 2 {
		return true // HTTP/0.9: no headers are read
	}
	return r.readHeaders()
}

// readHeaders is http.client.parse_headers and email's header parsing (compat32).
func (r *request) readHeaders() bool {
	var lines []string
	for {
		line, err := readLine(r.in, maxLine+1)
		if err != nil && err != io.EOF {
			return false // TimeoutError or a reset while reading headers: the reference answers nothing
		}
		if len(line) > maxLine {
			r.sendError(431, "Line too long", "got more than 65536 bytes when reading header line")
			return false
		}
		lines = append(lines, line)
		if len(lines) > maxHeaders {
			r.sendError(431, "Too many headers", "got more than 100 headers")
			return false
		}
		if line == "\r\n" || line == "\n" || line == "" {
			break
		}
	}
	r.headers = emailHeaders(strings.Join(lines, ""))
	return true
}

// emailHeaders is email.parser.Parser().parsestr(text) for the header block: lines split at \r\n, \r or \n;
// the block ends at an empty line or the first line that is not a header; "From " lines and lines starting
// with ':' are defects and are skipped; continuation lines are appended to the value.
func emailHeaders(text string) []header {
	var lines []string
	for len(text) > 0 {
		k := strings.IndexAny(text, "\r\n")
		if k < 0 {
			lines = append(lines, text)
			break
		}
		end := k + 1
		if text[k] == '\r' && k+1 < len(text) && text[k+1] == '\n' {
			end = k + 2
		}
		lines = append(lines, text[:end])
		text = text[end:]
	}
	var block []string
	for _, line := range lines {
		if !headerLine(line) {
			break
		}
		block = append(block, line)
	}
	var out []header
	var name string
	var value []string
	flush := func() {
		if name == "" {
			return
		}
		first := value[0][len(name)+1:]
		v := strings.TrimLeft(first, " \t") + strings.Join(value[1:], "")
		out = append(out, header{name, strings.TrimRight(v, "\r\n")})
		name, value = "", nil
	}
	for i, line := range block {
		if line[0] == ' ' || line[0] == '\t' {
			if name != "" {
				value = append(value, line)
			}
			continue
		}
		flush()
		if strings.HasPrefix(line, "From ") {
			if i == len(block)-1 {
				break
			}
			continue
		}
		k := strings.IndexByte(line, ':')
		if k <= 0 {
			continue
		}
		name, value = line[:k], []string{line}
	}
	flush()
	return out
}

// headerLine is email.feedparser.headerRE: ^(From |[\041-\071\073-\176]*:|[\t ]).
func headerLine(line string) bool {
	if line == "" || line == "\n" || line == "\r\n" || line == "\r" {
		return false
	}
	if strings.HasPrefix(line, "From ") || line[0] == ' ' || line[0] == '\t' {
		return true
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == ':' {
			return true
		}
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return false
}
