package signatures

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// pattern.go ports the part of CPython 3.13's re._parser that a signature pattern can use, so that the
// literal-anchor rule (signatures.compile_pattern) sees exactly the parse tree the reference sees: non-capturing
// groups are inlined, a one-item class becomes a literal, common prefixes of alternatives move out of the branch and
// all-single-character alternations become a class. The tree is then compiled to an equivalent Go regular
// expression over the Latin-1 image of the bytes. A signature only asks whether a match exists, which does not depend
// on the engine for patterns without backreferences or lookaround, provided every atom denotes the same byte set
// (Python's bytes semantics: ASCII-only IGNORECASE and \d \w \s, DOTALL). Constructs whose Python meaning RE2
// cannot express exactly are refused with errNotPorted, never approximated: inline flags, atomic groups,
// possessive repeats and $ anywhere but at the end of the pattern. Repeat counts above RE2's 1000 are split into
// pieces that denote the same language (writeRepeat), within a bound.

type opcode int

const (
	opLiteral opcode = iota
	opNotLiteral
	opAny
	opIn // class: items
	opBranch
	opSubpattern // capturing group (non-capturing groups are inlined)
	opRepeat     // greedy or lazy (existence does not depend on which)
	opPossessive
	opAt
	opAssert   // lookaround (always refused by the signature rules)
	opGroupRef // backreference (always refused by the signature rules)
	opFailure  // (?!) with an empty body
)

const maxRepeat = 4294967295 // CPython MAXREPEAT on 64-bit builds

type at int

const (
	atBeginning       at = iota // ^
	atBeginningString           // \A
	atEnd                       // $
	atEndString                 // \Z
	atBoundary                  // \b
	atNonBoundary               // \B
)

type classItem struct {
	kind     string // "literal", "range", "category", "negate"
	lo, hi   int
	category string // "digit", "not_digit", "space", "not_space", "word", "not_word"
}

type node struct {
	op       opcode
	value    int // literal value
	items    []classItem
	branches [][]node
	body     []node
	min, max int
	at       at
	group    int
}

// equal is the tuple equality the prefix factoring of _parse_sub compares. Groups, repeats, branches and assertions
// hold SubPattern objects, which compare by identity in Python, so two of them are never equal.
func (a node) equal(b node) bool {
	switch a.op {
	case opSubpattern, opRepeat, opPossessive, opBranch, opAssert, opGroupRef, opFailure:
		return false
	}
	if a.op != b.op || a.value != b.value || a.min != b.min || a.max != b.max || a.at != b.at || a.group != b.group ||
		len(a.items) != len(b.items) || len(a.branches) != len(b.branches) || len(a.body) != len(b.body) {
		return false
	}
	for i := range a.items {
		if a.items[i] != b.items[i] {
			return false
		}
	}
	for i := range a.branches {
		if !seqEqual(a.branches[i], b.branches[i]) {
			return false
		}
	}
	return seqEqual(a.body, b.body)
}

func seqEqual(a, b []node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].equal(b[i]) {
			return false
		}
	}
	return true
}

// patternError is a pattern Python rejects; errNotPorted one Python accepts but the Go backend refuses.
type patternError struct{ msg string }

func (e *patternError) Error() string { return e.msg }

type notPortedError struct{ what string }

func (e *notPortedError) Error() string {
	return "signature pattern construct not ported in the Go backend: " + e.what
}

type source struct {
	runes  []rune
	pos    int
	groups int            // groups opened so far; Python's state.groups is groups+1
	names  map[string]int // group name -> group number (state.groupdict)
	closed map[int]bool   // groups whose ")" was seen (state.checkgroup)
	// lookbehind is state.lookbehindgroups: 0 outside a lookbehind, else state.groups when the outermost began.
	lookbehind int
}

// failAt raises the re.error that _parser reports at rune position pos: "msg at position N", with the line and
// column appended when the pattern spans lines (re.error.__init__).
func (s *source) failAt(msg string, pos int) {
	text := fmt.Sprintf("%s at position %d", msg, pos)
	if pos > len(s.runes) {
		pos = len(s.runes)
	}
	newline := -1
	lines := 1
	for i, r := range s.runes[:pos] {
		if r == '\n' {
			lines++
			newline = i
		}
	}
	for _, r := range s.runes {
		if r == '\n' {
			text += fmt.Sprintf(" (line %d, column %d)", lines, pos-newline)
			break
		}
	}
	panic(&patternError{text})
}

// fail is source.error(msg, offset): the position is the next token's start minus offset.
func (s *source) fail(msg string, offset int) { s.failAt(msg, s.pos-offset) }

func runeLen(t string) int { return len([]rune(t)) }

// checkgroup is state.checkgroup: group gid exists and is closed.
func (s *source) checkgroup(gid int) bool { return gid <= s.groups && s.closed[gid] }

// checklookbehindgroup ports State.checklookbehindgroup.
func (s *source) checklookbehindgroup(gid int) {
	if s.lookbehind != 0 {
		if !s.checkgroup(gid) {
			s.fail("cannot refer to an open group", 0)
		}
		if gid >= s.lookbehind {
			s.fail("cannot refer to group defined in the same lookbehind subpattern", 0)
		}
	}
}

// getuntil ports Tokenizer.getuntil: tokens (an escape is one two-rune token) up to the terminator.
func (s *source) getuntil(terminator, name string) string {
	result := ""
	for {
		c, ok := s.get()
		if !ok {
			if result == "" {
				s.fail("missing "+name, 0)
			}
			s.fail(fmt.Sprintf("missing %s, unterminated name", terminator), runeLen(result))
		}
		if c == terminator {
			if result == "" {
				s.fail("missing "+name, 1)
			}
			return result
		}
		result += c
	}
}

// checkgroupname ports Tokenizer.checkgroupname for a str pattern (the first parse is of the str).
func (s *source) checkgroupname(name string, offset int) {
	if !isIdentifier(name) {
		s.fail("bad character in group name "+pyRepr(name), runeLen(name)+offset)
	}
}

func (s *source) next() (string, bool) {
	if s.pos >= len(s.runes) {
		return "", false
	}
	c := s.runes[s.pos]
	if c == '\\' {
		if s.pos+1 >= len(s.runes) {
			s.failAt("bad escape (end of pattern)", len(s.runes)-1)
		}
		return string(s.runes[s.pos : s.pos+2]), true
	}
	return string(c), true
}

func (s *source) get() (string, bool) {
	t, ok := s.next()
	if ok {
		s.pos += len([]rune(t))
	}
	return t, ok
}

func (s *source) match(c string) bool {
	if t, ok := s.next(); ok && t == c {
		s.pos += len([]rune(t))
		return true
	}
	return false
}

func (s *source) peekRune() rune {
	if s.pos >= len(s.runes) {
		return -1
	}
	return s.runes[s.pos]
}

func isHex(r rune) bool   { return strings.ContainsRune("0123456789abcdefABCDEF", r) }
func isOct(r rune) bool   { return r >= '0' && r <= '7' }
func isDigit(r rune) bool { return r >= '0' && r <= '9' }
func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

var escapes = map[string]int{`\a`: 7, `\b`: 8, `\f`: 12, `\n`: 10, `\r`: 13, `\t`: 9, `\v`: 11, `\\`: '\\'}
var categories = map[string]string{`\d`: "digit", `\D`: "not_digit", `\s`: "space", `\S`: "not_space", `\w`: "word", `\W`: "not_word"}
var atCodes = map[string]at{`\A`: atBeginningString, `\b`: atBoundary, `\B`: atNonBoundary, `\Z`: atEndString}

func (s *source) getwhile(n int, ok func(rune) bool) string {
	out := ""
	for i := 0; i < n; i++ {
		r := s.peekRune()
		if r < 0 || !ok(r) {
			break
		}
		out += string(r)
		s.pos++
	}
	return out
}

// escapeIn ports _class_escape for a bytes-compatible pattern: \u, \U and \N are rejected as the bytes recompile does.
func (s *source) escapeIn(escape string) classItem {
	if v, ok := escapes[escape]; ok {
		return classItem{kind: "literal", lo: v}
	}
	if c, ok := categories[escape]; ok {
		return classItem{kind: "category", category: c}
	}
	c := []rune(escape)[1]
	switch {
	case c == 'x':
		digits := s.getwhile(2, isHex)
		if len(digits) != 2 {
			s.fail("incomplete escape "+escape+digits, runeLen(escape+digits))
		}
		v, _ := strconv.ParseInt(digits, 16, 32)
		return classItem{kind: "literal", lo: int(v)}
	case isOct(c):
		digits := string(c) + s.getwhile(2, isOct)
		v, _ := strconv.ParseInt(digits, 8, 32)
		if v > 0o377 {
			s.fail("octal escape value \\"+digits+" outside of range 0-0o377", runeLen(digits)+1)
		}
		return classItem{kind: "literal", lo: int(v)}
	case isDigit(c), isASCIILetter(c):
		s.fail("bad escape "+escape, runeLen(escape))
	}
	return classItem{kind: "literal", lo: int(c)}
}

// escape ports _escape for a bytes-compatible pattern.
func (s *source) escape(escape string) node {
	if c, ok := categories[escape]; ok {
		return node{op: opIn, items: []classItem{{kind: "category", category: c}}}
	}
	if a, ok := atCodes[escape]; ok {
		return node{op: opAt, at: a}
	}
	if v, ok := escapes[escape]; ok {
		return node{op: opLiteral, value: v}
	}
	c := []rune(escape)[1]
	switch {
	case c == 'x':
		digits := s.getwhile(2, isHex)
		if len(digits) != 2 {
			s.fail("incomplete escape "+escape+digits, runeLen(escape+digits))
		}
		v, _ := strconv.ParseInt(digits, 16, 32)
		return node{op: opLiteral, value: int(v)}
	case c == '0':
		digits := "0" + s.getwhile(2, isOct)
		v, _ := strconv.ParseInt(digits, 8, 32)
		return node{op: opLiteral, value: int(v)}
	case isDigit(c):
		text := string(c)
		if isDigit(s.peekRune()) {
			text += string(s.peekRune())
			s.pos++
			if isOct([]rune(text)[0]) && isOct([]rune(text)[1]) && isOct(s.peekRune()) {
				text += string(s.peekRune())
				s.pos++
				v, _ := strconv.ParseInt(text, 8, 32)
				if v > 0o377 {
					s.fail("octal escape value \\"+text+" outside of range 0-0o377", runeLen(text)+1)
				}
				return node{op: opLiteral, value: int(v)}
			}
		}
		group, _ := strconv.Atoi(text)
		if group >= 1 && group <= s.groups {
			if !s.checkgroup(group) {
				s.fail("cannot refer to an open group", runeLen(text)+1)
			}
			s.checklookbehindgroup(group)
			return node{op: opGroupRef, group: group}
		}
		s.fail(fmt.Sprintf("invalid group reference %d", group), runeLen(text))
	case isASCIILetter(c):
		s.fail("bad escape "+escape, runeLen(escape))
	}
	return node{op: opLiteral, value: int(c)}
}

func uniq(items []classItem) []classItem {
	var out []classItem
	for _, it := range items {
		dup := false
		for _, o := range out {
			if o == it {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, it)
		}
	}
	return out
}

func (s *source) parseSub(nested int) []node {
	var items [][]node
	for {
		items = append(items, s.parse(nested+1))
		if !s.match("|") {
			break
		}
	}
	if len(items) == 1 {
		return items[0]
	}
	var sub []node
	for { // common prefix
		var prefix *node
		common := true
		for _, item := range items {
			if len(item) == 0 {
				common = false
				break
			}
			if prefix == nil {
				p := item[0]
				prefix = &p
			} else if !item[0].equal(*prefix) {
				common = false
				break
			}
		}
		if !common {
			break
		}
		for i := range items {
			items[i] = items[i][1:]
		}
		sub = append(sub, *prefix)
	}
	var set []classItem
	isSet := true
	for _, item := range items {
		if len(item) != 1 {
			isSet = false
			break
		}
		switch it := item[0]; {
		case it.op == opLiteral:
			set = append(set, classItem{kind: "literal", lo: it.value})
		case it.op == opIn && (len(it.items) == 0 || it.items[0].kind != "negate"):
			set = append(set, it.items...)
		default:
			isSet = false
		}
		if !isSet {
			break
		}
	}
	if isSet {
		return append(sub, node{op: opIn, items: uniq(set)})
	}
	return append(sub, node{op: opBranch, branches: items})
}

func (s *source) parse(nested int) []node {
	var sub []node
	for {
		this, ok := s.next()
		if !ok || this == "|" || this == ")" {
			break
		}
		s.get()
		switch {
		case strings.HasPrefix(this, `\`):
			sub = append(sub, s.escape(this))
		case !strings.Contains(`.\[{()*+?^$|`, this):
			sub = append(sub, node{op: opLiteral, value: int([]rune(this)[0])})
		case this == "[":
			sub = append(sub, s.class())
		case strings.Contains("*+?{", this):
			if !s.repeat(this, &sub) {
				continue
			}
		case this == ".":
			sub = append(sub, node{op: opAny})
		case this == "(":
			if n, ok := s.group(nested); ok {
				sub = append(sub, n...)
			}
		case this == "^":
			sub = append(sub, node{op: opAt, at: atBeginning})
		case this == "$":
			sub = append(sub, node{op: opAt, at: atEnd})
		}
	}
	var out []node
	for _, n := range sub { // unpack non-capturing groups
		if n.op == opSubpattern && n.group == 0 {
			out = append(out, n.body...)
		} else {
			out = append(out, n)
		}
	}
	return out
}

func (s *source) class() node {
	var set []classItem
	here := s.pos - 1 // the "["
	negate := s.match("^")
	for {
		this, ok := s.get()
		if !ok {
			s.failAt("unterminated character set", here)
		}
		if this == "]" && len(set) > 0 {
			break
		}
		var code1 classItem
		if strings.HasPrefix(this, `\`) {
			code1 = s.escapeIn(this)
		} else {
			code1 = classItem{kind: "literal", lo: int([]rune(this)[0])}
		}
		if s.match("-") {
			that, ok := s.get()
			if !ok {
				s.failAt("unterminated character set", here)
			}
			if that == "]" {
				set = append(set, code1, classItem{kind: "literal", lo: '-'})
				break
			}
			var code2 classItem
			if strings.HasPrefix(that, `\`) {
				code2 = s.escapeIn(that)
			} else {
				code2 = classItem{kind: "literal", lo: int([]rune(that)[0])}
			}
			if code1.kind != "literal" || code2.kind != "literal" || code2.lo < code1.lo {
				s.fail("bad character range "+this+"-"+that, runeLen(this)+1+runeLen(that))
			}
			set = append(set, classItem{kind: "range", lo: code1.lo, hi: code2.lo})
		} else {
			set = append(set, code1)
		}
	}
	set = uniq(set)
	if len(set) == 1 && set[0].kind == "literal" {
		if negate {
			return node{op: opNotLiteral, value: set[0].lo}
		}
		return node{op: opLiteral, value: set[0].lo}
	}
	if negate {
		set = append([]classItem{{kind: "negate"}}, set...)
	}
	return node{op: opIn, items: set}
}

// repeat ports the quantifier branch; it returns false when "{" turned out to be a literal.
func (s *source) repeat(this string, sub *[]node) bool {
	here := s.pos // just after the quantifier character
	min, max := 0, maxRepeat
	switch this {
	case "?":
		min, max = 0, 1
	case "*":
	case "+":
		min = 1
	case "{":
		if s.peekRune() == '}' {
			*sub = append(*sub, node{op: opLiteral, value: '{'})
			return false
		}
		lo := s.getwhile(1<<30, isDigit)
		hi := lo
		if s.match(",") {
			hi = s.getwhile(1<<30, isDigit)
		}
		if !s.match("}") {
			*sub = append(*sub, node{op: opLiteral, value: '{'})
			s.pos = here
			return false
		}
		if lo != "" {
			v, err := strconv.ParseInt(lo, 10, 64)
			if err != nil || v >= maxRepeat {
				panic(&patternError{"the repetition number is too large"})
			}
			min = int(v)
		}
		if hi != "" {
			v, err := strconv.ParseInt(hi, 10, 64)
			if err != nil || v >= maxRepeat {
				panic(&patternError{"the repetition number is too large"})
			}
			max = int(v)
			if max < min {
				s.failAt("min repeat greater than max repeat", here)
			}
		}
	}
	if len(*sub) == 0 || (*sub)[len(*sub)-1].op == opAt {
		s.failAt("nothing to repeat", here-runeLen(this))
	}
	last := (*sub)[len(*sub)-1]
	if last.op == opRepeat || last.op == opPossessive {
		s.failAt("multiple repeat", here-runeLen(this))
	}
	body := []node{last}
	if last.op == opSubpattern && last.group == 0 {
		body = last.body // a non-capturing group repeats its contents
	}
	op := opRepeat
	if !s.match("?") && s.match("+") {
		op = opPossessive
	}
	(*sub)[len(*sub)-1] = node{op: op, min: min, max: max, body: body}
	return true
}

func (s *source) group(nested int) ([]node, bool) {
	start := s.pos - 1 // the "("
	capture := true
	name, named := "", false
	if s.match("?") {
		char, ok := s.get()
		if !ok {
			s.fail("unexpected end of pattern", 0)
		}
		switch {
		case char == "P":
			if s.match("<") {
				name, named = s.getuntil(">", "group name"), true
				s.checkgroupname(name, 1)
			} else if s.match("=") {
				ref := s.getuntil(")", "group name")
				s.checkgroupname(ref, 1)
				gid, known := s.names[ref]
				if !known {
					s.fail("unknown group name "+pyRepr(ref), runeLen(ref)+1)
				}
				if !s.checkgroup(gid) {
					s.fail("cannot refer to an open group", runeLen(ref)+1)
				}
				s.checklookbehindgroup(gid)
				return []node{{op: opGroupRef, group: gid}}, true // refused by the signature rules
			} else {
				c, ok := s.get()
				if !ok {
					s.fail("unexpected end of pattern", 0)
				}
				s.fail("unknown extension ?P"+c, runeLen(c)+2)
			}
		case char == ":":
			capture = false
		case char == "#":
			for {
				if s.pos >= len(s.runes) {
					s.failAt("missing ), unterminated comment", start)
				}
				if c, _ := s.get(); c == ")" {
					return nil, false
				}
			}
		case char == "=" || char == "!" || char == "<":
			behind, outer := false, false
			if char == "<" {
				c, ok := s.get()
				if !ok {
					s.fail("unexpected end of pattern", 0)
				}
				if c != "=" && c != "!" {
					s.fail("unknown extension ?<"+c, runeLen(c)+2)
				}
				char, behind = c, true
				if s.lookbehind == 0 {
					s.lookbehind, outer = s.groups+1, true
				}
			}
			body := s.parseSub(nested + 1)
			if behind && outer {
				s.lookbehind = 0
			}
			if !s.match(")") {
				s.failAt("missing ), unterminated subpattern", start)
			}
			if char == "!" && len(body) == 0 {
				return []node{{op: opFailure}}, true
			}
			return []node{{op: opAssert, body: body}}, true
		case char == "(":
			panic(&notPortedError{"conditional backreference group"}) // GROUPREF_EXISTS: refused by the rules
		case char == ">":
			panic(&notPortedError{"atomic group"})
		case strings.Contains("aiLmsux-", char):
			panic(&notPortedError{"inline flags"})
		default:
			s.fail("unknown extension ?"+char, runeLen(char)+1)
		}
	}
	group := 0
	if capture {
		s.groups++
		group = s.groups
		if named {
			if was, dup := s.names[name]; dup {
				s.fail(fmt.Sprintf("redefinition of group name %s as group %d; was group %d", pyRepr(name), group, was), runeLen(name)+1)
			}
			s.names[name] = group
		}
	}
	body := s.parseSub(nested + 1)
	if !s.match(")") {
		s.failAt("missing ), unterminated subpattern", start)
	}
	if group != 0 {
		s.closed[group] = true
	}
	// group 0 marks a non-capturing group; _parse unpacks it into the enclosing sequence once the sequence ends,
	// so a quantifier that follows repeats the whole group.
	return []node{{op: opSubpattern, group: group, body: body}}, true
}

// isIdentifier is the group-name rule. Python checks str.isidentifier() on the str parse and rejects a non-ASCII
// name only on the bytes recompile (with a different message); the Go parser is bytes-compatible from the start and
// rejects it here, so only the wording of that error differs.
func isIdentifier(name string) bool { return validGroupName(name) }

// pyRepr is Python's repr() of a str: single quotes unless the text holds a single quote and no double quote,
// printable characters kept, the rest escaped as \xhh, \uhhhh or \Uhhhhhhhh.
func pyRepr(text string) string {
	quote := byte('\'')
	if strings.Contains(text, "'") && !strings.Contains(text, `"`) {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range text {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// latin1Error is str(UnicodeEncodeError) for str.encode("latin-1"): the first run of unencodable characters.
func latin1Error(runes []rune) string {
	for i, r := range runes {
		if r <= 0xff {
			continue
		}
		end := i + 1
		for end < len(runes) && runes[end] > 0xff {
			end++
		}
		if end == i+1 {
			escaped := fmt.Sprintf(`\u%04x`, r)
			if r > 0xffff {
				escaped = fmt.Sprintf(`\U%08x`, r)
			}
			return fmt.Sprintf("'latin-1' codec can't encode character '%s' in position %d: ordinal not in range(256)", escaped, i)
		}
		return fmt.Sprintf("'latin-1' codec can't encode characters in position %d-%d: ordinal not in range(256)", i, end-1)
	}
	return ""
}

func validGroupName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')) {
			return false // the bytes recompile requires an ASCII identifier
		}
	}
	return true
}

// RE2 caps a repeat count at 1000. A signature asks only whether a match exists, so a larger count is written as
// consecutive pieces of at most 1000 that denote the same language: x{m,n} is x{1000}...x{r} (m in all) followed by
// x{0,1000}...x{0,q} (n-m in all), and x{m,} ends in x*. The expansion is bounded (maxRepeatPieces pieces and
// maxExpression bytes); a larger one is refused as not ported, as is anything RE2 then rejects as too large.
const (
	maxRepeatPieces = 64
	maxExpression   = 1 << 20
)

func writeRepeat(b *strings.Builder, body string, min, max int) error {
	if min <= 1000 && (max == maxRepeat || max <= 1000) {
		b.WriteString(body)
		if max == maxRepeat {
			fmt.Fprintf(b, "{%d,}", min)
		} else {
			fmt.Fprintf(b, "{%d,%d}", min, max)
		}
		return nil
	}
	pieces := (min + 999) / 1000
	if max != maxRepeat {
		pieces += (max - min + 999) / 1000
	} else {
		pieces++
	}
	if pieces > maxRepeatPieces || b.Len()+pieces*(len(body)+12) > maxExpression {
		return &notPortedError{"repeat count above 1000"}
	}
	for left := min; left > 0; left -= 1000 {
		fmt.Fprintf(b, "%s{%d}", body, minInt(left, 1000))
	}
	if max == maxRepeat {
		b.WriteString(body + "*")
		return nil
	}
	for left := max - min; left > 0; left -= 1000 {
		fmt.Fprintf(b, "%s{0,%d}", body, minInt(left, 1000))
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parsePattern parses a whole pattern (re._parser.parse with flags 0).
func parsePattern(pattern string) (tree []node, err error) {
	defer func() {
		if r := recover(); r != nil {
			switch e := r.(type) {
			case *patternError:
				err = e
			case *notPortedError:
				err = e
			default:
				panic(r)
			}
		}
	}()
	s := &source{runes: []rune(pattern), names: map[string]int{}, closed: map[int]bool{}}
	tree = s.parseSub(0)
	if s.pos < len(s.runes) {
		if s.runes[s.pos] == ')' {
			s.fail("unbalanced parenthesis", 0)
		}
		return nil, &patternError{"internal: unparsed pattern"}
	}
	return tree, nil
}

// --- the signature rules over the tree (signatures._literal_runs, _contains_repeat) ---

func containsRepeat(tree []node) bool {
	for _, n := range tree {
		switch n.op {
		case opRepeat, opPossessive:
			return true
		case opSubpattern:
			if containsRepeat(n.body) {
				return true
			}
		case opBranch:
			for _, b := range n.branches {
				if containsRepeat(b) {
					return true
				}
			}
		}
	}
	return false
}

// literalRuns ports _literal_runs: literal byte runs outside repeats and branches, with the unsafe-construct checks.
func literalRuns(tree []node, insideRepeat bool, out *[][]int) error {
	var run []int
	flush := func() {
		if len(run) > 0 {
			*out = append(*out, run)
			run = nil
		}
	}
	for _, n := range tree {
		if n.op == opLiteral {
			if n.value > 255 {
				return &patternError{"Patterns must be Latin-1 encodable"}
			}
			if !insideRepeat {
				run = append(run, n.value)
				continue
			}
		}
		flush()
		switch n.op {
		case opRepeat, opPossessive:
			if containsRepeat(n.body) {
				return &patternError{"Nested quantifiers are not allowed"}
			}
			if n.max != maxRepeat && n.max > 4096 {
				return &patternError{"Repeat count exceeds 4096"}
			}
			if err := literalRuns(n.body, true, out); err != nil {
				return err
			}
		case opSubpattern:
			if err := literalRuns(n.body, insideRepeat, out); err != nil {
				return err
			}
		case opBranch:
			for _, b := range n.branches {
				if err := literalRuns(b, true, out); err != nil {
					return err
				}
			}
		case opGroupRef, opAssert:
			return &patternError{"Backreferences and lookaround are not allowed"}
		}
	}
	flush()
	return nil
}

// --- compilation to Go over the Latin-1 image ---

type byteSet [256]bool

func lowerByte(c int) int {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func inCategory(c int, category string) bool {
	switch category {
	case "digit":
		return c >= '0' && c <= '9'
	case "not_digit":
		return !(c >= '0' && c <= '9')
	case "space":
		return c == ' ' || (c >= 9 && c <= 13)
	case "not_space":
		return !(c == ' ' || (c >= 9 && c <= 13))
	case "word":
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
	case "not_word":
		return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')
	}
	return false
}

// classSet is the byte set of an IN node under Python's bytes rules; with ignorecase sre lowers the input byte and
// tests it against the lowered literals and ranges (categories are not lowered: they are case-stable).
func classSet(items []classItem, ignorecase bool) byteSet {
	var lits byteSet
	var cats []string
	negate := false
	for _, it := range items {
		switch it.kind {
		case "negate":
			negate = true
		case "literal":
			if it.lo < 256 {
				v := it.lo
				if ignorecase {
					v = lowerByte(v)
				}
				lits[v] = true
			}
		case "range":
			for v := it.lo; v <= it.hi && v < 256; v++ {
				w := v
				if ignorecase {
					w = lowerByte(w)
				}
				lits[w] = true
			}
		case "category":
			cats = append(cats, it.category)
		}
	}
	var out byteSet
	for c := 0; c < 256; c++ {
		probe := c
		if ignorecase {
			probe = lowerByte(c)
		}
		in := lits[probe]
		for _, cat := range cats {
			in = in || inCategory(probe, cat)
		}
		out[c] = in != negate
	}
	return out
}

func emitSet(b *strings.Builder, set byteSet) {
	count := 0
	for _, in := range set {
		if in {
			count++
		}
	}
	if count == 0 {
		b.WriteString(`[^\x{0}-\x{10FFFF}]`) // matches nothing
		return
	}
	b.WriteString("[")
	for c := 0; c < 256; c++ {
		if !set[c] {
			continue
		}
		start := c
		for c+1 < 256 && set[c+1] {
			c++
		}
		writeHexRune(b, start)
		if c > start {
			b.WriteByte('-')
			writeHexRune(b, c)
		}
	}
	b.WriteString("]")
}

// writeHexRune writes \x{c} in lower-case hex, the text fmt's %x gave, without fmt (it was the load hot path).
func writeHexRune(b *strings.Builder, c int) {
	const digits = "0123456789abcdef"
	b.WriteString(`\x{`)
	if c >= 16 {
		b.WriteByte(digits[c>>4])
	}
	b.WriteByte(digits[c&15])
	b.WriteByte('}')
}

func literalSet(v int, not, ignorecase bool) byteSet {
	var set byteSet
	for c := 0; c < 256; c++ {
		eq := c == v
		if ignorecase {
			eq = lowerByte(c) == lowerByte(v)
		}
		set[c] = eq != not
	}
	return set
}

// compileTree writes the Go expression; final reports whether the sequence ends the whole pattern ($ is exact there).
func compileTree(b *strings.Builder, tree []node, ignorecase, final bool) error {
	for i, n := range tree {
		last := final && i == len(tree)-1
		switch n.op {
		case opLiteral, opNotLiteral:
			if n.value > 255 {
				return &patternError{"Patterns must be Latin-1 encodable"}
			}
			if n.op == opLiteral && (!ignorecase || lowerByte(n.value) == n.value && (n.value < 'a' || n.value > 'z')) {
				// The set is the byte alone (no case partner): the text emitSet writes for it.
				b.WriteByte('[')
				writeHexRune(b, n.value)
				b.WriteByte(']')
				continue
			}
			emitSet(b, literalSet(n.value, n.op == opNotLiteral, ignorecase))
		case opAny:
			b.WriteString(`[\x{0}-\x{ff}]`)
		case opIn:
			emitSet(b, classSet(n.items, ignorecase))
		case opSubpattern:
			b.WriteString("(?:")
			if err := compileTree(b, n.body, ignorecase, last); err != nil {
				return err
			}
			b.WriteString(")")
		case opBranch:
			b.WriteString("(?:")
			for j, br := range n.branches {
				if j > 0 {
					b.WriteString("|")
				}
				if err := compileTree(b, br, ignorecase, last); err != nil {
					return err
				}
			}
			b.WriteString(")")
		case opRepeat:
			var body strings.Builder
			body.WriteString("(?:")
			if err := compileTree(&body, n.body, ignorecase, false); err != nil {
				return err
			}
			body.WriteString(")")
			if err := writeRepeat(b, body.String(), n.min, n.max); err != nil {
				return err
			}
		case opPossessive:
			return &notPortedError{"possessive repeat"}
		case opAt:
			switch n.at {
			case atBeginning, atBeginningString:
				b.WriteString(`\A`)
			case atEndString:
				b.WriteString(`\z`)
			case atBoundary:
				b.WriteString(`\b`)
			case atNonBoundary:
				b.WriteString(`\B`)
			case atEnd:
				if !last {
					return &notPortedError{"$ before the end of the pattern"}
				}
				b.WriteString(`\n?\z`) // at the end, or before a final newline
			}
		case opFailure:
			// CPython 3.9..3.12 reject (?!) as ASSERT_NOT; 3.13 parses it as FAILURE and accepts it. Refusing
			// lets the reference interpreter in use answer (TestEmptyNegativeLookaheadIsNotPorted).
			return &notPortedError{"empty negative lookahead"}
		case opAssert, opGroupRef:
			return &patternError{"Backreferences and lookaround are not allowed"}
		}
	}
	return nil
}

// latin1 maps bytes to the runes U+0000..U+00FF the compiled expressions are written over.
func latin1(data []byte) string {
	r := make([]rune, len(data))
	for i, c := range data {
		r[i] = rune(c)
	}
	return string(r)
}

// compiledPattern is one pattern-match condition's expression and literal anchor.
type compiledPattern struct {
	re     *regexp.Regexp
	anchor []byte
	insts  int // estimateInsts of the pattern: the per-byte cost weight of a search (SEC-SIG-1)
}

func (p *compiledPattern) search(value []byte) bool { return p.re.MatchString(latin1(value)) }

// compilePattern ports signatures.compile_pattern; err is *patternError (Python rejects) or *notPortedError.
func compilePattern(pattern string, kind string, ignorecase bool) (*compiledPattern, error) {
	return compileBudgeted(pattern, kind, ignorecase, nil)
}

// compileBudgeted is compilePattern charging the pattern's instruction estimate to budget (nil: the per-pattern
// cap only). Every reference rule is checked first, so a pattern Python rejects keeps its error; the estimate
// runs on the tree before the expression is built or regexp.Compile runs (SEC-SIG-2).
func compileBudgeted(pattern string, kind string, ignorecase bool, budget *instBudget) (*compiledPattern, error) {
	if n := len([]rune(pattern)); n < 1 || n > maxPattern {
		return nil, &patternError{fmt.Sprintf("Pattern must contain 1..%d characters", maxPattern)}
	}
	tree, err := parsePattern(pattern)
	if err != nil {
		if pe, ok := err.(*patternError); ok {
			return nil, &patternError{"Invalid pattern: " + pe.msg}
		}
		return nil, err
	}
	var runs [][]int
	if err := literalRuns(tree, false, &runs); err != nil {
		return nil, err
	}
	var anchor []int
	for _, r := range runs {
		if len(r) > len(anchor) {
			anchor = r
		}
	}
	required := 3
	if kind == "raw" {
		required = 7
	}
	if len(anchor) < required {
		return nil, &patternError{fmt.Sprintf("Pattern needs a literal run of at least %d bytes", required)}
	}
	if msg := latin1Error([]rune(pattern)); msg != "" {
		return nil, &patternError{"Pattern must be Latin-1 encodable: " + msg}
	}
	insts := estimateInsts(tree, maxPatternInsts)
	if err := budget.charge(insts); err != nil {
		return nil, err
	}
	var b strings.Builder
	if err := compileTree(&b, tree, ignorecase, true); err != nil {
		return nil, err
	}
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, &notPortedError{"expression rejected by RE2: " + err.Error()}
	}
	out := &compiledPattern{re: re, insts: insts}
	for _, v := range anchor {
		out.anchor = append(out.anchor, byte(v))
	}
	if ignorecase {
		for i, c := range out.anchor {
			out.anchor[i] = byte(lowerByte(int(c)))
		}
	}
	return out, nil
}
