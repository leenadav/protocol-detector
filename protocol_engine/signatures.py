"""Custom application signatures evaluated over bounded parser contexts.

A signature set is compiled once from a JSON document and shared across
inspectors, like RuleIndex. Signatures are evaluated only after a parser has
completed its structural profile (or after an unknown prefix of bounded size
has been collected), against a small dictionary of named contexts the parser
exposed. Contexts never leave the engine; a match contributes only the
signature's name and catalog metadata.

Regular expressions are compiled with the standard library. To keep evaluation
linear in the input, every pattern must contain a literal anchor of a minimum
length (7 bytes for raw payload contexts, 3 for parsed fields), may not nest
quantifiers or use backreferences/lookaround, and is only executed after the
anchor was found with a plain substring search. Inputs are bounded by the
parser budgets or by Config.signature_bytes for unknown payloads.
"""
import hashlib
import json
import re
from types import MappingProxyType

try:  # Python 3.11+ exposes the parser privately; 3.9/3.10 use sre_parse.
    from re import _parser as _sre
except ImportError:  # pragma: no cover - exercised on older interpreters
    import sre_parse as _sre

from .applications import CATEGORIES, CHARACTERISTICS, TECHNOLOGIES

# Context name -> (kind, protocol family it belongs to). Kinds: text (bytes, pattern/equal),
# integer (equal/less/greater), set (integers; equal-to means membership).
CONTEXTS = MappingProxyType({
    "http-req-method": ("text", "http"),
    "http-req-uri-path": ("text", "http"),
    "http-req-version": ("text", "http"),
    "http-req-host-header": ("text", "http"),
    "http-req-user-agent-header": ("text", "http"),
    "http-req-headers": ("raw", "http"),
    "http-rsp-status": ("integer", "http"),
    "http-rsp-reason": ("text", "http"),
    "http-req-content-length": ("integer", "http"),
    "http2-req-method": ("text", "http2"),
    "http2-req-uri-path": ("text", "http2"),
    "http2-req-host-header": ("text", "http2"),
    "http2-req-user-agent-header": ("text", "http2"),
    "http2-req-headers": ("raw", "http2"),
    "http2-rsp-status": ("integer", "http2-server"),
    "ssl-req-chello-sni": ("text", "tls"),
    "ssl-req-alpn": ("text", "tls"),
    "ssl-req-client-hello": ("raw", "tls"),
    "ssl-req-client-hello-ext-type": ("set", "tls"),
    "ssl-req-cipher-suite": ("set", "tls"),
    "ssl-req-version": ("integer", "tls"),
    "ssh-req-banner": ("text", "ssh"),
    "smtp-req-argument": ("text", "smtp"),
    "dns-req-query-name": ("text", "dns"),
    "dns-req-query-type": ("integer", "dns"),
    "socks-req-target": ("text", "socks5"),
    "socks-req-port": ("integer", "socks5"),
    "unknown-req-tcp-payload": ("raw", "unknown-tcp"),
    "unknown-req-tcp-payload-length": ("integer", "unknown-tcp"),
    "unknown-req-udp-payload": ("raw", "unknown-udp"),
    "unknown-req-udp-payload-length": ("integer", "unknown-udp"),
})
OPERATORS = ("pattern-match", "equal-to", "less-than", "greater-than")
MIN_ANCHOR = MappingProxyType({"raw": 7, "text": 3})
MAX_PATTERN = 512
MAX_SIGNATURES = 4096
MAX_CONDITIONS = 64
MAX_DEPTH = 4


class SignatureError(ValueError):
    pass


def _literal_runs(parsed, inside_repeat=False, depth=0):
    """Yield literal byte runs and flag unsafe constructs in a parsed pattern."""
    run = []
    for opcode, value in parsed:
        name = str(opcode)
        if name == "LITERAL":
            if value > 255:
                raise SignatureError("Patterns must be Latin-1 encodable")
            if not inside_repeat:
                run.append(value)
                continue
        if run:
            yield bytes(run)
            run = []
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            low, high, body = value
            if _contains_repeat(body):
                raise SignatureError("Nested quantifiers are not allowed")
            if high is not None and high != _sre.MAXREPEAT and high > 4096:
                raise SignatureError("Repeat count exceeds 4096")
            for inner in _literal_runs(body, True, depth + 1):
                yield inner
        elif name == "SUBPATTERN":
            body = value[-1]
            for inner in _literal_runs(body, inside_repeat, depth + 1):
                yield inner
        elif name == "BRANCH":
            for alternative in value[1]:
                for inner in _literal_runs(alternative, True, depth + 1):
                    yield inner
        elif name in ("GROUPREF", "GROUPREF_EXISTS", "ASSERT", "ASSERT_NOT"):
            raise SignatureError("Backreferences and lookaround are not allowed")
    if run:
        yield bytes(run)


def _contains_repeat(parsed):
    for opcode, value in parsed:
        name = str(opcode)
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            return True
        if name == "SUBPATTERN" and _contains_repeat(value[-1]):
            return True
        if name == "BRANCH" and any(_contains_repeat(alternative) for alternative in value[1]):
            return True
    return False


def compile_pattern(pattern, kind, case_insensitive=False):
    """Return (compiled regex over bytes, longest literal anchor) or raise SignatureError."""
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= MAX_PATTERN:
        raise SignatureError("Pattern must contain 1..{} characters".format(MAX_PATTERN))
    try:
        parsed = _sre.parse(pattern)
    except re.error as error:
        raise SignatureError("Invalid pattern: " + str(error)) from None
    anchors = list(_literal_runs(parsed))
    try:
        anchor = max((run for run in anchors if all(byte < 256 for byte in run)), key=len)
    except ValueError:
        anchor = b""
    required = MIN_ANCHOR["raw" if kind == "raw" else "text"]
    if len(anchor) < required:
        raise SignatureError("Pattern needs a literal run of at least {} bytes".format(required))
    flags = re.DOTALL | (re.IGNORECASE if case_insensitive else 0)
    try:
        compiled = re.compile(pattern.encode("latin-1"), flags)
    except (re.error, UnicodeEncodeError) as error:
        raise SignatureError("Pattern must be Latin-1 encodable: " + str(error)) from None
    if case_insensitive:
        anchor = anchor.lower()
    return compiled, anchor


class Condition:
    __slots__ = ("context", "kind", "operator", "negate", "value", "pattern", "anchor", "case_insensitive")

    def __init__(self, data):
        if not isinstance(data, dict) or "context" not in data:
            raise SignatureError("Condition requires a context")
        context = data["context"]
        if context not in CONTEXTS:
            raise SignatureError("Unknown context: " + str(context))
        self.context = context
        self.kind = CONTEXTS[context][0]
        operator = data.get("operator", "pattern-match")
        if operator not in OPERATORS:
            raise SignatureError("Unknown operator: " + str(operator))
        self.operator = operator
        self.negate = bool(data.get("negate", False))
        self.case_insensitive = bool(data.get("case_insensitive", False))
        self.pattern = self.anchor = self.value = None
        if operator == "pattern-match":
            if self.kind in ("integer", "set"):
                raise SignatureError("pattern-match requires a text or raw context")
            self.pattern, self.anchor = compile_pattern(data.get("pattern"), self.kind, self.case_insensitive)
        elif self.kind in ("integer", "set"):
            value = data.get("value")
            if type(value) is not int or not 0 <= value <= 2 ** 32:
                raise SignatureError("Integer condition requires an integer value")
            if self.kind == "set" and operator != "equal-to":
                raise SignatureError("Set contexts support equal-to (membership) only")
            self.value = value
        else:
            if operator != "equal-to":
                raise SignatureError("Text contexts support pattern-match and equal-to")
            value = data.get("value")
            if not isinstance(value, str) or not 1 <= len(value) <= MAX_PATTERN:
                raise SignatureError("equal-to requires a text value")
            try:
                self.value = value.encode("latin-1")
            except UnicodeEncodeError:
                raise SignatureError("equal-to value must be Latin-1 encodable") from None
            if self.case_insensitive:
                self.value = self.value.lower()

    def evaluate(self, contexts):
        value = contexts.get(self.context)
        if value is None:
            return False  # absent context: never a match, negate does not apply
        if self.operator == "pattern-match":
            haystack = value.lower() if self.case_insensitive else value
            result = self.anchor in haystack and self.pattern.search(value) is not None
        elif self.kind == "set":
            result = self.value in value
        elif self.kind == "integer":
            result = (value == self.value if self.operator == "equal-to" else
                      value < self.value if self.operator == "less-than" else value > self.value)
        else:
            result = (value.lower() if self.case_insensitive else value) == self.value
        return result != self.negate


class Group:
    __slots__ = ("operator", "members")

    def __init__(self, data, counter, depth=1):
        if depth > MAX_DEPTH:
            raise SignatureError("Condition nesting exceeds {} levels".format(MAX_DEPTH))
        if not isinstance(data, dict) or len(data) != 1 or next(iter(data)) not in ("and", "or"):
            raise SignatureError("Group requires exactly one of 'and'/'or'")
        self.operator, members = next(iter(data.items()))
        if not isinstance(members, list) or not members:
            raise SignatureError("Group needs a nonempty list of conditions")
        self.members = []
        for member in members:
            counter[0] += 1
            if counter[0] > MAX_CONDITIONS:
                raise SignatureError("Signature exceeds {} conditions".format(MAX_CONDITIONS))
            if isinstance(member, dict) and ("and" in member or "or" in member):
                self.members.append(Group(member, counter, depth + 1))
            else:
                self.members.append(Condition(member))

    def evaluate(self, contexts):
        if self.operator == "and":
            return all(member.evaluate(contexts) for member in self.members)
        return any(member.evaluate(contexts) for member in self.members)

    def contexts(self):
        for member in self.members:
            if isinstance(member, Group):
                for name in member.contexts():
                    yield name
            else:
                yield member.context


class Signature:
    __slots__ = ("name", "category", "subcategory", "technology", "risk", "characteristics", "parent",
                 "description", "root", "families", "positive")

    def __init__(self, data):
        if not isinstance(data, dict):
            raise SignatureError("Signature must be an object")
        name = data.get("name")
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise SignatureError("Signature name must contain 1..128 printable characters")
        self.name = name
        self.category = data.get("category", "custom")
        self.subcategory = data.get("subcategory", "custom-signature")
        if self.category not in CATEGORIES or self.subcategory not in CATEGORIES[self.category]:
            raise SignatureError("Unknown category/subcategory in " + name)
        self.technology = data.get("technology", "client-server")
        if self.technology not in TECHNOLOGIES:
            raise SignatureError("Unknown technology in " + name)
        self.risk = data.get("risk", 3)
        if type(self.risk) is not int or not 1 <= self.risk <= 5:
            raise SignatureError("Risk must be 1..5 in " + name)
        self.characteristics = tuple(data.get("characteristics", ()))
        if not set(self.characteristics) <= set(CHARACTERISTICS):
            raise SignatureError("Unknown characteristic in " + name)
        self.parent = data.get("parent")
        if self.parent is not None and not isinstance(self.parent, str):
            raise SignatureError("Parent must be an application name")
        self.description = str(data.get("description", ""))[:256]
        if data.get("scope", "transaction") != "transaction":
            raise SignatureError("Only transaction scope is supported in " + name)
        conditions = data.get("conditions")
        if isinstance(conditions, list):
            conditions = {"and": conditions}
        self.root = Group(conditions, [0])
        self.families = frozenset(CONTEXTS[context][1] for context in self.root.contexts())
        self.positive = any(not member.negate for member in _leaves(self.root))
        if not self.positive:
            raise SignatureError("Signature needs at least one non-negated condition: " + name)


def _leaves(group):
    for member in group.members:
        if isinstance(member, Group):
            for leaf in _leaves(member):
                yield leaf
        else:
            yield member


def _exact_key(signature):
    """(context, value) that any match of this signature must satisfy, or None (stage 7, A11).

    Only a top-level AND member that is a case-sensitive, non-negated equal-to on a text context qualifies:
    such a signature can match only when contexts[context] == value, so an exact lookup on that value
    selects it without changing which signatures can match. OR roots, negations, case-insensitive and
    pattern conditions stay on the family's scan list. Priority (definition order) is preserved by
    merging indexed candidates back into position order before evaluation.
    """
    root = signature.root
    if root.operator != "and":
        return None
    for member in root.members:
        if (isinstance(member, Condition) and member.operator == "equal-to" and member.kind == "text"
                and not member.negate and not member.case_insensitive):
            return member.context, member.value
    return None


class SignatureSet:
    """Immutable, compiled once; evaluation touches only signatures indexed by family.

    Stage 7 (A11): a name index (O(1) get/contains), a per-family exact-value index for signatures keyed by
    an equal-to text condition, and a per-family scan list for the rest. match() evaluates only the scan
    list plus the exact hits for the context values present, in definition order, first match wins; the
    number of candidates evaluated is reported through match_counted(). `digest` identifies the rule set so
    a session can pin the version it was classified with.
    """

    def __init__(self, signatures=(), version=1):
        by_family = {}
        names = {}
        count = 0
        hasher = hashlib.sha256()
        for item in signatures:
            signature = item if isinstance(item, Signature) else Signature(item)
            count += 1
            if count > MAX_SIGNATURES:
                raise SignatureError("Signature count exceeds {}".format(MAX_SIGNATURES))
            if signature.name in names:
                raise SignatureError("Duplicate signature name: " + signature.name)
            names[signature.name] = signature
            hasher.update(json.dumps(item, sort_keys=True, default=str).encode("utf-8") if isinstance(item, dict)
                          else signature.name.encode("utf-8"))
            hasher.update(b"\0")
            for family in signature.families:
                by_family.setdefault(family, []).append((count - 1, signature))
        index = {}
        for family, items in by_family.items():
            exact, scan = {}, []
            for position, signature in items:
                key = _exact_key(signature)
                if key is None:
                    scan.append((position, signature))
                else:
                    exact.setdefault(key[0], {}).setdefault(key[1], []).append((position, signature))
            index[family] = (MappingProxyType({context: MappingProxyType({value: tuple(hits) for value, hits in values.items()})
                                               for context, values in exact.items()}), tuple(scan))
        self._by_family = MappingProxyType({family: tuple(signature for _, signature in items) for family, items in by_family.items()})
        self._index = MappingProxyType(index)
        self._by_name = MappingProxyType(names)
        self._names = MappingProxyType({name: None for name in names})
        self.families = frozenset(by_family)
        self.version = version
        self.digest = hasher.hexdigest()[:16]
        self.stats = {"indexed": sum(sum(len(hits) for values in exact.values() for hits in values.values()) for exact, _ in index.values()),
                      "scanned": sum(len(scan) for _, scan in index.values())}

    @classmethod
    def from_json(cls, text):
        try:
            document = json.loads(text)
        except ValueError as error:
            raise SignatureError("Invalid JSON: " + str(error)) from None
        version = 1
        if isinstance(document, dict):
            if document.get("version", 1) != 1:
                raise SignatureError("Unsupported signature file version")
            version = document.get("version", 1)
            document = document.get("signatures", [])
        if not isinstance(document, list):
            raise SignatureError("Signature document must be a list or an object with 'signatures'")
        return cls(document, version)

    @classmethod
    def from_path(cls, path):
        with open(path, "rb") as handle:
            data = handle.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise SignatureError("Signature file exceeds 4 MiB")
        return cls.from_json(data.decode("utf-8"))

    def __len__(self):
        return len(self._names)

    def __contains__(self, name):
        return name in self._names

    def wants(self, family):
        return family in self._by_family

    def candidates(self, family, contexts):
        """Signatures that can still match these contexts, in definition order (scan list + exact hits)."""
        entry = self._index.get(family)
        if entry is None:
            return ()
        exact, scan = entry
        hits = []
        for context, values in exact.items():
            value = contexts.get(context)
            if value is not None:
                found = values.get(value)
                if found:
                    hits.extend(found)
        if not hits:
            return tuple(signature for _, signature in scan)
        merged = sorted(hits + list(scan), key=lambda item: item[0])
        return tuple(signature for _, signature in merged)

    def match_counted(self, family, contexts):
        """(first matching signature or None, candidates evaluated). Bounded by the family's candidate set."""
        evaluated = 0
        for signature in self.candidates(family, contexts):
            evaluated += 1
            if signature.root.evaluate(contexts):
                return signature, evaluated
        return None, evaluated

    def match(self, family, contexts):
        """First matching signature for a parser family, or None. Priority and first-match semantics kept."""
        return self.match_counted(family, contexts)[0]

    def match_linear(self, family, contexts):
        """Reference evaluation without the index (equivalence tests and benchmarks only)."""
        for signature in self._by_family.get(family, ()):
            if signature.root.evaluate(contexts):
                return signature
        return None

    def get(self, name):
        return self._by_name.get(name)
