"""Policy evaluation over session verdicts, in the vocabulary of application firewalls.

A policy is an ordered list of rules; the first rule whose conditions all match
decides (allow, deny or alert), otherwise the policy default applies. Rules
match the verdict produced by appid.session_verdict (application or outcome,
catalog attributes, port usage, encryption, carrier after a shift, flow risks)
plus the transport and server port of the session. This module never inspects
payload, never changes a verdict and performs no network action: the decision
is a label the host acts on. Policy files are operator input and are validated
strictly (unknown keys, unknown names and malformed ports are errors).
"""
import json
from types import MappingProxyType
from typing import NamedTuple, Optional, Tuple

from .applications import APPLICATIONS, CATEGORIES, CHARACTERISTICS, OUTCOMES, TECHNOLOGIES, lookup
from .appid import Verdict
from .risks import RISKS

ACTIONS = ("allow", "deny", "alert")
PORT_USAGE = ("standard", "nonstandard", "unknown")
_MATCH_KEYS = frozenset(("apps", "categories", "subcategories", "technologies", "characteristics", "risks", "port_usage",
                         "transports", "server_ports", "encryption", "shifted_from", "risk_min", "risk_max"))
_RULE_KEYS = frozenset(("name", "action", "match", "application_default", "description"))
_SUBCATEGORIES = frozenset(sub for subs in CATEGORIES.values() for sub in subs)
MAX_RULES = 1024


class PolicyError(ValueError):
    """Invalid policy document."""


class Decision(NamedTuple):
    action: str
    rule: Optional[str]         # matching rule name, None for the default
    reasons: Tuple[str, ...]

    def fields(self):
        return {"action": self.action, "rule": self.rule, "reasons": list(self.reasons)}


def _names(value, label, allowed=None, resolve=None):
    if not isinstance(value, list) or not value or len(value) > 256:
        raise PolicyError("'{}' must be a non-empty list of at most 256 strings".format(label))
    names = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise PolicyError("'{}' entries must be strings".format(label))
        if resolve is not None:
            item = resolve(item)
        if allowed is not None and item not in allowed:
            raise PolicyError("Unknown {} name: {}".format(label, item))
        names.append(item)
    return frozenset(names)


def _resolve_app(name):
    if name in OUTCOMES:
        return name
    entry = lookup(name)
    if entry is None:
        raise PolicyError("Unknown application: " + name)
    return entry.name


def _ports(value):
    """Parse ['tcp/443', 'udp/53-60', 'tcp/dynamic'] into {transport: (exact, ranges, dynamic)}."""
    if not isinstance(value, list) or not value or len(value) > 256:
        raise PolicyError("'server_ports' must be a non-empty list of at most 256 entries")
    table = {}
    for entry in value:
        if not isinstance(entry, str) or entry.count("/") != 1:
            raise PolicyError("Port entries look like tcp/443, udp/53-60 or tcp/dynamic")
        transport, spec = entry.split("/")
        if transport not in ("tcp", "udp"):
            raise PolicyError("Port transport must be tcp or udp")
        exact, ranges, dynamic = table.get(transport, (set(), [], False))
        if spec == "dynamic":
            dynamic = True
        else:
            low, _, high = spec.partition("-")
            try:
                low_value, high_value = int(low), int(high or low)
            except ValueError:
                raise PolicyError("Port numbers must be integers: " + entry) from None
            if not 1 <= low_value <= high_value <= 65535:
                raise PolicyError("Port range outside 1..65535: " + entry)
            if high:
                ranges.append((low_value, high_value))
            else:
                exact.add(low_value)
        table[transport] = (exact, ranges, dynamic)
    return MappingProxyType({t: (frozenset(e), tuple(r), d) for t, (e, r, d) in table.items()})


class Rule:
    """One ordered policy rule with pre-resolved condition sets."""
    __slots__ = ("name", "action", "apps", "categories", "subcategories", "technologies", "characteristics", "risks",
                 "port_usage", "transports", "server_ports", "encryption", "shifted_from", "risk_min", "risk_max",
                 "application_default", "description")

    def __init__(self, document, index):
        if not isinstance(document, dict):
            raise PolicyError("Rule {} must be an object".format(index))
        unknown = set(document) - _RULE_KEYS
        if unknown:
            raise PolicyError("Rule {} has unknown keys: {}".format(index, ", ".join(sorted(unknown))))
        name = document.get("name", "rule-{}".format(index))
        if not isinstance(name, str) or not 1 <= len(name) <= 64 or not name.isprintable():
            raise PolicyError("Rule {} name must be 1..64 printable characters".format(index))
        action = document.get("action")
        if action not in ACTIONS:
            raise PolicyError("Rule '{}' action must be one of {}".format(name, ", ".join(ACTIONS)))
        match = document.get("match", {})
        if not isinstance(match, dict):
            raise PolicyError("Rule '{}' match must be an object".format(name))
        unknown = set(match) - _MATCH_KEYS
        if unknown:
            raise PolicyError("Rule '{}' has unknown match keys: {}".format(name, ", ".join(sorted(unknown))))
        self.name, self.action = name, action
        self.description = document.get("description", "")
        if not isinstance(self.description, str) or len(self.description) > 512:
            raise PolicyError("Rule '{}' description must be a string of at most 512 characters".format(name))
        self.application_default = document.get("application_default", False)
        if type(self.application_default) is not bool:
            raise PolicyError("Rule '{}' application_default must be a boolean".format(name))
        self.apps = _names(match["apps"], "apps", resolve=_resolve_app) if "apps" in match else None
        self.categories = _names(match["categories"], "categories", CATEGORIES) if "categories" in match else None
        self.subcategories = _names(match["subcategories"], "subcategories", _SUBCATEGORIES) if "subcategories" in match else None
        self.technologies = _names(match["technologies"], "technologies", TECHNOLOGIES) if "technologies" in match else None
        self.characteristics = _names(match["characteristics"], "characteristics", CHARACTERISTICS) if "characteristics" in match else None
        self.risks = _names(match["risks"], "risks", RISKS) if "risks" in match else None
        self.port_usage = _names(match["port_usage"], "port_usage", PORT_USAGE) if "port_usage" in match else None
        self.transports = _names(match["transports"], "transports", ("tcp", "udp")) if "transports" in match else None
        self.server_ports = _ports(match["server_ports"]) if "server_ports" in match else None
        self.encryption = _names(match["encryption"], "encryption", ("none", "tls", "dtls", "quic", "wireguard", "openvpn")) if "encryption" in match else None
        self.shifted_from = _names(match["shifted_from"], "shifted_from", resolve=_resolve_app) if "shifted_from" in match else None
        self.risk_min = self._risk_bound(match, "risk_min", name)
        self.risk_max = self._risk_bound(match, "risk_max", name)
        if self.risk_min is not None and self.risk_max is not None and self.risk_min > self.risk_max:
            raise PolicyError("Rule '{}' risk_min exceeds risk_max".format(name))

    @staticmethod
    def _risk_bound(match, key, name):
        if key not in match:
            return None
        value = match[key]
        if type(value) is not int or not 1 <= value <= 5:
            raise PolicyError("Rule '{}' {} must be an integer 1..5".format(name, key))
        return value

    def matches(self, verdict, transport, server_port):
        """All present conditions must hold; list conditions hold when any entry matches."""
        if self.apps is not None and verdict.app not in self.apps:
            return False
        if self.categories is not None and verdict.category not in self.categories:
            return False
        if self.subcategories is not None and verdict.subcategory not in self.subcategories:
            return False
        if self.technologies is not None and verdict.technology not in self.technologies:
            return False
        if self.risk_min is not None and verdict.risk < self.risk_min:
            return False
        if self.risk_max is not None and verdict.risk > self.risk_max:
            return False
        if self.characteristics is not None and self.characteristics.isdisjoint(verdict.characteristics):
            return False
        if self.risks is not None and self.risks.isdisjoint(verdict.risks):
            return False
        if self.port_usage is not None and verdict.port_usage not in self.port_usage:
            return False
        if self.encryption is not None and (verdict.encryption or "none") not in self.encryption:
            return False
        if self.shifted_from is not None and verdict.shifted_from not in self.shifted_from:
            return False
        if self.transports is not None and transport not in self.transports:
            return False
        if self.server_ports is not None:
            if transport is None or server_port is None or transport not in self.server_ports:
                return False
            exact, ranges, dynamic = self.server_ports[transport]
            if not (dynamic or server_port in exact or any(low <= server_port <= high for low, high in ranges)):
                return False
        if self.application_default and verdict.port_usage == "nonstandard":
            return False
        return True


class Policy:
    def __init__(self, rules, default="allow", description=""):
        if default not in ACTIONS:
            raise PolicyError("Policy default must be one of " + ", ".join(ACTIONS))
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise PolicyError("Policy rules must be a list of at most {} rules".format(MAX_RULES))
        if not isinstance(description, str) or len(description) > 512:
            raise PolicyError("Policy description must be a string of at most 512 characters")
        parsed = tuple(Rule(rule, index) for index, rule in enumerate(rules))
        names = [rule.name for rule in parsed]
        if len(set(names)) != len(names):
            raise PolicyError("Rule names must be unique")
        self.rules = parsed
        self.default = default
        self.description = description

    @classmethod
    def from_json(cls, text):
        try:
            document = json.loads(text)
        except ValueError as error:
            raise PolicyError("Invalid JSON: " + str(error)) from None
        if not isinstance(document, dict):
            raise PolicyError("Policy document must be an object")
        unknown = set(document) - {"version", "default", "rules", "description"}
        if unknown:
            raise PolicyError("Policy has unknown keys: " + ", ".join(sorted(unknown)))
        if document.get("version", 1) != 1:
            raise PolicyError("Unsupported policy version")
        return cls(document.get("rules", []), document.get("default", "allow"), document.get("description", ""))

    @classmethod
    def from_path(cls, path):
        with open(path, "rb") as handle:
            data = handle.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise PolicyError("Policy file exceeds 4 MiB")
        return cls.from_json(data.decode("utf-8"))

    def __len__(self):
        return len(self.rules)

    def evaluate(self, verdict, transport=None, server_port=None):
        """First matching rule decides; otherwise the default. Linear in the rule count."""
        if not isinstance(verdict, Verdict):
            raise TypeError("evaluate expects a Verdict")
        for rule in self.rules:
            if rule.matches(verdict, transport, server_port):
                reasons = ("rule '{}' matched {}".format(rule.name, verdict.app),)
                if rule.application_default:
                    reasons += ("application-default: port usage {}".format(verdict.port_usage),)
                return Decision(rule.action, rule.name, reasons)
        reasons = ("no rule matched {}; policy default".format(verdict.app),)
        for rule in self.rules:
            if rule.application_default and rule.action == "allow" and verdict.port_usage == "nonstandard" \
                    and rule.matches(verdict._replace(port_usage="standard"), transport, server_port):
                reasons += ("rule '{}' would allow {} on its application-default ports only".format(rule.name, verdict.app),)
                break
        return Decision(self.default, None, reasons)

    def dependency_warnings(self):
        """Allowed applications whose implicitly-used or depended-on applications this policy denies."""
        warnings = []
        for rule in self.rules:
            if rule.action != "allow" or rule.apps is None:
                continue
            for app in sorted(rule.apps):
                entry = APPLICATIONS.get(app)
                if entry is None:
                    continue
                for dependency in entry.implicitly_uses + entry.depends_on:
                    target = APPLICATIONS.get(dependency)
                    if target is None:
                        continue
                    synthetic = Verdict(target.name, target.category, target.subcategory, target.technology, target.risk,
                                        target.characteristics, None, target.implicitly_uses, "standard", "identified",
                                        None, None, None, ())
                    decision = self.evaluate(synthetic, "tcp", None)
                    if decision.action == "deny":
                        kind = "implicitly uses" if dependency in entry.implicitly_uses else "depends on"
                        warnings.append("rule '{}' allows {} which {} {}, denied by {}".format(
                            rule.name, app, kind, dependency, "rule '{}'".format(decision.rule) if decision.rule else "the policy default"))
        return tuple(warnings)

    def lint(self):
        """Dependency warnings plus rules that can never match."""
        warnings = list(self.dependency_warnings())
        for rule in self.rules:
            if rule.application_default and rule.port_usage is not None and rule.port_usage == frozenset(("nonstandard",)):
                warnings.append("rule '{}' requires nonstandard ports and application-default at once; it never matches".format(rule.name))
            if rule.apps is not None and rule.apps <= frozenset(OUTCOMES) and (rule.categories or rule.subcategories or rule.technologies
                                                                                  or rule.risk_min or rule.risk_max or rule.characteristics):
                warnings.append("rule '{}' names only session outcomes but also requires catalog attributes; it never matches".format(rule.name))
        return tuple(warnings)
