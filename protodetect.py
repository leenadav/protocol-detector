#!/usr/bin/env python3
"""One entry point for the protocol detector tools.

  protodetect analyze capture.pcap [analyze options]   offline PCAP inspection (analyze_pcap.py)
  protodetect live --interface eth0 [live options]      passive live capture (live_capture.py)
  protodetect protocols | apps | risks                  inventories (families, catalog, flow risks)
  protodetect demo                                      offline fixture walk-through
  protodetect policy lint FILE [--strict]               validate a policy and report warnings
  protodetect policy test FILE --app ssl [--port 443 ...]  evaluate a synthetic verdict
  protodetect signatures lint FILE                      validate a custom signature file
  protodetect version

The subcommands delegate to the existing scripts without changing their
options, so documentation written for them stays valid.
"""
import argparse
import json
import sys


def _delegate(module_name, argv):
    module = __import__(module_name)
    sys.argv = [module_name + ".py"] + list(argv)
    try:
        result = module.main()
    except BrokenPipeError:  # output piped into a reader that stopped early (head)
        return 0
    return 0 if result is None else int(result)


def _risks_table(as_json):
    from protocol_engine.risks import RISKS
    if as_json:
        for name, (severity, description) in RISKS.items():
            print(json.dumps({"risk": name, "severity": severity, "description": description}))
        return 0
    width = max(len(name) for name in RISKS)
    for name, (severity, description) in RISKS.items():
        print("{:<{}} {:<7} {}".format(name, width, severity, description))
    return 0


def _policy_lint(path, strict):
    from protocol_engine.policy import Policy, PolicyError
    try:
        policy = Policy.from_path(path)
    except (OSError, PolicyError, UnicodeDecodeError) as error:
        print("policy error: {}".format(error))
        return 1
    warnings = policy.lint()
    print("policy ok: {} rules, default {}".format(len(policy), policy.default))
    for warning in warnings:
        print("warning: " + warning)
    return 1 if (warnings and strict) else 0


def _policy_test(args):
    from protocol_engine.applications import APPLICATIONS, OUTCOMES, lookup
    from protocol_engine.appid import Verdict
    from protocol_engine.policy import Policy, PolicyError
    try:
        policy = Policy.from_path(args.file)
    except (OSError, PolicyError, UnicodeDecodeError) as error:
        print("policy error: {}".format(error))
        return 1
    name = args.app
    if name in OUTCOMES:
        entry = APPLICATIONS[name]
        port_usage = "unknown"
    else:
        entry = lookup(name)
        if entry is None:
            print("unknown application: " + name)
            return 1
        port_usage = ("standard" if entry.uses_port(args.transport, args.port) else "nonstandard") if args.port and entry.has_ports else "unknown"
    verdict = Verdict(entry.name, entry.category, entry.subcategory, entry.technology, entry.risk, entry.characteristics, None,
                      entry.implicitly_uses, port_usage, "identified" if name not in OUTCOMES else "unknown", None, None,
                      args.encryption, (), args.shifted_from, tuple(sorted(set(args.risk or ()))))
    decision = policy.evaluate(verdict, args.transport, args.port)
    print(json.dumps({"app": verdict.app, "transport": args.transport, "server_port": args.port, "port_usage": port_usage,
                      "risks": list(verdict.risks), "decision": decision.fields()}))
    return 0


def _signatures_lint(path):
    from protocol_engine.signatures import SignatureError, SignatureSet
    try:
        signatures = SignatureSet.from_path(path)
    except (OSError, SignatureError, UnicodeDecodeError) as error:
        print("signature error: {}".format(error))
        return 1
    print("signatures ok: {} signatures, families {}".format(len(signatures), ", ".join(sorted(signatures.families))))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="protodetect", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("analyze", "Offline PCAP inspection; remaining options go to analyze_pcap.py"),
                            ("live", "Passive live capture; remaining options go to live_capture.py")):
        sub = commands.add_parser(name, help=help_text, add_help=False)
        sub.add_argument("rest", nargs=argparse.REMAINDER)
    commands.add_parser("protocols", help="List supported protocol families")
    commands.add_parser("apps", help="Print the application catalog").add_argument("--json", action="store_true")
    commands.add_parser("risks", help="Print the flow risk table").add_argument("--json", action="store_true")
    commands.add_parser("demo", help="Offline fixture walk-through").add_argument("--json", action="store_true")
    commands.add_parser("version", help="Print the engine version")
    policy = commands.add_parser("policy", help="Validate or evaluate a policy file (POLICY.md)")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    lint = policy_commands.add_parser("lint")
    lint.add_argument("file")
    lint.add_argument("--strict", action="store_true", help="Exit 1 when warnings exist")
    test = policy_commands.add_parser("test")
    test.add_argument("file")
    test.add_argument("--app", required=True, help="Catalog application, alias or session outcome")
    test.add_argument("--transport", choices=("tcp", "udp"), default="tcp")
    test.add_argument("--port", type=int, help="Server port")
    test.add_argument("--encryption", choices=("tls", "dtls", "quic", "wireguard", "openvpn"))
    test.add_argument("--shifted-from", dest="shifted_from", help="Carrier application after a structural shift")
    test.add_argument("--risk", action="append", help="Flow risk name (repeatable)")
    signatures = commands.add_parser("signatures", help="Validate a custom signature file (SIGNATURES.md)")
    signature_commands = signatures.add_subparsers(dest="signature_command", required=True)
    signature_commands.add_parser("lint").add_argument("file")
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _delegate("analyze_pcap", args.rest)
    if args.command == "live":
        return _delegate("live_capture", args.rest)
    if args.command == "protocols":
        return _delegate("protocol_demo", ["--list"])
    if args.command == "apps":
        return _delegate("appid_catalog", ["--json"] if args.json else [])
    if args.command == "demo":
        return _delegate("protocol_demo", ["--json"] if args.json else [])
    if args.command == "risks":
        return _risks_table(args.json)
    if args.command == "version":
        import re
        from pathlib import Path
        match = re.search(r'^version = "([^"]+)"', Path(__file__).with_name("pyproject.toml").read_text(), re.M)
        print("protocol-detector {}".format(match.group(1) if match else "unknown"))
        return 0
    if args.command == "policy":
        return _policy_lint(args.file, args.strict) if args.policy_command == "lint" else _policy_test(args)
    if args.command == "signatures":
        return _signatures_lint(args.file)
    return 2


if __name__ == "__main__":
    sys.exit(main())
