#!/usr/bin/env python3
"""One entry point for the protocol detector tools.

  protodetect analyze capture.pcap [analyze options]   offline PCAP inspection (the Go engine)
  protodetect live --interface eth0 [live options]      passive live capture (the Go engine)
  protodetect serve [--port N]                          the local demo page (the Go engine; make serve)
  protodetect schema [NAME] [--validate FILE]           print a published output schema or validate JSON Lines
  protodetect version

analyze, live and serve run the Go engine's binary with the arguments unchanged (PRO-402: Go is the product;
there is no Python backend to select and no fallback). The binary is PROTODETECT_GO_BINARY, then
go/bin/protodetect of this checkout (`make go-build`), then `protodetect-go` on PATH.

PRO-403: the Python reference engine is removed (its last state is the tag python-final), and with it the
subcommands that ran it (protocols, apps, risks, demo, content, explain, policy, signatures). schema stays: it
reads only the published schemas/ files.
"""
import argparse
import json
import sys


GO_COMMANDS = ("analyze", "live", "serve")


def go_binary():
    """The Go engine's binary, or None: PROTODETECT_GO_BINARY, then go/bin/protodetect, then protodetect-go."""
    import os
    import shutil
    from pathlib import Path
    named = os.environ.get("PROTODETECT_GO_BINARY")
    if named:
        return named if os.path.isfile(named) and os.access(named, os.X_OK) else None
    built = Path(__file__).resolve().parent / "go" / "bin" / "protodetect"
    if built.is_file() and os.access(str(built), os.X_OK):
        return str(built)
    return shutil.which("protodetect-go")


def _go(argv):
    """Run the Go binary with these arguments and return its exit status (2 when it is not installed)."""
    import subprocess
    binary = go_binary()
    if binary is None:
        sys.stderr.write("protodetect: the Go engine binary is not installed (make go-build, or set PROTODETECT_GO_BINARY)\n")
        return 2
    try:
        return subprocess.call([binary] + list(argv))  # noqa: S603 - the Go binary, the caller's own arguments
    except KeyboardInterrupt:
        return 130


REMOVED = ("protocols", "apps", "risks", "demo", "content", "explain", "policy", "signatures")


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else list(argv)
    if arguments and arguments[0] in GO_COMMANDS:
        # Everything after these commands belongs to the Go binary. argparse.REMAINDER does not accept an
        # option as the first remaining argument ("live --stdin", "live --interface eth0"), so they are
        # handed over before the parser sees them.
        return _go(arguments)
    if arguments and arguments[0] in REMOVED:
        sys.stderr.write("protodetect: '{}' ran the Python reference engine, which was removed (PRO-403); "
                         "its last state is the tag python-final\n".format(arguments[0]))
        return 2
    parser = argparse.ArgumentParser(prog="protodetect", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("analyze", "Offline PCAP inspection; remaining options go to the Go engine"),
                            ("live", "Passive live capture; remaining options go to the Go engine"),
                            ("serve", "The local demo page on 127.0.0.1; remaining options go to the Go engine")):
        sub = commands.add_parser(name, help=help_text, add_help=False)
        sub.add_argument("rest", nargs=argparse.REMAINDER)
    commands.add_parser("version", help="Print the version")
    schema = commands.add_parser("schema", help="Print an output schema (OUTPUT.md) or validate JSON Lines against one")
    schema.add_argument("name", nargs="?", help="session, live-event or offline-row; omitted lists the schemas")
    schema.add_argument("--validate", metavar="FILE", help="JSON Lines file (or - for stdin) to validate against NAME")
    args = parser.parse_args(argv)
    if args.command in GO_COMMANDS:
        return _go([args.command] + args.rest)
    if args.command == "version":
        import re
        from pathlib import Path
        match = re.search(r'^version = "([^"]+)"', Path(__file__).with_name("pyproject.toml").read_text(), re.M)
        print("protocol-detector {}".format(match.group(1) if match else "unknown"))
        return 0
    if args.command == "schema":
        sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent / "tools"))
        import schema_check
        if args.name is None:
            for name in schema_check.names():
                print(name)
            return 0
        if args.name not in schema_check.names():
            print("unknown schema: " + args.name)
            return 1
        if args.validate:
            return schema_check.main([args.name, args.validate])
        print(json.dumps(schema_check.load(args.name), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
