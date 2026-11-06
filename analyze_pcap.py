"""Root shim: this module moved to protocol_adapters.analyze_pcap (stage 1b, A01). The shim keeps bare imports,
scripts and CI steps working; the package module is the one source."""
from protocol_adapters.analyze_pcap import *  # noqa: F401,F403
from protocol_adapters.analyze_pcap import main
from protocol_adapters import analyze_pcap as _module

globals().update({k: v for k, v in vars(_module).items() if not k.startswith("__")})
del _module

if __name__ == "__main__":
    main()
