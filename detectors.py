"""Root shim: this module moved to protocol_adapters.detectors (stage 1b, A01). The shim keeps bare imports,
scripts and CI steps working; the package module is the one source."""
from protocol_adapters import detectors as _module

globals().update({k: v for k, v in vars(_module).items() if not k.startswith("__")})
del _module
