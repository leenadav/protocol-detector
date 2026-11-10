"""Root shim: this module moved to protocol_adapters.capture_stream (stage 1b, A01). The shim keeps bare imports,
scripts and CI steps working; the package module is the one source."""
from protocol_adapters import capture_stream as _module

globals().update({k: v for k, v in vars(_module).items() if not k.startswith("__")})
del _module
