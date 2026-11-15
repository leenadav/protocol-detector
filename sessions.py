"""Root shim: this module moved to protocol_adapters.sessions (stage 1b, A01). The shim keeps bare imports,
scripts and CI steps working; the package module is the one source."""
from protocol_adapters.sessions import *  # noqa: F401,F403
from protocol_adapters import sessions as _module

globals().update({k: v for k, v in vars(_module).items() if not k.startswith("__")})
del _module
