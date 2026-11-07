"""Protocol Observatory: the presentation application, installed as `protocol_observatory` (A01).

The modules import each other by their plain names (`jobs`, `live_manager`, `poc_decryption`) so that the
same files run from a checkout (`python3 -B presentation/server.py`) and from the installed package
(`python3 -m protocol_observatory.server`, or the `protocol-observatory` launcher); `server.py` registers
its own directory for that. The engine always comes from `protocol_engine`/`protocol_adapters`.
"""
