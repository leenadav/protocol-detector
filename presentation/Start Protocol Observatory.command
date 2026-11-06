#!/bin/bash
cd "$(dirname "$0")" || exit 1
demo_python="/Users/lee/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
if [ ! -x "$demo_python" ]; then
  demo_python="/usr/bin/python3"
fi
"$demo_python" -B launch.py
if [ $? -ne 0 ]; then
  read -r -p "Press Enter to close…"
fi
