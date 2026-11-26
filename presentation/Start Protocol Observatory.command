#!/bin/bash
# Starts the local presentation on the Go engine (protodetect serve); build the binary first:
#   make go-build   (from the repository root), or set PROTODETECT_GO_BINARY
cd "$(dirname "$0")" || exit 1
python3 -B launch.py
if [ $? -ne 0 ]; then
  read -r -p "Press Enter to close…"
fi
