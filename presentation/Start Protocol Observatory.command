#!/bin/bash
# Starts the local presentation with the system interpreter; install the optional extra first:
#   python3 -m pip install -e ".[decryption]"   (from the repository root)
cd "$(dirname "$0")" || exit 1
python3 -B launch.py
if [ $? -ne 0 ]; then
  read -r -p "Press Enter to close…"
fi
