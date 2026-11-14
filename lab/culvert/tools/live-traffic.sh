#!/bin/sh
# Keep the preview instance (G) supplied with fresh synthetic tunnels for two hours, so its Traffic page is live.
cd /home/user/culvert-lab || exit 1
i=0
while [ $i -lt 240 ]; do
  python3 tools/sample_traffic.py 18086 >/dev/null 2>&1
  python3 tools/policy_samples.py 18086 >/dev/null 2>&1
  i=$((i + 1))
  sleep 30
done
