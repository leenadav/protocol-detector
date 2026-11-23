#!/bin/sh
# Visibility-only lab run (decision 3, 2026-11-17): builds A (unmodified Culvert at LAB_CULVERT_BASE) to E, fresh
# data directories, no admin accounts and no restriction rules; then the observation scenarios.
# Loopback only; origins on RFC 5737 addresses; every Culvert protection stays on.
# Usage: LAB_CULVERT_BASE=<commit> tools/start-lab-visibility.sh
cd /home/user/culvert-lab/run || exit 1
: "${LAB_CULVERT_BASE:?set LAB_CULVERT_BASE to the Culvert commit build A was built from}"
pkill -f "bin/culvert-" 2>/dev/null; pkill -f tools/origins.py 2>/dev/null; sleep 1
python3 ../tools/addaddr.py 203.0.113.10 203.0.113.20 >/dev/null
grep -q origin.lab.test /etc/hosts || echo "203.0.113.10 origin.lab.test" >> /etc/hosts
grep -q secure.lab.test /etc/hosts || echo "203.0.113.20 secure.lab.test monitor.lab.test" >> /etc/hosts
(nohup python3 ../tools/origins.py ../certs > origins.log 2>&1 &)
start() { name=$1; bin=$2; port=$3; ui=$4; shift 4
  rm -rf "data-v-$name"; mkdir -p "data-v-$name"
  (env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u ALL_PROXY -u NO_PROXY -u no_proxy \
     CULVERT_DATA_DIR=/home/user/culvert-lab/run/data-v-$name "$@" nohup ../bin/$bin -port $port -ui-port $ui > culvert-$name.log 2>&1 &); }
start A culvert-A   18080 19090
start B culvert-lab 18081 19091
start C culvert-lab 18082 19092 CULVERT_LAB_PROTODETECT=fake CULVERT_LAB_PD_WINDOW_MS=3000
start D culvert-lab 18083 19093 CULVERT_LAB_PROTODETECT=real CULVERT_LAB_PD_WINDOW_MS=3000
start E culvert-lab 18084 19094 CULVERT_LAB_PROTODETECT=fake CULVERT_LAB_PD_WINDOW_MS=3000 CULVERT_LAB_PD_FAKE_PANIC=observe
for port in 18080 18081 18082 18083 18084; do
  until curl -s -o /dev/null -m 2 --noproxy '*' "http://127.0.0.1:$port/health"; do sleep 1; done
done
cd .. && rm -f results/results.json
LAB_VISIBILITY_ONLY=1 python3 tools/runner.py results/results.json
python3 tools/page.py results/results.json results/index.html
pkill -f "bin/culvert-" 2>/dev/null; pkill -f tools/origins.py 2>/dev/null
echo "visibility run finished"
