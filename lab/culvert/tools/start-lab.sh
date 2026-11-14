#!/bin/sh
# Start the four lab proxies (A unmodified, B integrated/off, C fake engine, D real detector) and the origins.
# Loopback only; origins on RFC 5737 addresses; every Culvert protection stays on.
cd /home/user/culvert-lab/run || exit 1
python3 ../tools/addaddr.py 203.0.113.10 203.0.113.20 >/dev/null
grep -q origin.lab.test /etc/hosts || echo "203.0.113.10 origin.lab.test" >> /etc/hosts
grep -q secure.lab.test /etc/hosts || echo "203.0.113.20 secure.lab.test monitor.lab.test" >> /etc/hosts
pgrep -f tools/origins.py >/dev/null || (nohup python3 ../tools/origins.py ../certs > origins.log 2>&1 &)
start() { name=$1; bin=$2; port=$3; ui=$4; shift 4; extra=""
  [ "$name" = G ] && extra="-ui-no-tls"
  mkdir -p data-$name
  (env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u ALL_PROXY -u NO_PROXY -u no_proxy \
     CULVERT_DATA_DIR=/home/user/culvert-lab/run/data-$name "$@" nohup ../bin/$bin -port $port -ui-port $ui $extra > culvert-$name.log 2>&1 &); }
start A culvert-A   18080 19090
start B culvert-lab 18081 19091
start C culvert-lab 18082 19092 CULVERT_LAB_PROTODETECT=fake CULVERT_LAB_PD_WINDOW_MS=3000
start D culvert-lab 18083 19093 CULVERT_LAB_PROTODETECT=real CULVERT_LAB_PD_WINDOW_MS=3000 CULVERT_EXPERIMENTAL_UI=1
start E culvert-lab 18084 19094 CULVERT_LAB_PROTODETECT=fake CULVERT_LAB_PD_WINDOW_MS=3000 CULVERT_LAB_PD_FAKE_PANIC=observe
start F culvert-lab 18085 19095
# G: the same as D, with the admin UI over plain HTTP for the preview pane (loopback lab only).
start G culvert-lab 18086 19096 CULVERT_LAB_PROTODETECT=real CULVERT_LAB_PD_WINDOW_MS=3000 CULVERT_EXPERIMENTAL_UI=1
