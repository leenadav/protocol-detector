#!/bin/sh
# Bring the whole lab back after a container restart: origins, the seven proxies, admin accounts and rules,
# the results page server and the synthetic traffic feed for the preview instance (G).
cd /home/user/culvert-lab || exit 1
pkill -f "bin/culvert-" 2>/dev/null; pkill -f tools/origins.py 2>/dev/null; pkill -f live-traffic.sh 2>/dev/null
sleep 1
tools/start-lab.sh
until curl -s -o /dev/null -m 2 --noproxy '*' http://127.0.0.1:18086/health; do sleep 1; done
python3 tools/lab_admin.py 19093 D >/dev/null
python3 tools/lab_admin.py 19095 F >/dev/null
python3 tools/lab_admin.py 19096 G http >/dev/null
pgrep -f "http.server 8899" >/dev/null || (cd results && nohup python3 -m http.server 8899 --bind 0.0.0.0 > ../run/web.log 2>&1 &)
(nohup tools/live-traffic.sh > run/live-traffic.log 2>&1 &)
echo "lab up"
