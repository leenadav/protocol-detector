#!/bin/sh
# Run the scenarios and keep the HTML page current while they run.
cd /home/user/culvert-lab || exit 1
rm -f results/results.json
python3 tools/runner.py results/results.json &
pid=$!
while kill -0 $pid 2>/dev/null; do
  [ -f results/results.json ] && python3 tools/page.py results/results.json results/index.html 2>/dev/null
  sleep 1
done
python3 tools/page.py results/results.json results/index.html
