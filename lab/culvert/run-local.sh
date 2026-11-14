#!/bin/sh
# Build and run the Culvert lab build (protocol detector + new UI) on your own machine.
#
#   sh lab/culvert/run-local.sh            build, then run
#   sh lab/culvert/run-local.sh --build    build only
#
# Run it from the root of your protocol-detector checkout, on branch claude/culvert-integration-prep.
# It works in ./lab-work (ignored by nothing else, safe to delete) and never pushes anywhere:
#   - clones KidCarmi/Culvert at the pinned commit and applies lab/culvert/culvert-lab-52eb9d1.patch,
#   - builds Culvert's new frontend and the lab binary against THIS checkout's go/ module,
#   - starts the proxy on http://localhost:8080 and the admin UI on https://localhost:9090.
#
# Needs: git, Go 1.27.4 or newer, Node 24.19.0 with npm 11.17.0 (the versions Culvert's frontend pins).
# Lab build only. It is not a release, and the enforce mode is a demonstration (see README.md).
set -eu

CULVERT_SHA=52eb9d1e4482adc9773afc4db77109acad617625
ROOT=$(pwd)
[ -f "$ROOT/go/detector/detector.go" ] && [ -f "$ROOT/lab/culvert/culvert-lab-52eb9d1.patch" ] || {
  echo "Run this from the root of the protocol-detector checkout (branch claude/culvert-integration-prep)." >&2
  exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1. $2" >&2; exit 1; }; }
need git "Install git."
need go "Install Go 1.27.4 or newer (https://go.dev/dl/)."
need node "Install Node 24.19.0 (https://nodejs.org/dist/v24.19.0/)."
need npm "npm 11.17.0 is needed: npm install -g npm@11.17.0"
[ "$(node --version)" = "v24.19.0" ] || { echo "Node $(node --version) found; Culvert's frontend pins v24.19.0." >&2; exit 1; }
[ "$(npm --version)" = "11.17.0" ] || { echo "npm $(npm --version) found; Culvert's frontend pins 11.17.0 (npm install -g npm@11.17.0)." >&2; exit 1; }

WORK="$ROOT/lab-work"
mkdir -p "$WORK"
if [ ! -d "$WORK/culvert/.git" ]; then
  git clone https://github.com/KidCarmi/Culvert "$WORK/culvert"
  git -C "$WORK/culvert" checkout -q -b lab/protocol-detector "$CULVERT_SHA"
  git -C "$WORK/culvert" remote set-url --push origin DISABLED-lab-no-push
  git -C "$WORK/culvert" -c user.name=lab -c user.email=lab@localhost am -q "$ROOT/lab/culvert/culvert-lab-52eb9d1.patch"
fi
printf 'go 1.27.0\n\ntoolchain go1.27.4\n\nuse (\n\t%s\n\t%s\n)\n' "$WORK/culvert" "$ROOT/go" > "$WORK/go.work"

echo "Building the frontend..."
(cd "$WORK/culvert/frontend" && npm ci --no-audit >/dev/null && npm run build >/dev/null)
echo "Building the lab binary..."
(cd "$WORK/culvert" && GOWORK="$WORK/go.work" go build -o "$WORK/culvert-lab" .)
echo "Built: $WORK/culvert-lab"
[ "${1:-}" = "--build" ] && exit 0

mkdir -p "$WORK/data"
cat <<'EOF'

Starting Culvert (lab build). Stop it with Ctrl+C.

  Admin UI (new frontend):  https://localhost:9090/app      accept the self-signed certificate
  First visit:              https://localhost:9090          create the admin account, then open /app
  Proxy:                    http://localhost:8080           after setup it asks for that admin user and password

What to try:
  - Monitor > Traffic: the "Application / Protocol" column and the row detail show what the detector saw.
    If history is disabled, press "Query recent memory instead".
  - Policies > Access Rules: edit or create an Allow rule with TLS action Bypass, then set
    "Protocol restriction (lab)". Add a final Allow-everything rule first, because a rulebase with rules
    denies whatever no rule matches.
  - Send something through the proxy, for example:
      curl -x http://admin:YOUR_PASSWORD@localhost:8080 https://example.com -o /dev/null

Only CONNECT tunnels that Culvert relays without inspection are observed. The traffic you send through
this proxy is your own; observations (including host names) are written to Culvert's local log.

EOF
exec env CULVERT_DATA_DIR="$WORK/data" CULVERT_EXPERIMENTAL_UI=1 CULVERT_LAB_PROTODETECT=real \
  "$WORK/culvert-lab" -port 8080 -ui-port 9090
