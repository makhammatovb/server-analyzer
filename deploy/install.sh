#!/usr/bin/env bash
# FleetGuard agent installer. Served by the dashboard origin and run as root:
#
#   curl -sSL https://<dashboard>/install.sh | sudo bash -s -- --server-url=<agent origin>
#
# The enrolment token is read from the terminal (/dev/tty) when the script asks
# for it: paste it at the prompt. That keeps it out of argv (visible to every
# local user in ps), the environment, shell history and disk. Non-interactive
# automation may instead set FG_ENROL_TOKEN in the installer's environment (note
# that sudo's env_reset often strips it: use `sudo --preserve-env=FG_ENROL_TOKEN`)
# or pass --token=, accepting that argv is then readable by local users.
#
# The dashboard origin below is filled in by the reverse proxy when it serves
# this file. That TLS connection (publicly trusted) is this installer's only
# trust anchor: it delivers ca.crt, the one file the agent trusts afterwards.
#
# NOTE (deliberate deviation from the design, tracked for Phase 5): the agent
# binary is verified against a SHA-256 checksum fetched over the same TLS
# connection. That catches a corrupted download, NOT a compromised central
# host. Signature verification against a pinned key is outstanding.
set -euo pipefail

BASE_URL='{{env "FG_BASE_URL"}}'

BIN=/usr/local/bin/fleetguard-agent
CONF_DIR=/etc/fleetguard
CONF=$CONF_DIR/agent.yaml
STATE_DIR=/var/lib/fleetguard
UNIT=/etc/systemd/system/fleetguard-agent.service

die() { echo "fleetguard-install: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
[ "$(uname -s)" = Linux ] || die "only Linux is supported"
case $BASE_URL in
  https://*) ;;
  *) die "this script was not served by a FleetGuard dashboard (no origin was filled in); fetch it from https://<your-dashboard>/install.sh" ;;
esac

TOKEN=${FG_ENROL_TOKEN:-}
unset FG_ENROL_TOKEN
SERVER_URL=""
for arg in "$@"; do
  case $arg in
    --token=*) TOKEN=${arg#--token=} ;;
    --server-url=*) SERVER_URL=${arg#--server-url=} ;;
    *) die "unknown argument: $arg" ;;
  esac
done
[ -n "$SERVER_URL" ] || die "--server-url is required (the agent origin, not the dashboard)"
if [ -z "$TOKEN" ]; then
  # The script itself arrives on stdin, so the terminal is read directly.
  { : </dev/tty; } 2>/dev/null || die "no terminal to ask for the enrolment token on: run the command from an interactive shell, or set FG_ENROL_TOKEN for automation"
  printf 'Paste the enrolment token and press Enter: ' >/dev/tty
  IFS= read -r -s TOKEN </dev/tty || die "could not read the enrolment token"
  printf '\n' >/dev/tty
  TOKEN=${TOKEN//[[:space:]]/}
fi
[ -n "$TOKEN" ] || die "no enrolment token given"
# Both values end up in a root-run script and a config file: accept only what
# an origin and a base64url token can look like.
[[ $TOKEN =~ ^[A-Za-z0-9_-]+$ ]] || die "malformed token"
[[ $SERVER_URL =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]] || die "--server-url must be a bare https origin, e.g. https://agents.example.com"
SERVER_URL=${SERVER_URL%/}
[ "$SERVER_URL" != "${BASE_URL%/}" ] || die "--server-url is the dashboard origin; the agent origin presents the fleet CA certificate the agent pins, and the dashboard's ACME certificate would fail every request"

case $(uname -m) in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
command -v curl >/dev/null || die "curl is required"
command -v sha256sum >/dev/null || die "sha256sum is required"

# Children must never read the script from stdin when it is piped to bash.
fetch() { curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 120 "$1" -o "$2" </dev/null; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; unset TOKEN' EXIT

echo "Downloading fleetguard-agent ($ARCH)..."
NAME=fleetguard-agent-linux-$ARCH
fetch "$BASE_URL/downloads/$NAME" "$TMP/$NAME"
fetch "$BASE_URL/downloads/$NAME.sha256" "$TMP/$NAME.sha256"
want=$(awk '{print $1; exit}' "$TMP/$NAME.sha256")
got=$(sha256sum "$TMP/$NAME" | awk '{print $1}')
[[ $want =~ ^[0-9a-f]{64}$ ]] || die "checksum file is malformed"
[ "$want" = "$got" ] || die "checksum mismatch for $NAME (expected $want, got $got); refusing to install"

# The root of trust: the fleet CA, fetched over the publicly trusted TLS
# connection and installed BEFORE enrolment. The agent has no fallback to
# system roots, so a missing ca.crt is a hard error rather than a downgrade.
fetch "$BASE_URL/ca.crt" "$TMP/ca.crt"
grep -q -- '-----BEGIN CERTIFICATE-----' "$TMP/ca.crt" || die "$BASE_URL/ca.crt is not a certificate"

install -d -m 0700 -o root -g root "$CONF_DIR" "$STATE_DIR"
install -m 0755 -o root -g root "$TMP/$NAME" "$BIN.new"
mv -f "$BIN.new" "$BIN"
install -m 0600 -o root -g root "$TMP/ca.crt" "$STATE_DIR/ca.crt"

umask 077
printf 'server_url: %s\n' "$SERVER_URL" >"$CONF.new"
mv -f "$CONF.new" "$CONF"

# The token goes to the agent in its environment, never on its command line
# (visible to every local user in ps) and never to disk. If this host is
# already enrolled the agent says so and spends nothing.
echo "Enrolling..."
FG_ENROL_TOKEN=$TOKEN "$BIN" enrol --config="$CONF" --state-dir="$STATE_DIR" </dev/null
unset TOKEN

fetch "$BASE_URL/fleetguard-agent.service" "$TMP/fleetguard-agent.service"
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  install -m 0644 -o root -g root "$TMP/fleetguard-agent.service" "$UNIT"
  systemctl daemon-reload
  systemctl enable fleetguard-agent.service
  systemctl restart fleetguard-agent.service
  echo "FleetGuard agent installed and running (systemctl status fleetguard-agent)."
else
  install -m 0644 -o root -g root "$TMP/fleetguard-agent.service" "$UNIT" 2>/dev/null || true
  echo "FleetGuard agent installed, but systemd is not running here, so it was not started."
  echo "Run it with: $BIN run --config=$CONF"
fi
