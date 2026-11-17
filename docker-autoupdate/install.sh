#!/bin/bash
# Installs docker-autoupdate (script + systemd service + weekly timer).
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/dnviti/k8s-useful-scripts/master/docker-autoupdate/install.sh | sudo bash -s -- --day Mon --time 03:30
#
# Options:
#   --day DAY        weekday(s) for OnCalendar, e.g. Mon or Mon,Thu (default: Sun)
#   --time HH:MM     time of day (default: 03:30)
#   --keep N         image versions to keep per repository (default: 2)
#   --map "P FILE"   add "P FILE" to /etc/docker-autoupdate.conf (compose file override
#                    for project P); repeatable
#   --no-enable      install without enabling the timer
#   --uninstall      disable and remove everything (keeps /etc/docker-autoupdate.conf)
# Environment:
#   BASE_URL         where to download the files from (default: this repo on GitHub)
set -euo pipefail

BASE_URL=${BASE_URL:-https://raw.githubusercontent.com/dnviti/k8s-useful-scripts/master/docker-autoupdate}
DAY=Sun; TIME=03:30; KEEP=2; ENABLE=1; UNINSTALL=0; MAPS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --day) DAY=$2; shift 2 ;;
    --time) TIME=$2; shift 2 ;;
    --keep) KEEP=$2; shift 2 ;;
    --map) MAPS+=("$2"); shift 2 ;;
    --no-enable) ENABLE=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

BIN=/usr/local/sbin/docker-autoupdate.sh
SVC=/etc/systemd/system/docker-autoupdate.service
TMR=/etc/systemd/system/docker-autoupdate.timer
CONF=/etc/docker-autoupdate.conf

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now docker-autoupdate.timer 2>/dev/null || true
  rm -f "$BIN" "$SVC" "$TMR"
  systemctl daemon-reload
  echo "docker-autoupdate removed ($CONF left in place if present)"
  exit 0
fi

command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "docker compose plugin not found" >&2; exit 1; }
[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || { echo "--keep must be a positive integer" >&2; exit 2; }
[[ "$TIME" =~ ^[0-2][0-9]:[0-5][0-9]$ ]] || { echo "--time must be HH:MM" >&2; exit 2; }
CAL="$DAY *-*-* $TIME:00"
systemd-analyze calendar "$CAL" >/dev/null || { echo "invalid schedule: $CAL" >&2; exit 2; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for f in docker-autoupdate.sh docker-autoupdate.service docker-autoupdate.timer; do
  curl -fsSL "$BASE_URL/$f" -o "$tmp/$f"
done
bash -n "$tmp/docker-autoupdate.sh"

sed -i "s|^Environment=KEEP=.*|Environment=KEEP=$KEEP|" "$tmp/docker-autoupdate.service"
sed -i "s|^OnCalendar=.*|OnCalendar=$CAL|" "$tmp/docker-autoupdate.timer"

install -m 0755 -o root -g root "$tmp/docker-autoupdate.sh" "$BIN"
install -m 0644 -o root -g root "$tmp/docker-autoupdate.service" "$SVC"
install -m 0644 -o root -g root "$tmp/docker-autoupdate.timer" "$TMR"
for m in "${MAPS[@]}"; do
  p=${m%% *}
  touch "$CONF"; chmod 0644 "$CONF"
  sed -i "/^$p[[:space:]]/d" "$CONF"
  echo "$m" >> "$CONF"
done
command -v restorecon >/dev/null && restorecon -F "$BIN" "$SVC" "$TMR" ${MAPS:+"$CONF"} 2>/dev/null || true

systemctl daemon-reload
systemd-analyze verify "$SVC" "$TMR"
if [ "$ENABLE" = 1 ]; then
  systemctl enable --now docker-autoupdate.timer
  systemctl list-timers docker-autoupdate.timer --no-pager
else
  echo "timer installed but not enabled: systemctl enable --now docker-autoupdate.timer"
fi
echo
echo "Check what the next run would do: sudo $BIN --dry-run"
