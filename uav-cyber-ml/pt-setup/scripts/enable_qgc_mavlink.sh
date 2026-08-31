#!/usr/bin/env bash
# Start a dedicated PX4 mavlink UDP instance for QGroundControl on the Mac.
# Leaves the Digital Twin path on UDP 14550 untouched.
set -euo pipefail
source "$HOME/uav_cyber_testbed/config/lab_env.sh"

# Target the Digital Twin, not a hardcoded lab address.
# Priority: explicit DT_IP > the peer that SSHed in to start SITL > lab default.
# The DT is always the host that runs ssh_control.start_sitl(), so $SSH_CLIENT
# is its address — this works on DHCP with no configuration on either side.
_SSH_PEER="$(echo "${SSH_CLIENT:-}" | awk "{print \$1}")"
QGC_HOST="${DT_IP:-${_SSH_PEER:-${QGC_HOST:-192.168.123.123}}}"
# PX4 SITL only talks to localhost unless told otherwise, and the DT recorder
# binds udpin:0.0.0.0:14550 — so send there, not to the old QGC port 14540.
QGC_PORT="${DT_GCS_PORT:-${PX4_GCS_PORT:-14550}}"
# Local bind on UAV (must not collide with existing 14550/14580/18570)
QGC_LOCAL_PORT="${QGC_LOCAL_PORT:-14541}"

PX4PID="$(ss -ulnp 2>/dev/null | sed -n 's/.*18570.*pid=\([0-9][0-9]*\).*/\1/p' | head -1)"
if [ -z "${PX4PID}" ]; then
  PX4PID="$(pgrep -n -f "$PX4_ROOT/build/px4_sitl_default/bin/px4 " || true)"
fi
if [ -z "${PX4PID}" ]; then
  echo "[error] PX4 SITL process not found; start SITL first" >&2
  exit 1
fi

# Already up?
if ss -ulnp 2>/dev/null | grep -q ":${QGC_LOCAL_PORT} "; then
  echo "[info] mavlink QGC local port ${QGC_LOCAL_PORT} already listening (pid check via ss)"
  exit 0
fi

if [ ! -w "/proc/${PX4PID}/fd/0" ] && [ ! -e "/proc/${PX4PID}/fd/0" ]; then
  echo "[error] cannot write PX4 shell stdin (/proc/${PX4PID}/fd/0)" >&2
  exit 1
fi

echo "[info] starting QGC mavlink: local ${QGC_LOCAL_PORT} -> ${QGC_HOST}:${QGC_PORT} (px4 pid ${PX4PID})"
# Write full command + newline; PX4 nsh echoes char-by-char from the pipe
printf 'mavlink start -x -u %s -r 4000000 -t %s -o %s\n' \
  "$QGC_LOCAL_PORT" "$QGC_HOST" "$QGC_PORT" > "/proc/${PX4PID}/fd/0"

# Wait briefly for bind
for i in 1 2 3 4 5 6 7 8 9 10; do
  if ss -ulnp 2>/dev/null | grep -q ":${QGC_LOCAL_PORT} "; then
    echo "[info] QGC mavlink listening on UDP ${QGC_LOCAL_PORT} -> ${QGC_HOST}:${QGC_PORT}"
    exit 0
  fi
  sleep 0.5
done

echo "[warn] mavlink start sent but UDP ${QGC_LOCAL_PORT} not observed yet; check pxh console" >&2
exit 1
