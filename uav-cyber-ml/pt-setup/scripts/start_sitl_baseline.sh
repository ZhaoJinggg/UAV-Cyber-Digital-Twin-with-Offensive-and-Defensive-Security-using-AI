#!/usr/bin/env bash
set -euo pipefail
source "$HOME/uav_cyber_testbed/config/lab_env.sh"

mkdir -p "$ARTIFACT_ROOT/runtime"
LOG_FILE="$ARTIFACT_ROOT/runtime/px4_sitl_$(date +%Y%m%d_%H%M%S).log"

# keep only the 5 most recent SITL console logs (prevents filling the disk)
ls -1t "$ARTIFACT_ROOT/runtime"/px4_sitl_*.log 2>/dev/null | tail -n +6 | xargs -r rm -f || true

echo "[info] stopping old SITL processes if present"
pkill -f "make px4_sitl gazebo-classic|sitl_run.sh|gzserver|gzclient|px4 $PX4_ROOT" 2>/dev/null || true
sleep 2

echo "[info] rotating oversized /tmp/px4_sitl_gazebo.log if needed"
if [ -f /tmp/px4_sitl_gazebo.log ] && [ "$(stat -c%s /tmp/px4_sitl_gazebo.log 2>/dev/null || echo 0)" -gt 104857600 ]; then
  truncate -s 0 /tmp/px4_sitl_gazebo.log
fi

echo "[info] starting PX4 SITL + Gazebo Classic"
# stdin from /dev/null: keeps the PX4 pxh> shell non-interactive so it does NOT
# spin and spam the console log (that bug produced tens of GB per run).
nohup bash -lc "export DISPLAY=:0; export XDG_RUNTIME_DIR=/run/user/$(id -u); export QT_QPA_PLATFORM=xcb; cd '$PX4_ROOT' && make px4_sitl gazebo-classic" < <(sleep infinity) > "$LOG_FILE" 2>&1 &
echo $! > "$ARTIFACT_ROOT/runtime/px4_sitl.pid"

sleep 5

echo "[info] starting Micro XRCE Agent if not running"
pgrep -f "MicroXRCEAgent udp4 -p $XRCE_PORT" >/dev/null || nohup /usr/local/bin/MicroXRCEAgent udp4 -p "$XRCE_PORT" > "$ARTIFACT_ROOT/runtime/microxrce_$(date +%Y%m%d_%H%M%S).log" 2>&1 < /dev/null &

echo "[info] baseline launch complete"
echo "[info] PX4 log: $LOG_FILE"

# Dedicated QGC MAVLink path for the Mac (UDP 14540). Does NOT touch DT :14550.
echo "[info] enabling QGC mavlink on ${QGC_HOST:-192.168.123.123}:${PX4_RX_PORT:-14540}"
for i in $(seq 1 30); do
  if pgrep -f "$PX4_ROOT/build/px4_sitl_default/bin/px4 " >/dev/null; then
    break
  fi
  sleep 1
done
# Give mavlink module time to finish default startups
sleep 8
"$TESTBED_ROOT/scripts/enable_qgc_mavlink.sh" || echo "[warn] QGC mavlink enable failed (SITL may still be starting); run scripts/enable_qgc_mavlink.sh later"
