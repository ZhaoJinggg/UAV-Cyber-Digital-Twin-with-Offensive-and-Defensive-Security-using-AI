#!/usr/bin/env bash
set -euo pipefail

export TESTBED_ROOT="$HOME/uav_cyber_testbed"
export PX4_ROOT="$HOME/PX4-Autopilot"
export ROS_WS="$HOME/px4_ros2_ws"
export ARTIFACT_ROOT="$TESTBED_ROOT/artifacts"
export EXPERIMENT_ID_DEFAULT="exp_$(date +%Y%m%d_%H%M%S)"
export PX4_GCS_PORT="14550"
export PX4_GCS_API_PORT="18570"
export PX4_ATTACK_PORT="14580"
export PX4_RX_PORT="14540"
export PX4_COMMANDER="$PX4_ROOT/build/px4_sitl_default/bin/px4-commander"
export ATTACK_TAKEOFF_ALT="2.5"
export XRCE_PORT="8888"
# Legacy static fallback ONLY. enable_qgc_mavlink.sh prefers $DT_IP, then the
# address of whoever SSHed in to start SITL ($SSH_CLIENT) — which is the Digital
# Twin. You should not need to edit this, even on DHCP.
export QGC_HOST="192.168.123.123"
export SITL_HOST="127.0.0.1"
export QGC_LOCAL_PORT="14541"
