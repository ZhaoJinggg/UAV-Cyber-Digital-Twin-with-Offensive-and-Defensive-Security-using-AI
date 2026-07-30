"""Start/stop/monitor PX4 SITL on the UAV machine over passwordless SSH."""

from __future__ import annotations

import subprocess
import time

from pymavlink import mavutil

import config as C


def _ssh(cmd: str, timeout=60) -> tuple[int, str]:
    full = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5", f"{C.SSH_USER}@{C.UAV_HOST}", cmd]
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "ssh timeout"


def uav_reachable() -> tuple[bool, str]:
    """Fast check that the Physical Twin host answers SSH."""
    code, out = _ssh("echo ok", timeout=8)
    text = (out or "").strip()
    if code == 0 and "ok" in text:
        return True, ""
    detail = text.splitlines()[0] if text else f"exit {code}"
    return False, (
        f"Physical Twin unreachable ({C.SSH_USER}@{C.UAV_HOST}): {detail}. "
        "Connect this Mac to the lab network (192.168.123.x), power on the UAV PC, "
        "then click Start sim before running scenarios."
    )


def start_sitl() -> str:
    # Script returns after launching make in the background (~few seconds), but
    # SSH + pkill + sleeps can exceed 60s on a loaded UAV PC.
    code, out = _ssh(f"cd {C.TESTBED_DIR} && ./scripts/start_sitl_baseline.sh",
                     timeout=90)
    # PX4 often brings up gzserver only; ensure the Gazebo *GUI* (PT) is visible
    # on the UAV display so DT ↔ PT stay visually coupled.
    gui = ensure_gzclient()
    return (out or f"(ssh exit {code})") + f"\n[pt] {gui}"


def stop_sitl() -> str:
    cmd = ("pkill -f 'make px4_sitl gazebo-classic' 2>/dev/null; "
           "pkill -f sitl_run.sh 2>/dev/null; pkill -f gzserver 2>/dev/null; "
           "pkill -f gzclient 2>/dev/null; pkill -f 'px4_sitl_default/bin/px4' 2>/dev/null; "
           "sleep 0.5; rm -f /tmp/px4-sock-0; echo stopped")
    _, out = _ssh(cmd, timeout=30)
    return out


def gzclient_running() -> bool:
    """True if the Gazebo Classic GUI (physical-twin view) is up on the UAV."""
    code, out = _ssh("pgrep -x gzclient >/dev/null && echo yes || echo no",
                     timeout=10)
    return "yes" in (out or "")


def ensure_gzclient() -> str:
    """Start gzclient on DISPLAY=:0 if gzserver is up but the GUI is missing.

    Headless gzserver alone makes the Mac DT look 'live' while the UAV has no
    visible Physical Twin window — which is the failure mode we care about.
    Uses the same Gazebo master / model paths as the PX4 SITL launch.
    """
    code, out = _ssh(
        "if pgrep -x gzclient >/dev/null; then echo already_running; "
        "elif ! pgrep -x gzserver >/dev/null; then echo no_gzserver; "
        "else "
        "  export DISPLAY=${DISPLAY:-:0}; "
        "  export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}; "
        "  export QT_QPA_PLATFORM=xcb; "
        "  export GAZEBO_MASTER_URI=${GAZEBO_MASTER_URI:-http://127.0.0.1:11345}; "
        "  PX4=$HOME/PX4-Autopilot; "
        "  export GAZEBO_PLUGIN_PATH=\"${GAZEBO_PLUGIN_PATH}:$PX4/build/px4_sitl_default/build_gazebo-classic\"; "
        "  export GAZEBO_MODEL_PATH=\"${GAZEBO_MODEL_PATH}:$PX4/Tools/simulation/gazebo-classic/sitl_gazebo-classic/models\"; "
        "  nohup gzclient >/tmp/gzclient_dashboard.log 2>&1 & "
        "  sleep 1.5; "
        "  if pgrep -x gzclient >/dev/null; then echo started; "
        "  else echo start_failed:$(tail -c 200 /tmp/gzclient_dashboard.log 2>/dev/null | tr '\\n' ' '); fi; "
        "fi",
        timeout=20,
    )
    return (out or f"ssh_exit_{code}").strip().splitlines()[-1] if (out or "").strip() else f"ssh_exit_{code}"


def pt_status() -> dict:
    """Compact Physical Twin health for the dashboard (+ live Gazebo iris pose)."""
    code, out = _ssh(
        "echo PX4=$(pgrep -c -f 'px4_sitl_default/bin/px4' || true); "
        "echo GZSERVER=$(pgrep -c -x gzserver || true); "
        "echo GZCLIENT=$(pgrep -c -x gzclient || true); "
        "echo DISPLAY=${DISPLAY:-:0}; "
        "POSE=$(gz model -m iris -p 2>/dev/null | head -1); "
        "echo POSE=${POSE:-none}",
        timeout=12,
    )
    info = {"px4": 0, "gzserver": 0, "gzclient": 0, "display": ":0",
            "raw": out, "pose": None}
    for line in (out or "").splitlines():
        if line.startswith("PX4="):
            try: info["px4"] = int(line.split("=", 1)[1])
            except ValueError: pass
        elif line.startswith("GZSERVER="):
            try: info["gzserver"] = int(line.split("=", 1)[1])
            except ValueError: pass
        elif line.startswith("GZCLIENT="):
            try: info["gzclient"] = int(line.split("=", 1)[1])
            except ValueError: pass
        elif line.startswith("DISPLAY="):
            info["display"] = line.split("=", 1)[1] or ":0"
        elif line.startswith("POSE=") and line != "POSE=none":
            parts = line.split("=", 1)[1].split()
            try:
                # Gazebo: x y z roll pitch yaw  (ENU-ish world frame)
                info["pose"] = {
                    "x": float(parts[0]), "y": float(parts[1]),
                    "z": float(parts[2]),
                }
            except (IndexError, ValueError):
                info["pose"] = None
    info["ok"] = info["px4"] > 0 and info["gzserver"] > 0 and info["gzclient"] > 0
    info["gui"] = info["gzclient"] > 0
    info["flying"] = bool(info.get("pose") and info["pose"]["z"] > 1.0)
    info["where"] = (
        f"UAV display {info['display']} @ {C.UAV_HOST} "
        "(Gazebo GUI is on the UAV PC, not the Mac browser)"
    )
    return info


def probe_passive(timeout: float = 6.0) -> tuple[bool, bool, float | None, float | None]:
    """Detect PX4 by passively reading its GCS broadcast on 14550.

    This is the reliable channel in SITL (PX4 streams full telemetry to the Mac
    on 14550). Returns ``(alive, grounded, x, y)`` where x/y are local-NED
    metres (or None if not yet seen). grounded == alive, disarmed, near ground.

    NOTE: binds UDP 14550, so callers must not overlap this with the physical
    recorder (which also binds 14550). Always call it sequentially, when idle.
    """
    try:
        c = mavutil.mavlink_connection(f"udpin:0.0.0.0:{C.GCS_PORT}")
    except OSError:
        return (False, False, None, None)   # someone else holds 14550
    alive = False
    alt = None
    armed = None
    x = y = None
    t0 = time.time()
    try:
        while time.time() - t0 < timeout:
            m = c.recv_match(blocking=True, timeout=0.4)
            if not m or m.get_srcSystem() != C.PX4_SYSID:
                continue
            t = m.get_type()
            if t == "HEARTBEAT":
                alive = True
                armed = bool(m.base_mode
                             & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
            elif t == "LOCAL_POSITION_NED":
                alt = -m.z
                x, y = float(m.x), float(m.y)
            if alive and armed is not None and alt is not None:
                break
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass
    grounded = bool(alive and (armed is False) and (alt is None or alt < 1.0))
    return (alive, grounded, x, y)


def reset_home(model: str = "iris") -> str:
    """Teleport the Gazebo model back to the origin (default spawn).

    Fast alternative to a full Gazebo reboot when we want the next run to start
    at (0, 0). Leaves gzserver / PX4 running.
    """
    cmd = (f"gz model -m {model} -x 0 -y 0 -z 0.12 2>/dev/null; "
           f"gz model -m {model} -p 2>/dev/null || echo reset_failed")
    _, out = _ssh(cmd, timeout=15)
    return out.strip()


def px4_alive() -> bool:
    """Probe from the Mac: is PX4 streaming telemetry? (passive on 14550)"""
    alive, _, _, _ = probe_passive(timeout=3.0)
    return alive


def wait_ready(timeout=120.0) -> bool:
    """Wait until PX4 is broadcasting telemetry on 14550; keep GUI alive."""
    t0 = time.time()
    next_gui = 0.0
    while time.time() - t0 < timeout:
        alive, _, _, _ = probe_passive(timeout=2.0)
        if alive:
            try:
                ensure_gzclient()
            except Exception:
                pass
            return True
        # While waiting for PX4, try to bring up gzclient once gzserver exists.
        if time.time() >= next_gui:
            try:
                ensure_gzclient()
            except Exception:
                pass
            next_gui = time.time() + 4.0
        time.sleep(0.4)
    return False


if __name__ == "__main__":
    import sys
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action == "start":
        print(start_sitl())
        print("ready:", wait_ready())
    elif action == "stop":
        print(stop_sitl())
    else:
        print("px4_alive:", px4_alive())
