"""Live twin bridge: stream PX4 pose to the dashboard after recording stops.

Used during the post-run land / disarm / home-reset so the digital twin keeps
following the vehicle (the CSV recorder has already closed its 14550 socket).
Does NOT write any dataset files.

PoseKeepalive + handoff_phys_to_twin fill the brief phys→twin socket gap so the
DT never freezes mid-air at Home WP (previously looked like a reconnect glitch).
"""

from __future__ import annotations

import math
import socket
import threading
import time
from typing import Callable, Optional

from pymavlink import mavutil

import config as C


class PoseKeepalive:
    """Re-emit last known vehicle pose at LIVE_EMIT_HZ while sockets swap."""

    def __init__(self, on_sample: Callable[[dict], None], t0: float):
        self._on = on_sample
        self._t0 = t0
        self._stop = threading.Event()
        self._thr: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thr and self._thr.is_alive():
            return
        self._stop.clear()
        self._thr = threading.Thread(target=self._run, name="pose-keepalive",
                                     daemon=True)
        self._thr.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thr:
            self._thr.join(timeout=1.0)
            self._thr = None

    def _run(self) -> None:
        period = 1.0 / max(20.0, float(getattr(C, "LIVE_EMIT_HZ", 60)))
        while not self._stop.is_set():
            try:
                from mav_common import vehicle_snapshot
                snap = vehicle_snapshot()
            except Exception:
                snap = {}
            if snap and snap.get("x") is not None and snap.get("z") is not None:
                payload = {
                    "t_rel": round(time.time() - self._t0, 3),
                    "phase_hint": "handoff",
                    "x": snap.get("x"),
                    "y": snap.get("y"),
                    "z": snap.get("z"),
                    "vx": snap.get("vx"),
                    "vy": snap.get("vy"),
                    "vz": snap.get("vz"),
                    "armed": snap.get("armed"),
                    "custom_mode": snap.get("custom_mode"),
                }
                try:
                    self._on(payload)
                except Exception:
                    pass
            self._stop.wait(period)


def handoff_phys_to_twin(
    phys,
    on_sample: Callable[[dict], None] | None,
    t0: float,
    *,
    bind_retries: int = 30,
    bind_pause_s: float = 0.04,
) -> Optional["TwinBridge"]:
    """Seamless phys → twin handoff so DT pose never goes stale at Home WP.

    1) keepalive last pose
    2) stop PhysicalRecorder (release :14550)
    3) bind TwinBridge with retries
    4) stop keepalive once twin is emitting
    """
    if on_sample is None:
        if phys is not None:
            try:
                phys.stop()
            except Exception:
                pass
        return None

    keep = PoseKeepalive(on_sample, t0)
    keep.start()
    twin: Optional[TwinBridge] = None
    try:
        if phys is not None:
            try:
                phys.stop()
            except Exception:
                pass
            # Brief settle so the OS fully releases the UDP bind.
            time.sleep(0.05)
        twin = TwinBridge(on_sample=on_sample, t0=t0)
        for _ in range(max(1, bind_retries)):
            if twin.start():
                # Seeded pose emits immediately; give first PX4 packet a beat.
                time.sleep(0.06)
                keep.stop()
                return twin
            time.sleep(bind_pause_s)
        twin = None
        return None
    finally:
        keep.stop()


class TwinBridge:
    """Passive 14550 telemetry fan-out for the digital twin only."""

    def __init__(self, on_sample, t0: float | None = None):
        self._on_sample = on_sample
        self._t0 = t0 or time.time()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._conn = None
        self._have_pose = False

    def start(self) -> bool:
        if self._on_sample is None:
            return False
        if self._thread is not None:
            return True
        try:
            # Probe/reuse so quick phys→twin swaps don't fail on EADDRINUSE.
            try:
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except OSError:
                        pass
                probe.bind(("0.0.0.0", int(C.GCS_PORT)))
                probe.close()
            except OSError:
                pass
            self._conn = mavutil.mavlink_connection(f"udpin:0.0.0.0:{C.GCS_PORT}")
            try:
                raw = getattr(self._conn, "port", None)
                if raw is not None and hasattr(raw, "setsockopt"):
                    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass
        except OSError:
            self._conn = None
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _seed_from_vehicle(self, state: dict) -> None:
        """Reuse last known recorder pose so the DT does not snap to origin."""
        try:
            from mav_common import vehicle_snapshot
            snap = vehicle_snapshot()
            for k in ("x", "y", "z", "vx", "vy", "vz", "armed", "custom_mode"):
                v = snap.get(k)
                if v is None:
                    continue
                if isinstance(v, float) and v != v:
                    continue
                state[k] = float(v) if k != "armed" else float(bool(v))
            if state["x"] == state["x"] and state["z"] == state["z"]:
                self._have_pose = True
        except Exception:
            pass

    def _boost_rates(self) -> None:
        """Re-request high-rate pose after recorder release (PX4 may drop rates)."""
        if self._conn is None:
            return
        interval_us = int(1_000_000 / max(float(getattr(C, "TWIN_STREAM_HZ", 30)), 1))
        for mid in (
            mavutil.mavlink.MAVLINK_MSG_ID_LOCAL_POSITION_NED,
            mavutil.mavlink.MAVLINK_MSG_ID_ATTITUDE,
            mavutil.mavlink.MAVLINK_MSG_ID_GLOBAL_POSITION_INT,
            mavutil.mavlink.MAVLINK_MSG_ID_HEARTBEAT,
        ):
            try:
                self._conn.mav.command_long_send(
                    C.PX4_SYSID, C.PX4_COMPID,
                    mavutil.mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, 0,
                    mid, interval_us, 0, 0, 0, 0, 0)
            except Exception:
                pass
        try:
            self._conn.mav.request_data_stream_send(
                C.PX4_SYSID, C.PX4_COMPID,
                mavutil.mavlink.MAV_DATA_STREAM_ALL,
                int(getattr(C, "STREAM_REQUEST_HZ", 20)), 1)
        except Exception:
            pass

    def _loop(self):
        state = {
            "x": math.nan, "y": math.nan, "z": math.nan,
            "vx": math.nan, "vy": math.nan, "vz": math.nan,
            "roll": math.nan, "pitch": math.nan, "yaw": math.nan,
            "armed": 0.0, "custom_mode": math.nan,
            "batt_remaining": math.nan, "batt_voltage": math.nan,
            "rel_alt": math.nan,
        }
        self._seed_from_vehicle(state)
        self._boost_rates()
        live_dt = 1.0 / max(20.0, float(C.LIVE_EMIT_HZ))  # denser during land
        next_emit = time.time()
        boosted = False
        while not self._stop.is_set():
            try:
                m = self._conn.recv_match(blocking=True, timeout=0.05)
            except Exception:
                break
            if m is not None and m.get_srcSystem() == C.PX4_SYSID:
                if not boosted:
                    self._boost_rates()
                    boosted = True
                t = m.get_type()
                if t == "LOCAL_POSITION_NED":
                    state["x"], state["y"], state["z"] = float(m.x), float(m.y), float(m.z)
                    state["vx"], state["vy"], state["vz"] = float(m.vx), float(m.vy), float(m.vz)
                    self._have_pose = True
                elif t == "ATTITUDE":
                    state["roll"], state["pitch"], state["yaw"] = (
                        float(m.roll), float(m.pitch), float(m.yaw))
                elif t == "HEARTBEAT":
                    state["armed"] = float(
                        bool(m.base_mode
                             & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED))
                    state["custom_mode"] = float(m.custom_mode)
                elif t == "GLOBAL_POSITION_INT":
                    state["rel_alt"] = float(m.relative_alt) / 1000.0
                elif t == "SYS_STATUS":
                    state["batt_remaining"] = float(m.battery_remaining)
                    state["batt_voltage"] = float(m.voltage_battery) / 1000.0

            now = time.time()
            if now < next_emit:
                continue
            next_emit = now + live_dt
            # Never emit NaN pose — that made the DT jump to ground (alt=0).
            if not self._have_pose:
                continue
            self._emit(now, state)

    def _emit(self, now: float, state: dict):
        def clean(v):
            return None if (isinstance(v, float) and math.isnan(v)) else v

        vx, vy, vz = state["vx"], state["vy"], state["vz"]
        speed = horiz = tilt = None
        if not any(isinstance(v, float) and math.isnan(v) for v in (vx, vy, vz)):
            speed = math.sqrt(vx * vx + vy * vy + vz * vz)
            horiz = math.sqrt(vx * vx + vy * vy)
        roll, pitch = state["roll"], state["pitch"]
        if not (math.isnan(roll) or math.isnan(pitch)):
            tilt = math.sqrt(roll * roll + pitch * pitch)

        payload = {
            "t_rel": round(now - self._t0, 3),
            "phase_hint": "landing",
            "x": clean(state["x"]), "y": clean(state["y"]), "z": clean(state["z"]),
            "vx": clean(state["vx"]), "vy": clean(state["vy"]), "vz": clean(state["vz"]),
            "roll": clean(state["roll"]), "pitch": clean(state["pitch"]),
            "yaw": clean(state["yaw"]),
            "armed": int(state["armed"]) if state["armed"] == state["armed"] else 0,
            "custom_mode": clean(state["custom_mode"]),
            "rel_alt": clean(state["rel_alt"]),
            "batt_remaining": clean(state["batt_remaining"]),
            "batt_voltage": clean(state["batt_voltage"]),
            "speed": clean(speed) if speed is not None else None,
            "horiz_speed": clean(horiz) if horiz is not None else None,
            "vertical_speed": clean(vz),
            "tilt_mag": clean(tilt) if tilt is not None else None,
        }
        try:
            from mav_common import update_vehicle_state
            update_vehicle_state(payload)
        except Exception:
            pass
        try:
            self._on_sample(payload)
        except Exception:
            pass
