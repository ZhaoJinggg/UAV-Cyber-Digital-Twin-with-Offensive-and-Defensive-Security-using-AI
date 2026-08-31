"""Shared MAVLink helpers: a GCS link with heartbeat thread + PX4 commands.

Used by both the benign controller and the attack scripts. All of this runs on
the Mac and talks to PX4 SITL over UDP.

Command path (critical): ``udpout`` to PX4's broadcast GCS port **14550**.
That instance is pinned to the Mac (``-t 192.168.123.123``) and reliably
accepts arm / OFFBOARD / setpoints. The legacy 18570 peer link is sticky and
often goes silent after reconnects — which left the digital twin frozen on the
ground even while 14550 telemetry looked "live".

Telemetry feedback (altitude / armed) prefers 18570 when available, then falls
back to the latest LOCAL_POSITION published by the physical recorder / twin
bridge into ``update_vehicle_state``.
"""

from __future__ import annotations

import threading
import time

from pymavlink import mavutil

import config as C

# Latest vehicle pose/armed from the 14550 recorder (filled during runs).
_VEHICLE = {
    "t": 0.0,
    "x": None,
    "y": None,
    "z": None,       # NED z (negative up)
    "armed": None,
    "custom_mode": None,
    "lat": None,     # deg
    "lon": None,     # deg
    "alt_msl": None, # m
    "vx": None,      # NED m/s if available
    "vy": None,
    "vz": None,
}
_VEHICLE_LOCK = threading.Lock()

# Dashboard Stop / orchestrator abort — attack loops poll this.
_RUN_ABORT = threading.Event()


def request_run_abort() -> None:
    _RUN_ABORT.set()


def clear_run_abort() -> None:
    _RUN_ABORT.clear()


def run_abort_requested() -> bool:
    return _RUN_ABORT.is_set()


def update_vehicle_state(sample: dict) -> None:
    """Called by PhysicalRecorder / TwinBridge live emits."""
    with _VEHICLE_LOCK:
        _VEHICLE["t"] = time.time()
        for key in ("x", "y", "z", "armed", "custom_mode",
                    "lat", "lon", "alt_msl", "vx", "vy", "vz"):
            v = sample.get(key)
            if v is None:
                continue
            if isinstance(v, float) and v != v:  # NaN
                continue
            _VEHICLE[key] = v


def vehicle_geo() -> dict:
    """Latest lat/lon/alt/vel for spoof seeding (empty fields may be None)."""
    with _VEHICLE_LOCK:
        return {
            "lat": _VEHICLE["lat"],
            "lon": _VEHICLE["lon"],
            "alt_msl": _VEHICLE["alt_msl"],
            "x": _VEHICLE["x"],
            "y": _VEHICLE["y"],
            "z": _VEHICLE["z"],
            "vx": _VEHICLE["vx"],
            "vy": _VEHICLE["vy"],
            "vz": _VEHICLE["vz"],
            "t": _VEHICLE["t"],
        }


def vehicle_snapshot() -> dict:
    """Latest pose for DT keepalive during phys→twin socket handoff."""
    with _VEHICLE_LOCK:
        return {
            "x": _VEHICLE["x"],
            "y": _VEHICLE["y"],
            "z": _VEHICLE["z"],
            "vx": _VEHICLE["vx"],
            "vy": _VEHICLE["vy"],
            "vz": _VEHICLE["vz"],
            "armed": _VEHICLE["armed"],
            "custom_mode": _VEHICLE["custom_mode"],
            "lat": _VEHICLE["lat"],
            "lon": _VEHICLE["lon"],
            "alt_msl": _VEHICLE["alt_msl"],
            "t": _VEHICLE["t"],
        }

def vehicle_altitude() -> float | None:
    with _VEHICLE_LOCK:
        z = _VEHICLE["z"]
        return None if z is None else -float(z)


def vehicle_armed() -> bool | None:
    with _VEHICLE_LOCK:
        a = _VEHICLE["armed"]
        if a is None:
            return None
        return bool(a)


def _tx_endpoint(host: str | None, port: int | None) -> tuple[str, int]:
    """Resolve TX host/port — prefer local proactive gateway when enabled."""
    if host is not None or port is not None:
        return (host or C.UAV_HOST), int(port or C.GCS_TX_PORT)
    if getattr(C, "MAV_GATEWAY_ENABLED", True):
        try:
            from ids.mav_gateway import ensure_gateway_started
            ensure_gateway_started()
        except Exception:
            pass
        return (getattr(C, "MAV_GATEWAY_HOST", "127.0.0.1"),
                int(getattr(C, "MAV_GATEWAY_PORT", 19550)))
    return C.UAV_HOST, int(C.GCS_TX_PORT)


class MavLink:
    """Command link to PX4 (tx via proactive gateway → 14550) + optional rx."""

    def __init__(self, sysid: int, port: int | None = None, host: str | None = None,
                 spoof_gcs: bool = True):
        self.host, self.port = _tx_endpoint(host, port)
        self.sysid = sysid
        self._spoof = spoof_gcs
        self.conn = mavutil.mavlink_connection(
            f"udpout:{self.host}:{self.port}",
            source_system=sysid, source_component=190,
        )
        # Optional feedback on the classic API port (may be sticky / silent).
        self.rx = None
        try:
            self.rx = mavutil.mavlink_connection(
                f"udpout:{self.host}:{C.GCS_API_PORT}",
                source_system=sysid, source_component=191,
            )
        except Exception:
            self.rx = None
        self._stop = threading.Event()
        self._hb = threading.Thread(target=self._hb_loop, daemon=True)
        self._hb.start()

    def _hb_loop(self):
        while not self._stop.is_set():
            try:
                self.conn.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_GCS,
                    mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            except Exception:
                pass
            if self.rx is not None:
                try:
                    self.rx.mav.heartbeat_send(
                        mavutil.mavlink.MAV_TYPE_GCS,
                        mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
                except Exception:
                    pass
            time.sleep(0.25)

    def reclaim(self):
        """Push heartbeats on both sockets so PX4 hears this controller."""
        for _ in range(6):
            try:
                self.conn.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_GCS,
                    mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            except Exception:
                pass
            time.sleep(0.04)

    def reopen(self):
        try:
            self.conn.close()
        except Exception:
            pass
        if self.rx is not None:
            try:
                self.rx.close()
            except Exception:
                pass
        self.conn = mavutil.mavlink_connection(
            f"udpout:{self.host}:{self.port}",
            source_system=self.sysid, source_component=190,
        )
        try:
            self.rx = mavutil.mavlink_connection(
                f"udpout:{self.host}:{C.GCS_API_PORT}",
                source_system=self.sysid, source_component=191,
            )
        except Exception:
            self.rx = None
        self.reclaim()

    def close(self):
        self._stop.set()
        try:
            self.conn.close()
        except Exception:
            pass
        if self.rx is not None:
            try:
                self.rx.close()
            except Exception:
                pass

    # ---- link bring-up ----
    def wait_heartbeat(self, timeout=15.0):
        """Prefer API-port HB; else accept fresh 14550 recorder state."""
        self.reclaim()
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.rx is not None:
                m = self.rx.recv_match(type="HEARTBEAT", blocking=True, timeout=0.35)
                if m and m.get_srcSystem() == C.PX4_SYSID:
                    return m
            # Recorder / twin live state is enough to consider the link up
            with _VEHICLE_LOCK:
                fresh = (time.time() - _VEHICLE["t"]) < 1.5
                if fresh and _VEHICLE["armed"] is not None:
                    return True
            # Passive listen only when nothing else holds 14550
            try:
                c = mavutil.mavlink_connection(f"udpin:0.0.0.0:{C.GCS_PORT}",
                                               source_system=self.sysid)
            except OSError:
                c = None
            if c is not None:
                try:
                    m = c.recv_match(type="HEARTBEAT", blocking=True, timeout=0.4)
                    if m and m.get_srcSystem() == C.PX4_SYSID:
                        return m
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass
            self.reclaim()
        return None

    def ensure_link(self, timeout: float = 6.0) -> bool:
        if self.wait_heartbeat(timeout=timeout * 0.6):
            return True
        self.reopen()
        return self.wait_heartbeat(timeout=timeout * 0.4) is not None

    def request_streams(self, rate_hz=C.STREAM_REQUEST_HZ):
        self.conn.mav.request_data_stream_send(
            C.PX4_SYSID, C.PX4_COMPID,
            mavutil.mavlink.MAV_DATA_STREAM_ALL, int(rate_hz), 1)

    # ---- commands (always via 14550 tx) ----
    def _cmd(self, command, *params):
        p = list(params) + [0] * (7 - len(params))
        self.conn.mav.command_long_send(
            C.PX4_SYSID, C.PX4_COMPID, command, 0, *p[:7])

    def set_mode(self, name: str):
        main, sub = C.PX4_MODES[name]
        self._cmd(mavutil.mavlink.MAV_CMD_DO_SET_MODE,
                  mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, main, sub)

    def set_message_interval(self, msgid: int, hz: float):
        interval_us = int(1e6 / hz) if hz > 0 else -1
        self._cmd(mavutil.mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, msgid, interval_us)

    def arm(self, force=True):
        self._cmd(mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 1,
                  C.ARM_FORCE_MAGIC if force else 0)

    def disarm(self, force=True):
        self._cmd(mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0,
                  C.ARM_FORCE_MAGIC if force else 0)

    def set_param(self, name: str, value: float) -> None:
        """Best-effort PARAM_SET (SITL prep / recovery)."""
        try:
            self.conn.mav.param_set_send(
                C.PX4_SYSID, C.PX4_COMPID, name.encode("ascii"), float(value),
                mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        except Exception:
            pass

    def prepare_sitl_for_arm(self) -> None:
        """Clear common SITL arm blockers (mag health / RC-loss failsafe).

        Warm Gazebo sessions often accumulate a Compass-0 fault that denies arm
        even with force-arm. These overrides match a healthy lab baseline.
        """
        for name, value in (
            ("SYS_HAS_MAG", 0),
            ("EKF2_MAG_TYPE", 5),          # None — don't require mag for EKF
            ("CAL_MAG0_PRIO", 0),
            ("CAL_MAG1_PRIO", 0),
            ("CAL_MAG2_PRIO", 0),
            ("COM_ARM_MAG_ANG", -1),
            ("COM_ARM_MAG_STR", -1),
            ("COM_ARM_WO_GPS", 1),
            ("COM_ARM_CHK_ESCS", 0),
            ("COM_RC_IN_MODE", 4),         # RC unused / stick fallback off
            ("NAV_RCL_ACT", 0),            # ignore RC loss
            ("COM_RCL_EXCEPT", 4),         # exempt OFFBOARD from RC failsafe
            ("CBRK_IO_SAFETY", 22027),
        ):
            self.set_param(name, value)
            time.sleep(0.04)
        # Give PX4 a moment to recompute health after param writes.
        time.sleep(0.6)

    def takeoff(self, alt=2.5):
        self._cmd(mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, alt)

    def land(self):
        self._cmd(mavutil.mavlink.MAV_CMD_NAV_LAND)

    def set_position_target(self, x: float, y: float, z: float):
        """Send an OFFBOARD local-NED position setpoint (z is negative-up)."""
        self.conn.mav.set_position_target_local_ned_send(
            0, C.PX4_SYSID, C.PX4_COMPID,
            mavutil.mavlink.MAV_FRAME_LOCAL_NED,
            0b110111111000,          # position only (ignore vel/accel/yaw)
            x, y, z, 0, 0, 0, 0, 0, 0, 0, 0)

    def read(self, timeout=0.2):
        if self.rx is not None:
            return self.rx.recv_match(blocking=True, timeout=timeout)
        return None

    def altitude(self, timeout=1.0):
        # Prefer live recorder state (always current during a dashboard run)
        alt = vehicle_altitude()
        if alt is not None:
            return alt
        if self.rx is not None:
            m = self.rx.recv_match(type="LOCAL_POSITION_NED",
                                   blocking=True, timeout=timeout)
            if m is not None:
                return -m.z
        return None

    def is_armed(self, timeout: float = 0.4) -> bool | None:
        a = vehicle_armed()
        if a is True:
            return True
        # Prefer a fresh HEARTBEAT when the recorder still says disarmed —
        # otherwise wait_armed can miss a successful arm for up to ~1s+.
        if self.rx is not None:
            m = self.rx.recv_match(type="HEARTBEAT", blocking=True, timeout=timeout)
            if m is not None and m.get_srcSystem() == C.PX4_SYSID:
                return bool(m.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
        return a

    def wait_armed(self, timeout: float = 5.0) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            a = self.is_armed(timeout=0.35)
            if a is True:
                return True
            # Climb starting is also proof of arm for OFFBOARD SITL.
            alt = vehicle_altitude()
            if alt is not None and alt > 0.6:
                return True
            self.reclaim()
            try:
                self.set_mode("OFFBOARD")
                self.arm(force=True)
            except Exception:
                pass
            time.sleep(0.1)
        return False


def ping_command_link(timeout: float = 4.0) -> bool:
    """True if telemetry on 14550 is alive (commands use the same PX4 instance)."""
    # Prefer passive 14550 — the command tx path is the same mavlink instance.
    try:
        import ssh_control as ssh
        alive, _, _, _ = ssh.probe_passive(timeout=min(timeout, 3.0))
        if alive:
            return True
    except Exception:
        pass
    m = MavLink(sysid=C.CONTROLLER_SYSID)
    try:
        return m.ensure_link(timeout=timeout)
    finally:
        m.close()


# Optional live log sinks (e.g. the dashboard). Each is called as sink(tag, msg).
LOG_SINKS: list = []


def add_log_sink(fn):
    if fn not in LOG_SINKS:
        LOG_SINKS.append(fn)


def remove_log_sink(fn):
    if fn in LOG_SINKS:
        LOG_SINKS.remove(fn)


def log(tag: str, msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)
    for sink in list(LOG_SINKS):
        try:
            sink(tag, msg)
        except Exception:
            pass
