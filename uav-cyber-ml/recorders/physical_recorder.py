"""Physical-layer recorder.

Acts as a passive GCS on PX4's port 18570, requests all data streams, and logs
the vehicle's physical state. Produces two files per run:

  physical_raw.csv       one row per received MAVLink message (decoded fields)
  physical_processed.csv wide feature vector resampled at a fixed rate + derived

Runs on the Mac; controlled by the orchestrator via start()/stop().
"""

from __future__ import annotations

import csv
import math
import threading
import time
from pathlib import Path

from pymavlink import mavutil

import config as C

# msg_type -> list of (mavlink_attr, output_column)
FIELD_MAP = {
    "ATTITUDE": [("roll", "roll"), ("pitch", "pitch"), ("yaw", "yaw"),
                 ("rollspeed", "rollspeed"), ("pitchspeed", "pitchspeed"),
                 ("yawspeed", "yawspeed")],
    "LOCAL_POSITION_NED": [("x", "x"), ("y", "y"), ("z", "z"),
                           ("vx", "vx"), ("vy", "vy"), ("vz", "vz")],
    "GLOBAL_POSITION_INT": [("lat", "lat"), ("lon", "lon"), ("alt", "alt_msl"),
                            ("relative_alt", "rel_alt"), ("hdg", "hdg")],
    "VFR_HUD": [("airspeed", "airspeed"), ("groundspeed", "groundspeed"),
                ("heading", "heading"), ("throttle", "throttle"),
                ("alt", "vfr_alt"), ("climb", "climb")],
    "SYS_STATUS": [("voltage_battery", "batt_voltage"),
                   ("current_battery", "batt_current"),
                   ("battery_remaining", "batt_remaining"),
                   ("load", "cpu_load")],
    "SERVO_OUTPUT_RAW": [("servo1_raw", "m1"), ("servo2_raw", "m2"),
                         ("servo3_raw", "m3"), ("servo4_raw", "m4"),
                         ("servo5_raw", "m5"), ("servo6_raw", "m6"),
                         ("servo7_raw", "m7"), ("servo8_raw", "m8")],
    "ATTITUDE_TARGET": [("body_roll_rate", "tgt_rollrate"),
                        ("body_pitch_rate", "tgt_pitchrate"),
                        ("body_yaw_rate", "tgt_yawrate"),
                        ("thrust", "tgt_thrust")],
    "POSITION_TARGET_LOCAL_NED": [("x", "tgt_x"), ("y", "tgt_y"), ("z", "tgt_z"),
                                  ("vx", "tgt_vx"), ("vy", "tgt_vy"), ("vz", "tgt_vz")],
}

# All processed columns (state we track)
STATE_COLS = [col for fields in FIELD_MAP.values() for _, col in fields]
STATE_COLS += ["armed", "custom_mode", "base_mode", "system_status"]

RAW_HEADER = ["t_wall", "t_rel", "msg_type", "src_sys", "src_comp"] + STATE_COLS
DERIVED_COLS = ["speed", "horiz_speed", "vertical_speed", "tilt_mag",
                "motor_mean", "motor_spread", "pos_err_z"]
PROC_HEADER = ["t_wall", "t_rel"] + STATE_COLS + DERIVED_COLS


def _armed_from(base_mode: int) -> int:
    return int(bool(base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED))


class PhysicalRecorder:
    def __init__(self, run_dir: Path, on_sample=None):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.t0 = None
        self.n_msgs = 0
        self.bind_error = None
        self._conn = None
        # optional live callback: on_sample(dict) fired at PHYS_SAMPLE_HZ
        self._on_sample = on_sample
        self._raw_since = 0
        self._raw_by_type = {}

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        # Close the UDP socket promptly so TwinBridge can rebind :14550
        # without a multi-second DT freeze at Home WP.
        conn = getattr(self, "_conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._conn = None
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self):
        # Passive GCS sink: PX4 broadcasts its full telemetry stream to the Mac
        # on 14550. Listening here is reliable and does not disturb PX4's
        # single-remote routing on the command port (18570).
        try:
            conn = mavutil.mavlink_connection(f"udpin:0.0.0.0:{C.GCS_PORT}")
            self._conn = conn
        except OSError as exc:
            self.bind_error = (
                f"cannot bind UDP {C.GCS_PORT}: {exc}. "
                "Close QGroundControl or any stale recorder/orchestrator, then retry.")
            print(f"[physical_recorder] ERROR: {self.bind_error}", flush=True)
            return
        requested = False

        self.t0 = time.time()
        state = {c: math.nan for c in STATE_COLS}
        raw_f = open(self.run_dir / "physical_raw.csv", "w", newline="")
        proc_f = open(self.run_dir / "physical_processed.csv", "w", newline="")
        raw_w = csv.writer(raw_f)
        proc_w = csv.writer(proc_f)
        raw_w.writerow(RAW_HEADER)
        proc_w.writerow(PROC_HEADER)

        next_sample = self.t0
        sample_dt = 1.0 / C.PHYS_SAMPLE_HZ
        live_dt = 1.0 / C.LIVE_EMIT_HZ
        next_live = self.t0
        last_live = self.t0
        next_flush = self.t0 + 1.0     # flush to disk ~1 Hz for live dataset view

        while not self._stop.is_set():
            now = time.time()

            try:
                m = conn.recv_match(blocking=True, timeout=0.02)
            except OSError:
                # stop() closes the socket from another thread; that surfaces
                # here as EBADF. Expected during shutdown — exit quietly rather
                # than dumping a traceback at the end of every run.
                if self._stop.is_set():
                    break
                raise
            if m is not None and m.get_srcSystem() == C.PX4_SYSID:
                # once we know PX4's address, raise telemetry rates
                if not requested:
                    self._boost_rates(conn)
                    requested = True
                mtype = m.get_type()
                row = {c: math.nan for c in STATE_COLS}
                touched = False
                if mtype in FIELD_MAP:
                    for attr, col in FIELD_MAP[mtype]:
                        v = getattr(m, attr, None)
                        if v is not None:
                            state[col] = float(v)
                            row[col] = float(v)
                            touched = True
                if mtype == "HEARTBEAT":
                    state["armed"] = _armed_from(m.base_mode)
                    state["custom_mode"] = float(m.custom_mode)
                    state["base_mode"] = float(m.base_mode)
                    state["system_status"] = float(m.system_status)
                    row.update({"armed": state["armed"], "custom_mode": state["custom_mode"],
                                "base_mode": state["base_mode"],
                                "system_status": state["system_status"]})
                    touched = True
                if touched:
                    self.n_msgs += 1
                    self._raw_since += 1
                    self._raw_by_type[mtype] = self._raw_by_type.get(mtype, 0) + 1
                    raw_w.writerow([f"{now:.4f}", f"{now - self.t0:.4f}", mtype,
                                    m.get_srcSystem(), m.get_srcComponent()]
                                   + [row[c] for c in STATE_COLS])

            # fixed-rate processed sample -> dataset CSV (kept at PHYS_SAMPLE_HZ)
            if now >= next_sample:
                proc_w.writerow([f"{now:.4f}", f"{now - self.t0:.4f}"]
                                + [state[c] for c in STATE_COLS]
                                + self._derived(state))
                next_sample += sample_dt

            # high-rate live push -> twin/graphs, and shared vehicle state.
            # NOT gated on _on_sample: _emit_sample also publishes the shared
            # vehicle snapshot that MavLink.wait_heartbeat() falls back on when
            # PX4's command-port heartbeat is silent (it is, for a remote DT).
            # Gating this on the dashboard callback left CLI orchestrator runs
            # with no vehicle state at all, so arming failed with
            # "no heartbeat on command link" and the UAV never left the ground.
            if now >= next_live:
                self._emit_sample(now, state, max(now - last_live, 1e-3))
                last_live = now
                next_live = now + live_dt

            # periodically flush so the dashboard's dataset explorer can read
            # the CSVs while they are still being written (live plotting)
            if now >= next_flush:
                try:
                    raw_f.flush()
                    proc_f.flush()
                except Exception:
                    pass
                next_flush = now + 1.0

        raw_f.close()
        proc_f.close()
        try:
            conn.close()
        except Exception:
            pass
        if getattr(self, "_conn", None) is conn:
            self._conn = None

    def _boost_rates(self, conn):
        """Ask PX4 for high-rate telemetry so the twin looks truly live.

        The default GCS broadcast sends position at ~1 Hz; SET_MESSAGE_INTERVAL
        raises the twin-driving messages to TWIN_STREAM_HZ. Falls back to the
        legacy data-stream request too.
        """
        interval_us = int(1_000_000 / max(C.TWIN_STREAM_HZ, 1))
        msg_ids = [
            mavutil.mavlink.MAVLINK_MSG_ID_LOCAL_POSITION_NED,
            mavutil.mavlink.MAVLINK_MSG_ID_ATTITUDE,
            mavutil.mavlink.MAVLINK_MSG_ID_GLOBAL_POSITION_INT,
            mavutil.mavlink.MAVLINK_MSG_ID_ATTITUDE_TARGET,
            mavutil.mavlink.MAVLINK_MSG_ID_POSITION_TARGET_LOCAL_NED,
            mavutil.mavlink.MAVLINK_MSG_ID_SERVO_OUTPUT_RAW,
            mavutil.mavlink.MAVLINK_MSG_ID_VFR_HUD,
        ]
        for mid in msg_ids:
            try:
                conn.mav.command_long_send(
                    C.PX4_SYSID, C.PX4_COMPID,
                    mavutil.mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, 0,
                    mid, interval_us, 0, 0, 0, 0, 0)
            except Exception:
                pass
        try:
            conn.mav.request_data_stream_send(
                C.PX4_SYSID, C.PX4_COMPID,
                mavutil.mavlink.MAV_DATA_STREAM_ALL,
                int(C.STREAM_REQUEST_HZ), 1)
        except Exception:
            pass

    def _emit_sample(self, now: float, state: dict, elapsed: float):
        """Build a JSON-safe live sample dict and hand it to the callback."""
        def clean(v):
            return None if (isinstance(v, float) and math.isnan(v)) else v

        payload = {"t_rel": round(now - self.t0, 3)}
        for c in STATE_COLS:
            payload[c] = clean(state.get(c, math.nan))
        for c, v in zip(DERIVED_COLS, self._derived(state)):
            payload[c] = clean(v)
        payload["raw_since"] = self._raw_since
        payload["raw_rate"] = round(self._raw_since / elapsed, 1)
        payload["raw_by_type"] = dict(self._raw_by_type)
        self._raw_since = 0
        self._raw_by_type = {}
        try:
            from mav_common import update_vehicle_state
            update_vehicle_state(payload)
        except Exception:
            pass
        if self._on_sample is not None:
            try:
                self._on_sample(payload)
            except Exception:
                pass

    @staticmethod
    def _derived(s: dict) -> list:
        def g(k):
            v = s.get(k, math.nan)
            return v if isinstance(v, (int, float)) else math.nan

        vx, vy, vz = g("vx"), g("vy"), g("vz")
        speed = math.sqrt(sum(v * v for v in (vx, vy, vz) if not math.isnan(v))) \
            if not all(math.isnan(v) for v in (vx, vy, vz)) else math.nan
        horiz = math.sqrt(vx * vx + vy * vy) if not (math.isnan(vx) or math.isnan(vy)) else math.nan
        roll, pitch = g("roll"), g("pitch")
        tilt = math.sqrt(roll * roll + pitch * pitch) if not (math.isnan(roll) or math.isnan(pitch)) else math.nan
        motors = [g(f"m{i}") for i in range(1, 5)]
        motors = [x for x in motors if not math.isnan(x)]
        m_mean = sum(motors) / len(motors) if motors else math.nan
        m_spread = (max(motors) - min(motors)) if motors else math.nan
        z, tz = g("z"), g("tgt_z")
        pos_err_z = (tz - z) if not (math.isnan(z) or math.isnan(tz)) else math.nan
        return [speed, horiz, vz, tilt, m_mean, m_spread, pos_err_z]
