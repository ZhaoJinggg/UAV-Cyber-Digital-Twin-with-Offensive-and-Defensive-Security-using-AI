"""Shared multi-waypoint mission pilot (benign + every attack scenario).

All scenarios fly the same ``config.MISSION_PLAN``. Attacks pause the plan at
``ATTACK_AFTER_WP``, inject, then resume the remaining waypoints so pre/post
behaviour is comparable on an identical route.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

import config as C
from mav_common import MavLink, log


class BenignPilot:
    """OFFBOARD mission runner over the shared multi-point plan."""

    def __init__(self, on_wp: Optional[Callable] = None):
        self.mav = MavLink(sysid=C.CONTROLLER_SYSID)
        self._target = [0.0, 0.0, -C.CRUISE_ALT]
        self._stream = False
        self._stop = threading.Event()
        self._sp_thread: threading.Thread | None = None
        self._mission_thread: threading.Thread | None = None
        self._connected = False
        self.on_wp = on_wp  # optional callback(wp_idx, wp_dict, phase_hint)
        # mission progression
        self.wp_idx = -1
        self.wp_id = ""
        self.mission_done = threading.Event()
        self._gate = threading.Event()       # set when next attack gate WP completed
        self._gate_hit = False               # True only for a real mid-mission gate
        self._last_gate: dict | None = None
        self._resume = threading.Event()     # cleared while frozen for attack
        self._resume.set()
        self._freeze = False
        self._attack_gate = int(C.ATTACK_AFTER_WP)
        self._pause_for_attack = False       # True for attack scenarios
        # Multi-attack tour: [{after_wp, attack, wp_id}, ...] sorted by after_wp
        self._schedule: list[dict] = []
        self._schedule_i = 0
        self.pending_attack: str | None = None
        self.on_gate: Optional[Callable] = None  # callback(entry_dict)
        self.arm_failed = False
        # When True (Defense ON + model): announce gate + continue immediately.
        self._pass_through_gates = False
        # Unprotected GPS spoof: integrate NED bias into setpoints so Gazebo
        # shows navigation corruption when EKF alone would reject the spoof.
        self._bias_n = 0.0
        self._bias_e = 0.0
        self._bias_rate_n = 0.0  # m/s
        self._bias_rate_e = 0.0
        self._bias_lock = threading.Lock()
        self._nominal_target = [0.0, 0.0, -C.CRUISE_ALT]

    # ---------------------------------------------------------------- link ---
    def connect(self, settle=0.3) -> bool:
        ok = self.mav.ensure_link(timeout=5.0)
        if not ok:
            log("mission", "ERROR: no heartbeat on command link (18570) — "
                           "cannot arm; DT will stay on the ground")
            self._connected = False
            return False
        if settle > 0:
            time.sleep(settle)
        self._connected = True
        return True

    def close(self):
        self._stop.set()
        self._freeze = False
        self._resume.set()
        self._stream = False
        try:
            self.mav.close()
        except Exception:
            pass

    # ---------------------------------------------------- OFFBOARD internals -
    def _setpoint_loop(self):
        last = time.time()
        while not self._stop.is_set():
            now = time.time()
            dt = max(0.0, min(0.2, now - last))
            last = now
            with self._bias_lock:
                if self._bias_rate_n or self._bias_rate_e:
                    self._bias_n += self._bias_rate_n * dt
                    self._bias_e += self._bias_rate_e * dt
                bn, be = self._bias_n, self._bias_e
            if self._stream and not self._freeze:
                try:
                    x = float(self._nominal_target[0]) + bn
                    y = float(self._nominal_target[1]) + be
                    z = float(self._nominal_target[2])
                    self._target = [x, y, z]
                    self.mav.set_position_target(x, y, z)
                except Exception:
                    pass
            time.sleep(0.05)

    def set_nav_bias_rate(self, north_mps: float = 0.0, east_mps: float = 0.0):
        """Start integrating a horizontal nav bias (unprotected GPS effect)."""
        with self._bias_lock:
            self._bias_rate_n = float(north_mps)
            self._bias_rate_e = float(east_mps)
        log("mission", f"nav bias rate N={north_mps:.2f} E={east_mps:.2f} m/s")

    def clear_nav_bias(self, reset_offset: bool = False):
        with self._bias_lock:
            self._bias_rate_n = 0.0
            self._bias_rate_e = 0.0
            if reset_offset:
                self._bias_n = 0.0
                self._bias_e = 0.0
        log("mission", "nav bias cleared")

    def _ensure_setpoint_thread(self):
        if self._sp_thread is None or not self._sp_thread.is_alive():
            self._sp_thread = threading.Thread(target=self._setpoint_loop,
                                               daemon=True)
            self._sp_thread.start()

    def _wait_altitude(self, target_up: float, timeout: float = 4.0,
                       ratio: float = 0.55) -> bool:
        need = max(0.8, target_up * ratio)
        t0 = time.time()
        while time.time() - t0 < timeout and not self._stop.is_set():
            alt = self.mav.altitude(timeout=0.25)
            if alt is not None and alt >= need:
                return True
            time.sleep(0.1)
        return False

    def engage_offboard(self, alt: float | None = None) -> bool:
        alt = alt if alt is not None else float(C.MISSION_PLAN[0]["z"])
        self._nominal_target = [0.0, 0.0, -alt]
        self._target = list(self._nominal_target)
        self._freeze = False
        self._stream = True
        self._ensure_setpoint_thread()
        try:
            self.mav.request_streams(rate_hz=20)
            self.mav.set_message_interval(32, 20)  # LOCAL_POSITION_NED
            self.mav.set_message_interval(30, 20)  # ATTITUDE
        except Exception:
            pass
        time.sleep(0.5)
        log("mission", f"OFFBOARD engage + arm, climb to {alt:.1f} m")
        armed = False
        for attempt in range(1, 4):
            self.mav.reclaim()
            self.mav.set_mode("OFFBOARD")
            time.sleep(0.12)
            self.mav.arm(force=True)
            armed = self.mav.wait_armed(timeout=2.2)
            if armed:
                break
            log("mission", f"arm attempt {attempt}/3 failed — retrying")
            self.mav.reopen()
            time.sleep(0.3)
        if not armed:
            log("mission", "ERROR: vehicle did not arm — twin will not move")
            return False
        ok = self._wait_altitude(alt, timeout=5.0, ratio=0.45)
        log("mission", f"climb {'reached' if ok else 'timeout (still streaming)'}")
        return True

    def goto(self, x: float, y: float, z_up: float, dwell: float):
        self._nominal_target = [x, y, -z_up]
        self._target = list(self._nominal_target)
        t0 = time.time()
        while time.time() - t0 < dwell and not self._stop.is_set():
            if self._freeze:
                break
            time.sleep(0.1)

    def land(self):
        log("mission", "AUTO.LAND (smooth descent)")
        self._stream = False
        self._freeze = True
        try:
            self.mav.set_mode("AUTO_LAND")
            time.sleep(0.2)
            self.mav.set_mode("AUTO_LAND")
            self.mav.land()
        except Exception:
            pass
        # Follow altitude down so TwinBridge / DT see a continuous descent
        t0 = time.time()
        while time.time() - t0 < 16.0 and not self._stop.is_set():
            alt = self.mav.altitude(timeout=0.3)
            if alt is not None and alt < 0.4:
                break
            if int(time.time() - t0) % 2 == 0:
                try:
                    self.mav.set_mode("AUTO_LAND")
                except Exception:
                    pass
            time.sleep(0.2)

    # ---------------------------------------------------- mission execution --
    def _emit_wp(self, idx: int, wp: dict, hint: str):
        self.wp_idx = idx
        self.wp_id = wp["id"]
        log("mission", f"{hint} {wp['id']}  "
                       f"(N={wp['x']:.0f} E={wp['y']:.0f} alt={wp['z']:.0f})")
        if self.on_wp:
            try:
                self.on_wp(idx, wp, hint)
            except Exception:
                pass

    def _run_plan(self, land_at_end: bool = True):
        """Fly MISSION_PLAN from start; optionally pause at the attack gate."""
        try:
            if not self.connect(settle=0.2):
                return
            if not self.engage_offboard():
                return
            for i, wp in enumerate(C.MISSION_PLAN):
                if self._stop.is_set():
                    break
                self._emit_wp(i, wp, "→")
                self.goto(float(wp["x"]), float(wp["y"]), float(wp["z"]),
                          float(wp["dwell_s"]))
                if self._stop.is_set():
                    break
                # Multi-attack schedule gates (preferred when present)
                hit = None
                if self._schedule and self._schedule_i < len(self._schedule):
                    nxt = self._schedule[self._schedule_i]
                    if int(nxt["after_wp"]) == i:
                        hit = nxt
                elif self._pause_for_attack and i == self._attack_gate:
                    hit = {"after_wp": i, "wp_id": wp["id"],
                           "attack": "scheduled"}

                if hit is not None:
                    self.pending_attack = hit.get("attack")
                    self._last_gate = dict(hit)
                    self._gate_hit = True
                    if self.on_gate:
                        try:
                            self.on_gate(hit)
                        except Exception:
                            pass
                    self._gate.set()
                    if self._pass_through_gates:
                        # Defended smooth flight: announce gate and keep flying.
                        # Leave _gate_hit set until orch consume_attack_gate().
                        log("mission", f"attack gate AFTER {wp['id']} (idx={i}) — "
                                       f"pass-through · {self.pending_attack}")
                        if self._schedule:
                            self._schedule_i += 1
                        continue
                    log("mission", f"attack gate AFTER {wp['id']} (idx={i}) — "
                                   f"holding for {self.pending_attack}")
                    self._resume.clear()
                    # Capture mode: wait until orch resumes after the attack window.
                    while not self._resume.is_set() and not self._stop.is_set():
                        time.sleep(0.05)
                    if self._stop.is_set():
                        break
                    log("mission", "resuming shared plan after attack")
                    self._freeze = False
                    self._stream = True
                    self.mav.reclaim()
                    self._ensure_setpoint_thread()
                    time.sleep(0.4)
                    try:
                        self.mav.set_mode("OFFBOARD")
                        time.sleep(0.1)
                        self.mav.arm(force=True)
                        self.mav.wait_armed(timeout=2.0)
                    except Exception:
                        pass
                    if self._schedule:
                        self._schedule_i += 1
                    # gate already cleared by resume_after_attack()
            if land_at_end and not self._stop.is_set():
                self.land()
                time.sleep(1.0)
        finally:
            self.mission_done.set()
            # Wake waiters so they can observe mission_done — but do NOT mark
            # a real gate hit (that previously fired attacks at takeoff).
            self._gate.set()

    def start_shared_mission(self, pause_for_attack: bool = False,
                             land_at_end: bool = True,
                             schedule: list | None = None,
                             pass_through_gates: bool = False):
        """Start the shared plan in a background thread.

        ``pass_through_gates=True`` (Defense ON): reach attack WPs and continue
        at normal dwell — no extra wait for the attack window.
        """
        self._pause_for_attack = pause_for_attack
        self._pass_through_gates = bool(pass_through_gates)
        self._schedule = list(schedule or [])
        self._schedule_i = 0
        self.pending_attack = None
        self._last_gate = None
        self._gate_hit = False
        self._stop.clear()
        self.mission_done.clear()
        self._gate.clear()
        self._resume.set()
        self._freeze = False
        self._mission_thread = threading.Thread(
            target=self._run_plan, args=(land_at_end,), daemon=True)
        self._mission_thread.start()

    def start_multi_attack_tour(self, schedule: list, land_at_end: bool = True,
                                 pass_through_gates: bool = False):
        """Fly plan and pause at every scheduled waypoint for a different attack."""
        self.start_shared_mission(pause_for_attack=False, land_at_end=land_at_end,
                                  schedule=schedule,
                                  pass_through_gates=pass_through_gates)

    def abort_now(self):
        """Interrupt mission / gate / dwell immediately (dashboard Stop)."""
        self._stop.set()
        self._freeze = False
        self._stream = False
        self._resume.set()
        self._gate_hit = False
        self._gate.set()
        self.mission_done.set()
        try:
            self.clear_nav_bias(reset_offset=False)
        except Exception:
            pass
        log("mission", "abort_now — mission interrupted")

    def wait_attack_gate(self, timeout: float = 180.0) -> bool:
        """Block until the next *real* mid-mission attack gate is reached.

        Returns False on timeout, stop, or mission end without a gate hit.
        (Previously ``finally: _gate.set()`` made attacks fire at takeoff.)
        """
        deadline = time.time() + max(0.1, float(timeout))
        while time.time() < deadline:
            if self._stop.is_set():
                return False
            if self._gate.wait(timeout=0.15):
                if self._stop.is_set():
                    return False
                if self._gate_hit:
                    return True
                # Spurious wake (mission ended / aborted) — not a real gate.
                if self.mission_done.is_set() or self._stop.is_set():
                    return False
                self._gate.clear()
                continue
        return False

    def freeze_for_attack(self, hard: bool = True):
        """Optionally stop setpoints so an undefended attack can take effect.

        ``hard=True`` (Defense OFF / capture runs): freeze OFFBOARD stream so
        the injector owns the vehicle — needed for labeled attack effects.

        ``hard=False`` (Defense ON): keep holding setpoints. Proactive gateway
        drops attacker traffic while the benign pilot keeps the plan stable.
        """
        if hard:
            self._freeze = True
            self._stream = False
            log("mission", "frozen for attack injection (undefended capture)")
        else:
            self._freeze = False
            self._stream = True
            self._ensure_setpoint_thread()
            log("mission", "attack window — keeping OFFBOARD hold (defended)")

    def consume_attack_gate(self):
        """Clear gate latch so the next wait_attack_gate() can block again."""
        self._gate.clear()
        self._gate_hit = False

    def resume_after_attack(self):
        """Release the gate so the pilot continues the remaining waypoints."""
        self.consume_attack_gate()
        self._freeze = False
        self._stream = True
        self._resume.set()
        log("mission", "resume signal sent — continuing shared plan")

    def wait_mission_done(self, timeout: float = 300.0) -> bool:
        return self.mission_done.wait(timeout=timeout)

    # --------- legacy / hover helpers kept for compatibility ---------------
    def freeze(self):
        self.freeze_for_attack()

    def resume_mission(self, duration: float = 0.0):
        """Legacy API: release attack gate (duration ignored — plan-driven)."""
        self.resume_after_attack()
        if duration > 0:
            time.sleep(min(duration, 1.0))

    def normal_mission(self, duration: float = 0.0):
        """Benign: fly the full shared plan (blocking)."""
        self.start_shared_mission(pause_for_attack=False, land_at_end=True)
        self.wait_mission_done(timeout=max(60.0, C.mission_duration_s() + 30))

    def run_async_warmup(self):
        """Attack pre-path: start shared plan and pause at the attack gate."""
        self.start_shared_mission(pause_for_attack=True, land_at_end=True)

    def takeoff(self, alt=3.0):
        self.engage_offboard(alt=alt)

    def hold(self, seconds: float):
        t0 = time.time()
        while time.time() - t0 < seconds and not self._stop.is_set():
            time.sleep(0.2)

    def loiter(self):
        try:
            self.mav.set_mode("AUTO_LOITER")
        except Exception:
            pass
