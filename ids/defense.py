"""Active UAV defense (IPS): PREVENT attacks when IDS alerts and Defense is ON.

Detection-only mode (Defense unchecked) never touches the vehicle.

When Defense is checked (default mode = ``prevent``):
  * short signature grace (so live training still sees the attack),
  * set abort so attack loops stop injecting,
  * reclaim control from the spoofed attacker sysid,
  * continuous OFFBOARD hold + re-arm / mode restore for ``DEFENSE_PREVENT_HOLD_S``,
  * re-engage if the attacker is still active.

This is intentionally stronger than detect-only recovery: the goal is to
stop the physical effect while SITL is running, not only raise an alert.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

import config as C
from mav_common import MavLink, vehicle_altitude, vehicle_armed

PublishFn = Callable[[dict], None]
# ok, result_str, attack_class, mitigation_delay_s, resume_ok
ResultFn = Callable[..., None]

SIGNATURE_GRACE_S = float(getattr(C, "DEFENSE_SIGNATURE_GRACE_S", 1.0))
PREVENT_HOLD_S = float(getattr(C, "DEFENSE_PREVENT_HOLD_S", 12.0))
ENGAGE_SCORE = float(getattr(C, "DEFENSE_ENGAGE_SCORE", 0.72))
DEFENSE_MODE = str(getattr(C, "DEFENSE_MODE", "proactive")).lower()


_ABORT = threading.Event()
_STATE_LOCK = threading.Lock()
_ENABLED = False
_MODEL_AVAILABLE = False  # True only when a trained IDS artifact is loaded
_ACTIVE = False
_N_DEFENSES = 0
_LAST: dict[str, Any] | None = None


def set_model_available(available: bool) -> None:
    """Gate defense on trained-model presence (dashboard / live bridge)."""
    global _MODEL_AVAILABLE, _ENABLED
    with _STATE_LOCK:
        _MODEL_AVAILABLE = bool(available)
        if not _MODEL_AVAILABLE:
            _ENABLED = False
        armed = bool(_ENABLED) and bool(_MODEL_AVAILABLE)
    try:
        from ids.mav_gateway import get_gateway
        get_gateway().set_defense_enabled(armed)
        if not armed:
            get_gateway().clear_drop_policy()
    except Exception:
        pass


def model_available() -> bool:
    with _STATE_LOCK:
        return bool(_MODEL_AVAILABLE)


def defense_enabled() -> bool:
    """True only when the operator armed Defense AND a trained model is loaded."""
    with _STATE_LOCK:
        return bool(_ENABLED) and bool(_MODEL_AVAILABLE)


def set_defense_enabled(enabled: bool) -> None:
    global _ENABLED
    with _STATE_LOCK:
        # Ignore ON requests when no trained model — unprotected mode.
        if enabled and not _MODEL_AVAILABLE:
            _ENABLED = False
        else:
            _ENABLED = bool(enabled)
        armed = bool(_ENABLED) and bool(_MODEL_AVAILABLE)
        if not armed:
            _ABORT.clear()
    try:
        from ids.mav_gateway import get_gateway
        get_gateway().set_defense_enabled(armed)
        if not armed:
            get_gateway().clear_drop_policy()
    except Exception:
        pass


def defense_active() -> bool:
    with _STATE_LOCK:
        return _ACTIVE


def defense_should_abort() -> bool:
    """Attacks call this inside loops — True once IPS reclaim/prevent starts."""
    return _ABORT.is_set() and defense_enabled()


def defense_status() -> dict:
    with _STATE_LOCK:
        model_ok = bool(_MODEL_AVAILABLE)
        want = bool(_ENABLED)
        return {
            "defense_enabled": bool(want and model_ok),
            "defense_wanted": want,
            "model_available": model_ok,
            "unprotected": not model_ok,
            "defense_active": _ACTIVE,
            "n_defenses": _N_DEFENSES,
            "last_defense": dict(_LAST) if _LAST else None,
            "signature_grace_s": SIGNATURE_GRACE_S,
            "prevent_hold_s": PREVENT_HOLD_S,
            "engage_score": ENGAGE_SCORE,
            "defense_mode": DEFENSE_MODE,
        }


class DefenseController:
    """Runs prevent/recover engagements on a dedicated defender GCS link."""

    def __init__(self, publish: PublishFn | None = None):
        self.publish = publish or (lambda _msg: None)
        self.on_result: ResultFn | None = None
        self._thread: threading.Thread | None = None
        self._engaging = threading.Event()
        self._stop = threading.Event()

    def set_enabled(self, enabled: bool) -> None:
        set_defense_enabled(enabled)
        if not enabled:
            self._stop.set()
            _ABORT.clear()
            self.publish({
                "type": "ids",
                "data": {
                    "event": "defense_mode",
                    "defense_enabled": False,
                    "defense_mode": DEFENSE_MODE,
                    "message": "Defense OFF — detect only (no prevention)",
                },
            })
        else:
            self._stop.clear()
            mode = DEFENSE_MODE
            armed = defense_enabled()
            try:
                from ids.mav_gateway import get_gateway
                get_gateway().set_defense_enabled(armed)
                get_gateway().set_mode(mode)
            except Exception:
                pass
            self.publish({
                "type": "ids",
                "data": {
                    "event": "defense_mode",
                    "defense_enabled": armed,
                    "defense_mode": mode,
                    "unprotected": not model_available(),
                    "model_available": model_available(),
                    "message": (
                        "Defense ON blocked — no trained IDS model (unprotected)"
                        if not armed else
                        (f"Defense ON — {mode.upper()} "
                         f"(proactive=pre-PX4 drop · reactive=reclaim; "
                         f"grace {SIGNATURE_GRACE_S:.1f}s, "
                         f"hold {PREVENT_HOLD_S:.0f}s)")
                    ),
                },
            })

    def maybe_engage(
        self,
        *,
        action: str,
        attack_class: str | None,
        score: float,
        modality: str,
        hold_s: float | None = None,
        gt_attack: bool = False,
        rules_severity: float | int | str = 0,
        grace_s: float | None = None,
    ) -> bool:
        """Start prevention if Defense is enabled. Returns True if engaged.

        IMPORTANT: only engages during the orchestrator ground-truth attack
        window (``gt_attack=True``). Detection still runs on the whole flight,
        but reclaiming OFFBOARD mid-mission (false positives on climb) used to
        break the shared plan and make the DT look like it “starts with attacks”.
        """
        if not defense_enabled():
            return False
        if action in ("none", "", None):
            return False
        # Reclaim/OFFBOARD only inside the orchestrator GT attack window.
        # Outside GT, the CNN still arms *proactive gateway drops* (see
        # live_bridge) — but reclaiming early made attacks look like they
        # started at climb and zeroed proactive block counts (_ABORT killed
        # the injector before packets hit the gateway).
        if not gt_attack:
            try:
                from ids.mav_gateway import get_gateway
                if float(score or 0.0) >= ENGAGE_SCORE:
                    get_gateway().arm_drop_policy(
                        attack_class, reason="cnn1d_preemptive")
            except Exception:
                pass
            return False
        if isinstance(rules_severity, str):
            sev = {"none": 0, "info": 0, "warn": 1, "critical": 2}.get(
                rules_severity.lower(), 0)
        else:
            sev = float(rules_severity or 0)

        high_score = float(score or 0.0) >= ENGAGE_SCORE
        if self._engaging.is_set():
            return False

        self._engaging.set()
        self._stop.clear()
        # Do NOT abort the injector immediately in proactive/hybrid — let
        # packets reach the gateway so pre-PX4 drops are counted, then abort.
        mode = DEFENSE_MODE
        if mode in ("reactive", "soft"):
            _ABORT.set()
        else:
            _ABORT.clear()
        # Proactive/hybrid: arm gateway drops immediately (pre-PX4) — no wait.
        # Reactive/soft: keep signature grace so reclaim is post-effect.
        if grace_s is not None:
            grace = float(grace_s)
        elif mode in ("proactive", "hybrid", "prevent"):
            grace = 0.0
        else:
            grace = float(SIGNATURE_GRACE_S)
        prevent_hold = float(hold_s if hold_s is not None else PREVENT_HOLD_S)
        # In soft mode, shorter reclaim; prevent/hybrid hold for the attack window.
        if mode == "soft":
            prevent_hold = min(prevent_hold, 5.0)
        try:
            from ids.mav_gateway import get_gateway
            get_gateway().arm_drop_policy(attack_class, reason="ids_engage")
        except Exception:
            pass

        def _worker():
            global _ACTIVE, _N_DEFENSES, _LAST
            with _STATE_LOCK:
                _ACTIVE = True
                _N_DEFENSES += 1
                n = _N_DEFENSES
            reason = ("critical_rule" if sev >= 2
                      else ("high_score" if high_score else "gt_window"))
            path = ("proactive+reactive" if mode in ("hybrid", "prevent")
                    else ("proactive" if mode == "proactive" else "reactive"))
            detail = {
                "event": "defend",
                "defense_enabled": True,
                "defense_active": True,
                "defense_mode": mode,
                "defense_path": path,
                "action": action,
                "attack_class": attack_class,
                "attack_score": score,
                "modality": modality,
                "n_defenses": n,
                "grace_s": grace,
                "prevent_hold_s": prevent_hold,
                "engage_reason": reason,
                "message": (f"DEFENSE ({path}) · {attack_class or 'attack'} → {action} "
                            f"({reason}, grace {grace:.1f}s, hold {prevent_hold:.0f}s)"),
            }
            with _STATE_LOCK:
                _LAST = dict(detail)
            self.publish({"type": "ids", "data": detail})
            self.publish({
                "type": "log",
                "tag": "defense",
                "msg": detail["message"],
                "ts": time.time(),
            })
            result = "ok"
            engage_t0 = time.time()
            mitigation_delay = None
            resume_ok = None
            try:
                t0 = time.time()
                while time.time() - t0 < grace:
                    if self._stop.is_set() or not defense_enabled():
                        result = "canceled"
                        return
                    time.sleep(0.05)
                # Proactive: keep injector alive briefly so the gateway can
                # actually receive+drop attack packets (otherwise abort races
                # the first GPS_INPUT/COMMAND and proactive_blocks stay 0).
                # Hybrid: short observe, then abort + optional reclaim.
                if mode == "proactive":
                    t_obs = time.time()
                    while time.time() - t_obs < 1.25:
                        if self._stop.is_set() or not defense_enabled():
                            break
                        time.sleep(0.05)
                elif mode == "hybrid":
                    t_obs = time.time()
                    while time.time() - t_obs < 0.35:
                        if self._stop.is_set() or not defense_enabled():
                            break
                        time.sleep(0.05)
                _ABORT.set()
                mitigation_delay = max(0.0, time.time() - engage_t0)
                # Proactive: gateway drop + abort only.
                # Hybrid: drop/abort, then briefly stabilize GPS/mode attacks so
                # the defence response is visible, then release the pilot.
                if mode == "proactive":
                    result = "proactive_gateway_drop"
                    resume_ok = True
                elif mode in ("hybrid", "prevent"):
                    if attack_class in (
                        "gps_spoofing", "mode_change_land", "mode_change_rtl",
                        "disarm_injection", "mission_injection",
                    ):
                        short_hold = min(3.0, prevent_hold)
                        result = self._prevent(
                            action, attack_class, hold_s=short_hold)
                        resume_ok = (bool(result)
                                     and not str(result).startswith("error")
                                     and result != "canceled")
                    else:
                        result = "hybrid_gateway_drop"
                        resume_ok = True
                else:
                    result = self._prevent(action, attack_class, hold_s=prevent_hold)
                    # Mission resume OK if reclaim finished and vehicle still safe.
                    resume_ok = (bool(result)
                                 and not str(result).startswith("error")
                                 and result != "canceled")
                    if resume_ok:
                        try:
                            resume_ok = bool(
                                vehicle_armed() or vehicle_altitude() > 1.0)
                        except Exception:
                            pass
            except Exception as exc:  # noqa: BLE001
                result = f"error: {exc}"
                resume_ok = False
                self.publish({
                    "type": "log",
                    "tag": "defense",
                    "msg": f"defense failed: {exc}",
                    "ts": time.time(),
                })
            finally:
                if DEFENSE_MODE != "prevent":
                    _ABORT.clear()
                else:
                    # Keep abort briefly so late attack packets die out.
                    time.sleep(0.6)
                    _ABORT.clear()
                ok = (bool(result)
                      and not str(result).startswith("error")
                      and result != "canceled")
                with _STATE_LOCK:
                    _ACTIVE = False
                    if _LAST is not None:
                        _LAST = {**_LAST, "result": result, "defense_active": False,
                                 "ok": ok,
                                 "mitigation_delay_s": mitigation_delay,
                                 "resume_ok": resume_ok}
                self._engaging.clear()
                if self.on_result is not None:
                    try:
                        self.on_result(ok, str(result), attack_class,
                                       mitigation_delay, resume_ok)
                    except TypeError:
                        try:
                            self.on_result(ok, str(result), attack_class)
                        except TypeError:
                            try:
                                self.on_result(ok, str(result))  # type: ignore[call-arg]
                            except Exception:
                                pass
                        except Exception:
                            pass
                    except Exception:
                        pass
                self.publish({
                    "type": "ids",
                    "data": {
                        "event": "defend_done",
                        "defense_enabled": defense_enabled(),
                        "defense_active": False,
                        "action": action,
                        "attack_class": attack_class,
                        "result": result,
                        "ok": ok,
                        "mitigation_delay_s": mitigation_delay,
                        "resume_ok": resume_ok,
                        "message": f"defense complete ({result})",
                    },
                })
                self.publish({
                    "type": "log",
                    "tag": "defense",
                    "msg": f"defense complete · {action} · {result}"
                           + (f" · mit={mitigation_delay:.2f}s" if mitigation_delay is not None else "")
                           + (f" · resume={'ok' if resume_ok else 'fail'}" if resume_ok is not None else ""),
                    "ts": time.time(),
                })

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        return True

    def _snapshot_pose(self) -> tuple[float, float, float]:
        x = y = 0.0
        z = -float(C.CRUISE_ALT)
        from mav_common import _VEHICLE, _VEHICLE_LOCK
        with _VEHICLE_LOCK:
            if _VEHICLE.get("x") is not None:
                x = float(_VEHICLE["x"])
            if _VEHICLE.get("y") is not None:
                y = float(_VEHICLE["y"])
            if _VEHICLE.get("z") is not None:
                z = float(_VEHICLE["z"])
                # Keep a safe minimum hold altitude if nearly on the ground
                # after a disarm/land attack.
                if -z < 1.5:
                    z = -float(C.CRUISE_ALT)
        return x, y, z

    def _prevent(self, action: str, attack_class: str | None, hold_s: float) -> str:
        """Abort attacker + continuous reclaim for ``hold_s`` seconds."""
        m = MavLink(sysid=getattr(C, "DEFENDER_SYSID", 249))
        try:
            m.reclaim()
            x, y, z = self._snapshot_pose()
            steps: list[str] = ["abort_attacker"]

            # Immediate class-specific counters (burst before hold loop).
            if action in ("require_auth_arming",) or attack_class == "disarm_injection":
                for _ in range(8):
                    m.arm(force=True)
                    time.sleep(0.08)
                steps.append("re-arm_burst")

            if attack_class in ("mode_change_land", "mode_change_rtl",
                                "mission_injection", "takeoff_injection",
                                "rc_override") or action in (
                "block_mode_change", "reject_mission_upload",
                "ignore_rc_override", "hold_or_rtl",
            ):
                for _ in range(5):
                    m.set_mode("OFFBOARD")
                    time.sleep(0.08)
                steps.append("force_OFFBOARD")

            if action == "block_param_set" or attack_class == "param_injection":
                safe = [
                    ("COM_DISARM_LAND", 2.0),
                    ("NAV_RCL_ACT", 2.0),
                    ("COM_RCL_EXCEPT", 0.0),
                ]
                from pymavlink import mavutil
                for name, val in safe:
                    try:
                        m.conn.mav.param_set_send(
                            C.PX4_SYSID, C.PX4_COMPID, name.encode(), float(val),
                            mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
                    except Exception:
                        pass
                steps.append("restore_params")

            if action == "reject_mission_upload" or attack_class == "mission_injection":
                # Clear rogue mission and keep OFFBOARD (do not fly attacker WPs).
                try:
                    from pymavlink import mavutil
                    m.conn.mav.mission_clear_all_send(C.PX4_SYSID, C.PX4_COMPID)
                except Exception:
                    pass
                steps.append("mission_clear")

            if action == "gps_integrity_gate" or attack_class == "gps_spoofing":
                steps.append("local_ned_hold")

            if action == "rate_limit_commands" or attack_class == "command_flood_dos":
                # Out-rate the flood with trusted heartbeats + OFFBOARD setpoints.
                steps.append("trusted_flood_counter")

            # Continuous prevent loop: keep abort set and dominate the command link.
            t0 = time.time()
            n_cmd = 0
            while time.time() - t0 < hold_s and not self._stop.is_set():
                if not defense_enabled():
                    steps.append("canceled")
                    break
                _ABORT.set()
                try:
                    m.reclaim()
                    m.set_mode("OFFBOARD")
                    m.set_position_target(x, y, z)
                    # Re-arm aggressively against disarm / DoS races.
                    if vehicle_armed() is False or attack_class in (
                        "disarm_injection", "command_flood_dos", None
                    ):
                        m.arm(force=True)
                    # Counter mode hijack every few ticks.
                    if n_cmd % 8 == 0 and attack_class in (
                        "mode_change_land", "mode_change_rtl", "mission_injection"
                    ):
                        m.set_mode("OFFBOARD")
                    n_cmd += 1
                except Exception:
                    pass
                time.sleep(0.05)

            alt = vehicle_altitude()
            armed = vehicle_armed()
            steps.append(
                f"held_{n_cmd}cmds_alt="
                f"{alt:.1f}m" if alt is not None else f"held_{n_cmd}cmds"
            )
            steps.append(f"armed={armed}")
            return "+".join(steps)
        finally:
            try:
                m.close()
            except Exception:
                pass


# Module-level singleton used by the dashboard.
_CONTROLLER: DefenseController | None = None


def get_defense_controller(publish: PublishFn | None = None) -> DefenseController:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = DefenseController(publish=publish)
    elif publish is not None:
        _CONTROLLER.publish = publish
    return _CONTROLLER
