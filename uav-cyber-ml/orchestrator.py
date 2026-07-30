"""Master runner: drive the whole scenario matrix from the Mac.

For every scenario (benign + each attack) and every run it:
  1. restarts PX4 SITL on the UAV over SSH and waits until ready,
  2. starts the physical + network recorders on the Mac,
  3. runs a benign flight, or warms up + fires the attack at a fixed offset,
  4. stops the recorders and writes run metadata (incl. the attack window),
  5. stops SITL.

Usage:
  python3 orchestrator.py --runs 3
  python3 orchestrator.py --scenarios benign,takeoff_injection --runs 2
  python3 orchestrator.py --list
"""

from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import config as C
import ssh_control as ssh
import mav_common
from attacks.benign import BenignPilot
from attacks.suite import ATTACKS, BENIGN_META, pipeline_scenario_ids, core_attack_ids
from mav_common import log
from recorders.network_recorder import NetworkRecorder
from recorders.physical_recorder import PhysicalRecorder

# Cooperative abort: dashboard Stop must interrupt pilot / attack / land waits.
_ACTIVE_PILOT: BenignPilot | None = None
_ACTIVE_PILOT_LOCK = threading.Lock()


def request_run_abort(reason: str = "user_stop") -> None:
    """Hard-cancel the in-flight scenario as quickly as possible."""
    mav_common.request_run_abort()
    log("orch", f"abort requested ({reason})")
    try:
        from ids.defense import _ABORT
        _ABORT.set()
    except Exception:
        pass
    with _ACTIVE_PILOT_LOCK:
        pilot = _ACTIVE_PILOT
    if pilot is not None:
        try:
            pilot.abort_now()
        except Exception:
            pass


def clear_run_abort() -> None:
    mav_common.clear_run_abort()
    try:
        from ids.defense import _ABORT, defense_active
        if not defense_active():
            _ABORT.clear()
    except Exception:
        pass


def run_abort_requested() -> bool:
    return mav_common.run_abort_requested()


def _register_pilot(pilot: BenignPilot | None) -> None:
    global _ACTIVE_PILOT
    with _ACTIVE_PILOT_LOCK:
        _ACTIVE_PILOT = pilot


def _defense_on() -> bool:
    try:
        from ids.defense import defense_enabled
        return bool(defense_enabled())
    except Exception:
        return False


def _fire_attack_async(fn, duration_s: float, log_fn) -> threading.Thread:
    """Run injector in background so the mission thread is not blocked."""
    def _run():
        try:
            fn(float(duration_s), log_fn)
        except Exception as exc:  # noqa: BLE001
            try:
                log_fn("orch", f"async attack error: {exc}")
            except Exception:
                pass
    th = threading.Thread(target=_run, daemon=True, name="atk-async")
    th.start()
    return th


def _end_attack_window_later(hooks: "Hooks", *, scenario: str, t0: float,
                             entry: dict, idx: int, total: int,
                             windows: list, post_s: float, delay_s: float,
                             start_rel: float, tour: bool = False):
    """Close GT attack phase after a short defended burst (non-blocking)."""
    def _end():
        time.sleep(max(0.2, float(delay_s)))
        a1 = time.time() - t0
        windows.append({
            "attack": scenario if not tour else entry.get("attack", scenario),
            "wp_id": entry["wp_id"],
            "after_wp": entry.get("after_wp"),
            "start_rel": float(start_rel),
            "end_rel": a1,
        })
        kw = dict(phase="post_attack", scenario=scenario,
                  attack_end_rel=a1, attack_wp=entry["wp_id"])
        if tour:
            kw["tour"] = True
        else:
            kw.update(post_s=post_s, attack_idx=idx, attack_total=total,
                      remaining_attacks=max(0, total - idx),
                      attack_windows=list(windows))
        try:
            hooks.state(**kw)
        except Exception:
            pass
    threading.Thread(target=_end, daemon=True, name="atk-gt-end").start()


@dataclass
class Hooks:
    """Optional live callbacks so a UI (dashboard) can observe a run.

    All callbacks are optional; when omitted the run behaves exactly like the
    headless CLI. ``should_stop`` lets a UI request early cancellation.
    """
    on_log: Optional[Callable[[str, str], None]] = None
    on_phys: Optional[Callable[[dict], None]] = None
    on_net: Optional[Callable[[dict], None]] = None
    on_state: Optional[Callable[[dict], None]] = None
    should_stop: Optional[Callable[[], bool]] = None

    def state(self, **kw):
        if self.on_state:
            try:
                self.on_state(kw)
            except Exception:
                pass

    def stopped(self) -> bool:
        if mav_common.run_abort_requested():
            return True
        return bool(self.should_stop and self.should_stop())


def port_free(port: int) -> bool:
    """True if the UDP port can be bound on the Mac right now."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def probe_vehicle(timeout: float = 4.0) -> tuple[bool, bool, float | None, float | None]:
    """Return (alive, grounded, x, y) using the reliable passive 14550 listen.

    Used to decide whether a warm SITL can be reused instead of restarting
    Gazebo. Binds 14550, so it must be called sequentially when idle (before the
    physical recorder binds the same port).
    """
    return ssh.probe_passive(timeout=timeout)


def _near_home(x, y, radius: float = 2.0) -> bool:
    if x is None or y is None:
        return False
    return abs(x) < radius and abs(y) < radius


def _ensure_command_link(hooks: Hooks) -> bool:
    """Verify PX4 telemetry/command path (14550) before a run."""
    if mav_common.ping_command_link(timeout=3.5):
        return True
    log("orch", "GCS telemetry (14550) dead — restarting SITL to recover")
    hooks.state(phase="sitl_starting", reason="command_link_dead")
    ssh.stop_sitl()
    ssh.start_sitl()
    if not ssh.wait_ready(timeout=150):
        log("orch", "SITL did not recover after command-link restart")
        hooks.state(phase="error", message="SITL not ready after command-link restart")
        return False
    time.sleep(1.0)
    ok = mav_common.ping_command_link(timeout=5.0)
    if not ok:
        log("orch", "command/telemetry link still dead after SITL restart")
        hooks.state(phase="error", message="GCS link dead (14550)")
    return ok


def _prepare_vehicle_for_flight(hooks: Hooks, force_cold: bool = False) -> bool:
    """Apply SITL arming prep; cold-restart once if the warm instance is sick.

    Root cause we hit in the lab: warm SITL accumulates Compass-0 / preflight
    faults so OFFBOARD is accepted but ARM is denied — DT/PT stay grounded.
    """
    if force_cold:
        log("orch", "cold-starting SITL before flight (arm recovery)")
        hooks.state(phase="sitl_starting", reason="arm_recovery")
        ssh.stop_sitl()
        time.sleep(1.0)
        ssh.start_sitl()
        if not ssh.wait_ready(timeout=150):
            hooks.state(phase="error", message="SITL not ready after arm recovery")
            return False
        time.sleep(1.5)

    m = mav_common.MavLink(sysid=C.CONTROLLER_SYSID)
    try:
        if not m.ensure_link(timeout=6.0):
            log("orch", "prepare_vehicle: no command link")
            return False
        log("orch", "preparing vehicle for arm (disable mag/RC arm blockers)")
        m.prepare_sitl_for_arm()

        # Inspect MAG health while 14550 is still free (before the recorder binds).
        mag_ok = True
        try:
            from pymavlink import mavutil
            c = mavutil.mavlink_connection(f"udpin:0.0.0.0:{C.GCS_PORT}",
                                           source_system=253)
            m._cmd(mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE,
                   mavutil.mavlink.MAVLINK_MSG_ID_SYS_STATUS)
            t0 = time.time()
            while time.time() - t0 < 2.5:
                msg = c.recv_match(type="SYS_STATUS", blocking=True, timeout=0.3)
                if msg is None:
                    continue
                # MAV_SYS_STATUS_SENSOR_3D_MAG = 4
                present = bool(msg.onboard_control_sensors_present & 4)
                healthy = bool(msg.onboard_control_sensors_health & 4)
                mag_ok = (not present) or healthy
                log("orch", f"mag present={present} healthy={healthy}")
                break
            c.close()
        except Exception as exc:  # noqa: BLE001
            log("orch", f"mag health probe skipped: {exc}")

        if mag_ok or force_cold:
            return True

        log("orch", "MAG unhealthy on warm SITL — cold restart required for arming")
        try:
            m.close()
        except Exception:
            pass
        return _prepare_vehicle_for_flight(hooks, force_cold=True)
    except Exception as exc:  # noqa: BLE001
        log("orch", f"prepare_vehicle warning: {exc}")
        return True  # still attempt the run
    finally:
        try:
            m.close()
        except Exception:
            pass


def _land_disarm_reset(hooks: Hooks, timeout: float = 14.0) -> None:
    """Land, disarm, and teleport the Gazebo model back to home (0, 0).

    Keeps Gazebo warm so the next scenario can arm/takeoff immediately while
    still guaranteeing a default spawn position. TwinBridge (started by the
    caller) keeps the digital twin following this motion via UDP 14550.
    """
    # User Stop: skip the long land/settle path — just try a quick disarm/home.
    if hooks.stopped():
        log("orch", "stop active — fast wind-down (skip full land wait)")
        try:
            m = mav_common.MavLink(sysid=C.CONTROLLER_SYSID)
            try:
                m.ensure_link(timeout=1.0)
                m.set_mode("AUTO_LAND")
                m.disarm(force=True)
            finally:
                m.close()
        except Exception:
            pass
        try:
            ssh.reset_home()
        except Exception:
            pass
        hooks.state(phase="home_reset")
        return

    m = None
    try:
        m = mav_common.MavLink(sysid=C.CONTROLLER_SYSID)
        try:
            m.ensure_link(timeout=3.0)
            m.request_streams(rate_hz=20)
            m.set_message_interval(32, 20)   # LOCAL_POSITION_NED
            m.set_message_interval(30, 20)   # ATTITUDE
        except Exception:
            pass
        # Drop any lingering OFFBOARD stream and command LAND clearly
        m.set_mode("AUTO_LAND")
        time.sleep(0.15)
        m.set_mode("AUTO_LAND")
        m.land()
        t0 = time.time()
        last_alt = None
        # On stop mid-land, bail quickly.
        land_timeout = min(timeout, 3.0) if hooks.stopped() else timeout
        while time.time() - t0 < land_timeout:
            if hooks.stopped():
                break
            alt = m.altitude(timeout=0.35)
            if alt is not None:
                last_alt = alt
                if alt < 0.35:
                    break
            # re-assert LAND periodically (PX4 can ignore a one-shot after attacks)
            if int(time.time() - t0) % 2 == 0:
                m.set_mode("AUTO_LAND")
            time.sleep(0.15)
        log("orch", f"land complete (alt≈{last_alt})")
        hooks.state(phase="landed", alt=last_alt)
        m.disarm(force=True)
        time.sleep(0.3 if hooks.stopped() else 0.6)
        m.disarm(force=True)
        time.sleep(0.2 if hooks.stopped() else 0.4)
    except Exception as exc:  # noqa: BLE001
        log("orch", f"land/disarm exception: {exc}")
    finally:
        if m is not None:
            try:
                m.close()
            except Exception:
                pass
    if hooks.stopped():
        try:
            ssh.reset_home()
        except Exception:
            pass
        hooks.state(phase="home_reset")
        return
    # Brief settle so DT can show the vehicle on the pad before the Gazebo teleport
    hooks.state(phase="settling")
    time.sleep(1.2)
    try:
        pose = ssh.reset_home()
        log("orch", f"reset vehicle to home: {pose}")
        time.sleep(1.0)
    except Exception as exc:  # noqa: BLE001
        log("orch", f"home reset failed: {exc}")
        time.sleep(0.4)
    hooks.state(phase="home_reset")


def preflight() -> bool:
    if port_free(C.GCS_PORT):
        return True
    import subprocess as sp
    who = sp.run(["lsof", "-nP", f"-iUDP:{C.GCS_PORT}"], capture_output=True, text=True).stdout
    print(f"\nERROR: UDP {C.GCS_PORT} is busy — the physical recorder cannot bind it.")
    print("Close QGroundControl or kill the process holding it, then rerun.\n")
    print(who or "(could not determine holder)")
    return False


def sudo_prime() -> bool:
    """Cache sudo credentials once so tcpdump can run unattended."""
    r = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if r.returncode == 0:
        return True
    print("Network capture needs sudo (tcpdump). Enter your Mac password once:")
    return subprocess.run(["sudo", "-v"]).returncode == 0


def _wait_mission_interruptible(pilot: BenignPilot, hooks: Hooks,
                                  timeout: float) -> bool:
    """Like wait_mission_done, but returns early when Stop is pressed."""
    deadline = time.time() + max(0.5, float(timeout))
    while time.time() < deadline:
        if hooks.stopped():
            try:
                pilot.abort_now()
            except Exception:
                pass
            return False
        if pilot.mission_done.wait(timeout=0.2):
            return True
    return False


def run_scenario(scenario: str, run_idx: int, net_ok: bool,
                 hooks: Optional[Hooks] = None,
                 reuse_sitl: bool = False,
                 stop_sitl_after: bool = True,
                 attack_schedule: Optional[list] = None,
                 attack_seed: int | None = None) -> Path:
    hooks = hooks or Hooks()
    clear_run_abort()
    if hooks.on_log:
        mav_common.add_log_sink(hooks.on_log)
    run_dir = C.RUNS_DIR / scenario / f"run_{run_idx:02d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    run_name = f"run_{run_idx:02d}"
    log("orch", f"=== scenario={scenario} run={run_idx} ===")

    live_net = None
    try:
        # 1. sim: reuse warm SITL only if grounded near home (0,0); else fresh boot
        reused = False
        if reuse_sitl:
            hooks.state(phase="sitl_probing", scenario=scenario, run=run_idx)
            alive, grounded, x, y = probe_vehicle()
            if alive and grounded and _near_home(x, y):
                reused = True
                log("orch", f"reusing warm SITL at home "
                            f"(x={x:.1f}, y={y:.1f})")
                hooks.state(phase="sitl_ready", scenario=scenario,
                            run=run_idx, reused=True)
            elif alive:
                log("orch", f"warm SITL not at home "
                            f"(grounded={grounded}, x={x}, y={y}) — resetting")
                if grounded:
                    try:
                        ssh.reset_home()
                        time.sleep(0.8)
                        alive2, grounded2, x2, y2 = probe_vehicle(timeout=3.0)
                        if alive2 and grounded2 and _near_home(x2, y2):
                            reused = True
                            log("orch", "home reset OK — reusing SITL")
                            hooks.state(phase="sitl_ready", scenario=scenario,
                                        run=run_idx, reused=True)
                    except Exception:
                        pass
        if not reused:
            hooks.state(phase="sitl_starting", scenario=scenario, run=run_idx)
            ssh.stop_sitl()
            ssh.start_sitl()
            if not ssh.wait_ready(timeout=150):
                log("orch", "SITL not ready; skipping run")
                hooks.state(phase="error", message="SITL not ready")
                return run_dir
            time.sleep(0.8)  # brief settle (was 3s)
            hooks.state(phase="sitl_ready", scenario=scenario,
                        run=run_idx, reused=False)

        # Command/telemetry path (14550) must be alive or the vehicle never arms and the
        # digital twin stays grounded.
        if not _ensure_command_link(hooks):
            return run_dir
        # Clear sticky SITL prearm faults (compass) before the recorder binds 14550.
        if not _prepare_vehicle_for_flight(hooks, force_cold=False):
            return run_dir

        # 2. recorders
        phys = PhysicalRecorder(run_dir, on_sample=hooks.on_phys)
        net = NetworkRecorder(run_dir) if net_ok else None
        if net:
            net.start()
        if net_ok and hooks.on_net:
            from recorders.live_network import LiveNetworkSniffer
            live_net = LiveNetworkSniffer(on_window=hooks.on_net)
            live_net.start()
        phys.start()
        t0 = time.time()
        log("orch", "recording started")

        attack_start = attack_end = post_end = None
        pilot = None
        pre_s = atk_s = post_s = None
        attack_wp = None
        windows: list[dict] = []
        schedule: list[dict] = []

        def _on_wp(idx, wp, hint):
            hooks.state(phase="mission_wp", scenario=scenario,
                        wp_idx=idx, wp_id=wp["id"],
                        x=wp["x"], y=wp["y"], z=wp["z"], hint=hint)

        if scenario == "benign":
            run_total = float(C.mission_duration_s())
            hooks.state(phase="recording", scenario=scenario, run=run_idx,
                        run_name=run_name, duration_s=run_total,
                        profile="shared_mission", is_attack=False, t0_wall=t0,
                        mission_plan=C.MISSION_PLAN)
            log("orch", f"BENIGN shared mission ({len(C.MISSION_PLAN)} WPs, "
                        f"~{run_total:.0f}s)")
            pilot = BenignPilot(on_wp=_on_wp)
            _register_pilot(pilot)
            pilot.start_shared_mission(pause_for_attack=False, land_at_end=False)
            _wait_mission_interruptible(pilot, hooks, run_total + 40)
            run_total = time.time() - t0
        else:
            meta = ATTACKS[scenario]
            atk_s = float(C.ATTACK_DUR_S)
            schedule = list(attack_schedule or C.build_repeated_attack_schedule(
                scenario, seed=attack_seed))
            first_gate = int(schedule[0]["after_wp"]) if schedule else int(C.ATTACK_AFTER_WP)
            attack_wp = C.MISSION_PLAN[first_gate]["id"] if first_gate < len(C.MISSION_PLAN) else None
            pre_s = float(sum(float(w["dwell_s"]) for w in C.MISSION_PLAN[:first_gate + 1]) + 3.0)
            post_s = float(sum(float(w["dwell_s"]) for w in C.MISSION_PLAN[first_gate + 1:]))
            run_total = float(C.mission_duration_s() + len(schedule) * atk_s)
            hooks.state(phase="recording", scenario=scenario, run=run_idx,
                        run_name=run_name, duration_s=run_total,
                        profile="shared_mission", is_attack=True, t0_wall=t0,
                        pre_s=pre_s, attack_s=atk_s, post_s=post_s,
                        mission_plan=C.MISSION_PLAN,
                        attack_after_wp=first_gate, attack_wp=attack_wp,
                        attack_schedule=schedule, attack_seed=attack_seed)
            log("orch", f"ATTACK scenario '{scenario}' on shared mission: "
                        + ", ".join(f"{e['wp_id']}→{e['attack']}" for e in schedule))

            pilot = BenignPilot(on_wp=_on_wp)
            _register_pilot(pilot)
            defended = _defense_on()
            # Defense ON → fly through attack WPs at normal dwell (no pause).
            # Defense OFF → hold at gate so capture labels see a clean effect.
            pilot.start_shared_mission(pause_for_attack=False, land_at_end=False,
                                       schedule=schedule,
                                       pass_through_gates=defended)
            hooks.state(phase="pre_attack", scenario=scenario,
                        attack_at_s=pre_s, pre_s=pre_s,
                        attack_wp=attack_wp, attack_schedule=schedule)

            for idx, entry in enumerate(schedule, start=1):
                if hooks.stopped():
                    break
                gate_timeout = max(60.0, float(C.mission_duration_s()))
                gate_ok = pilot.wait_attack_gate(timeout=gate_timeout)
                if not gate_ok or hooks.stopped():
                    log("orch", f"WARNING: attack gate timeout before {entry['wp_id']}")
                    break
                # Verify the gate matches the scheduled waypoint (guards against
                # spurious early wakes that used to fire attacks at takeoff).
                got = getattr(pilot, "_last_gate", None) or {}
                if got.get("wp_id") and got.get("wp_id") != entry.get("wp_id"):
                    log("orch", f"WARNING: gate mismatch got={got.get('wp_id')} "
                                f"expected={entry.get('wp_id')} — skipping fire")
                    pilot.resume_after_attack()
                    continue

                a0 = time.time() - t0
                if attack_start is None:
                    attack_start = a0

                if defended:
                    # Hybrid demo: let spoof packets through briefly so the UAV
                    # shows an effect; IDS rules/CNN then arm drops + abort.
                    # Proactive: still preemptive (drop immediately).
                    try:
                        from ids.defense import DEFENSE_MODE
                        mode = str(DEFENSE_MODE or "hybrid").lower()
                    except Exception:
                        mode = "hybrid"
                    burst = min(float(atk_s), 8.0 if mode == "hybrid" else 3.0)
                    log("orch", f"FIRING '{scenario}' attempt {idx}/{len(schedule)} "
                                f"at t_rel={a0:.1f}s after {entry['wp_id']} "
                                f"async {burst:.1f}s (defended {mode})")
                    hooks.state(phase="attack", scenario=scenario,
                                attack_start_rel=a0,
                                title=meta.get("title", scenario),
                                effect=meta.get("effect", ""),
                                attack_wp=entry["wp_id"],
                                attack_idx=idx, attack_total=len(schedule),
                                unprotected=False)
                    if scenario == "gps_spoofing" and mode == "hybrid":
                        drift = float(getattr(C, "GPS_SPOOF_DRIFT", 3e-5))
                        v_walk = drift * 111320.0
                        pilot.set_nav_bias_rate(v_walk, v_walk)
                    if mode in ("proactive", "prevent"):
                        try:
                            from ids.mav_gateway import get_gateway
                            gw = get_gateway()
                            gw.set_mode(mode)
                            gw.set_defense_enabled(True)
                            gw.arm_drop_policy(
                                scenario, reason="orch_preemptive")
                        except Exception:
                            pass
                        # Let injector run the burst so gateway can drop+count.
                        # Early abort (0.2s) killed attacks before packets, so
                        # the proactive table stayed at 0.
                        abort_delay = max(0.8, burst - 0.15)
                    else:
                        # hybrid: do NOT pre-arm drops; IDS will arm on detect
                        try:
                            from ids.mav_gateway import get_gateway
                            get_gateway().set_mode(mode)
                        except Exception:
                            pass
                        abort_delay = max(2.5, burst * 0.55)
                    try:
                        from ids.defense import _ABORT
                        _ABORT.clear()
                    except Exception:
                        pass
                    time.sleep(0.05)
                    _fire_attack_async(meta["fn"], burst, log)

                    def _proactive_abort(delay=abort_delay, hold=burst):
                        time.sleep(delay)
                        try:
                            from ids.defense import _ABORT
                            from ids.mav_gateway import get_gateway
                            get_gateway().arm_drop_policy(
                                scenario, reason="orch_timeout_arm")
                            _ABORT.set()
                            try:
                                pilot.clear_nav_bias(reset_offset=True)
                            except Exception:
                                pass
                            time.sleep(max(0.5, hold - delay))
                            _ABORT.clear()
                        except Exception:
                            pass
                    threading.Thread(target=_proactive_abort, daemon=True).start()
                    pilot.consume_attack_gate()
                    _end_attack_window_later(
                        hooks, scenario=scenario, t0=t0, entry=entry,
                        idx=idx, total=len(schedule), windows=windows,
                        post_s=post_s, delay_s=burst + 0.15,
                        start_rel=a0, tour=False)
                    attack_end = a0 + burst
                    continue

                # Capture / undefended (no trained model OR Defense OFF):
                # GPS keeps OFFBOARD streaming + nav bias so Gazebo shows drift.
                hard = scenario not in ("gps_spoofing",)
                pilot.freeze_for_attack(hard=hard)
                if scenario == "gps_spoofing":
                    # Match GPS_SPOOF_DRIFT (~deg/s → m/s) for visible path error.
                    drift = float(getattr(C, "GPS_SPOOF_DRIFT", 3e-5))
                    v_walk = drift * 111320.0
                    pilot.set_nav_bias_rate(v_walk, v_walk)
                log("orch", f"FIRING '{scenario}' attempt {idx}/{len(schedule)} "
                            f"at t_rel={a0:.1f}s after {entry['wp_id']} for {atk_s:.1f}s "
                            f"({'hard-freeze' if hard else 'unprotected GPS spoof'})")
                hooks.state(phase="attack", scenario=scenario,
                            attack_start_rel=a0,
                            title=meta.get("title", scenario),
                            effect=meta.get("effect", ""),
                            attack_wp=entry["wp_id"],
                            attack_idx=idx, attack_total=len(schedule),
                            unprotected=True)
                time.sleep(0.15)
                meta["fn"](atk_s, log)
                a1 = time.time() - t0
                attack_end = a1
                windows.append({
                    "attack": scenario,
                    "wp_id": entry["wp_id"],
                    "after_wp": entry["after_wp"],
                    "start_rel": a0,
                    "end_rel": a1,
                })
                try:
                    n_cand = len(C.attack_gate_candidates())
                    (run_dir / "metadata.json").write_text(json.dumps({
                        "scenario": scenario, "run": run_idx, "is_attack": True,
                        "attack_start_rel": attack_start,
                        "attack_end_rel": attack_end,
                        "attack_windows": windows,
                        "attack_schedule": list(schedule),
                        "n_attack_gates": len(schedule),
                        "n_normal_gates": max(0, n_cand - len(schedule)),
                        "partial": True,
                    }, indent=2))
                except Exception:
                    pass
                log("orch", f"attack attempt {idx}/{len(schedule)} ended at "
                            f"t_rel={a1:.1f}s — resuming mission")
                if scenario == "gps_spoofing":
                    pilot.clear_nav_bias(reset_offset=False)
                hooks.state(phase="post_attack", scenario=scenario,
                            attack_end_rel=a1, post_s=post_s,
                            attack_wp=entry["wp_id"],
                            attack_idx=idx, attack_total=len(schedule),
                            remaining_attacks=max(0, len(schedule) - idx),
                            attack_windows=windows)
                pilot.resume_after_attack()

            wait_extra = (0.0 if defended else len(schedule) * atk_s)
            _wait_mission_interruptible(
                pilot, hooks, C.mission_duration_s() + wait_extra + 60)
            post_end = time.time() - t0
            run_total = post_end

        # Announce landing early so UI / twin handoff stay continuous.
        hooks.state(phase="landing", scenario=scenario)

        # Seamless phys→twin handoff (keepalive fills the UDP socket swap gap).
        # Without this the DT freezes mid-air at Home WP until twin rebinds.
        twin = None
        from recorders.twin_bridge import handoff_phys_to_twin
        twin = handoff_phys_to_twin(phys, hooks.on_phys, t0)
        if live_net:
            live_net.stop()
        if net:
            net.stop()
        if phys.bind_error:
            log("orch", f"WARNING: physical recorder failed — {phys.bind_error}")
        elif phys.n_msgs == 0:
            log("orch", "WARNING: 0 physical msgs (is QGC on 14550? is SITL streaming?)")
        log("orch", f"recording stopped ({phys.n_msgs} physical msgs)")
        if twin is not None:
            log("orch", "twin bridge live for landing follow-through")
        elif hooks.on_phys is not None:
            log("orch", "twin bridge could not bind 14550 — DT may freeze during land")

        # Start AUTO_LAND while twin is already streaming, then release the
        # pilot. Do not abort setpoints *before* land mode — that left the
        # vehicle hanging mid-air until the next land command arrived.
        if pilot is not None:
            try:
                if not hooks.stopped():
                    pilot._stream = False
                    pilot._freeze = True
                    try:
                        pilot.mav.set_mode("AUTO_LAND")
                        time.sleep(0.1)
                        pilot.mav.set_mode("AUTO_LAND")
                        pilot.mav.land()
                    except Exception:
                        pass
            except Exception as exc:  # noqa: BLE001
                log("orch", f"begin-land warning: {exc}")
            try:
                pilot.abort_now()
                pilot.close()
            except Exception:
                pass
            _register_pilot(None)
            pilot = None

        # 4. metadata + per-row phase labels for ML
        n_cand = len(C.attack_gate_candidates()) if schedule else 0
        meta_out = {
            "scenario": scenario,
            "run": run_idx,
            "is_attack": scenario != "benign",
            "attack_start_rel": attack_start,
            "attack_end_rel": attack_end,
            "attack_windows": windows,
            "post_end_rel": post_end if post_end is not None else run_total,
            "pre_s": pre_s,
            "attack_s": atk_s,
            "post_s": post_s,
            "run_duration_s": run_total,
            "flight_profile": "shared_mission",
            "mission_plan": C.MISSION_PLAN,
            "attack_after_wp": (schedule[0]["after_wp"] if schedule else None),
            "attack_wp": attack_wp,
            "attack_schedule": list(schedule),
            "attack_repeats": len(schedule),
            "n_attack_gates": len(schedule) if schedule else 0,
            "n_normal_gates": max(0, n_cand - len(schedule)) if schedule else None,
            "attack_seed": attack_seed,
            "phys_sample_hz": C.PHYS_SAMPLE_HZ,
            "physical_msgs": phys.n_msgs,
            "network_capture": bool(net),
            "t0_wall": t0,
            "label_scheme": {
                "label_phase": "normal_plan | attack",
                "attack_active": "1 only while under attack",
                "label_binary": "0 normal plan / 1 under attack",
                "label_class": "benign | <attack>  (pre+post = benign)",
                "note": "Pre and post fly the shared normal plan and are "
                        "labeled benign. Only the attack window is attack.",
            },
        }
        (run_dir / "metadata.json").write_text(json.dumps(meta_out, indent=2))
        try:
            import build_dataset as _bd
            _bd.annotate_run_dir(run_dir, meta_out)
        except Exception as exc:  # noqa: BLE001
            log("orch", f"label annotate warning: {exc}")

        # 5. wind down — twin bridge follows smooth land → then home reset
        try:
            if stop_sitl_after:
                ssh.stop_sitl()
                hooks.state(phase="sitl_stopped", scenario=scenario)
            else:
                _land_disarm_reset(hooks)
                hooks.state(phase="sitl_ready", scenario=scenario, reused=True)
        finally:
            if twin is not None:
                twin.stop()

        hooks.state(phase="done", scenario=scenario, run=run_idx,
                    run_name=run_name,
                    attack_start_rel=attack_start, attack_end_rel=attack_end,
                    post_end_rel=meta_out.get("post_end_rel"),
                    physical_msgs=phys.n_msgs, run_dir=str(run_dir))
        return run_dir
    finally:
        if hooks.on_log:
            mav_common.remove_log_sink(hooks.on_log)


def _next_run_idx(scenario: str) -> int:
    base = C.RUNS_DIR / scenario
    idx = 0
    while (base / f"run_{idx:02d}").exists():
        idx += 1
    return idx


def run_multi_attack_tour(net_ok: bool, hooks: Optional[Hooks] = None,
                          seed: int | None = None,
                          reuse_sitl: bool = True,
                          stop_sitl_after: bool = False) -> Path:
    """One continuous mission with every Tier-A attack at random waypoints.

    Used to evaluate Defense ON vs OFF on a single flight. Schedule is written
    into metadata for reproducibility.
    """
    hooks = hooks or Hooks()
    clear_run_abort()
    if hooks.on_log:
        mav_common.add_log_sink(hooks.on_log)

    run_idx = _next_run_idx(scenario)
    run_name = f"run_{run_idx:02d}"
    run_dir = C.RUNS_DIR / scenario / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    schedule = C.build_random_attack_schedule(seed=seed)
    live_net = None
    twin = None
    pilot = None

    try:
        hooks.state(phase="sitl_starting", scenario=scenario, run=run_idx)
        if reuse_sitl and ssh.wait_ready(timeout=4):
            hooks.state(phase="sitl_ready", scenario=scenario, run=run_idx, reused=True)
        else:
            ssh.start_sitl()
            if not ssh.wait_ready(timeout=150):
                hooks.state(phase="error", message="SITL not ready")
                return run_dir
            hooks.state(phase="sitl_ready", scenario=scenario, run=run_idx)
        if not _ensure_command_link(hooks):
            return run_dir

        phys = PhysicalRecorder(run_dir, on_sample=hooks.on_phys)
        net = NetworkRecorder(run_dir) if net_ok else None
        if net:
            net.start()
        if net_ok and hooks.on_net:
            from recorders.live_network import LiveNetworkSniffer
            live_net = LiveNetworkSniffer(on_window=hooks.on_net)
            live_net.start()
        phys.start()
        t0 = time.time()

        run_total = float(C.multi_attack_tour_duration_s(len(schedule)))
        hooks.state(phase="recording", scenario=scenario, run=run_idx,
                    run_name=run_name, duration_s=run_total,
                    profile="multi_attack_tour", is_attack=True, t0_wall=t0,
                    mission_plan=C.MISSION_PLAN, attack_schedule=schedule)
        log("orch", f"MULTI-ATTACK TOUR ({len(schedule)} injections): "
                    + ", ".join(f"{e['wp_id']}→{e['attack']}" for e in schedule))

        windows = []

        def _on_wp(idx, wp, hint):
            hooks.state(phase="mission_wp", scenario=scenario,
                        wp_idx=idx, wp_id=wp["id"],
                        x=wp["x"], y=wp["y"], z=wp["z"], hint=hint)

        pilot = BenignPilot(on_wp=_on_wp)
        _register_pilot(pilot)
        defended = _defense_on()
        pilot.start_multi_attack_tour(schedule, land_at_end=False,
                                       pass_through_gates=defended)

        for entry in schedule:
            if hooks.stopped():
                break
            aid = entry["attack"]
            gate_ok = pilot.wait_attack_gate(timeout=120)
            if not gate_ok or hooks.stopped():
                log("orch", f"gate timeout/stop before {aid}")
                break
            meta = ATTACKS.get(aid)
            if not meta:
                pilot.resume_after_attack()
                continue
            a0 = time.time() - t0
            if defended:
                try:
                    from ids.defense import DEFENSE_MODE
                    mode = str(DEFENSE_MODE or "hybrid").lower()
                except Exception:
                    mode = "hybrid"
                burst = min(float(C.ATTACK_DUR_S), 8.0 if mode == "hybrid" else 3.0)
                log("orch", f"TOUR FIRE '{aid}' after {entry['wp_id']} @ t={a0:.1f}s "
                            f"async {burst:.1f}s (defended {mode})")
                hooks.state(phase="attack", scenario=aid,
                            attack_start_rel=a0,
                            title=meta.get("title", aid),
                            effect=meta.get("effect", ""),
                            attack_wp=entry["wp_id"],
                            tour=True)
                if mode in ("proactive", "prevent"):
                    try:
                        from ids.mav_gateway import get_gateway
                        gw = get_gateway()
                        gw.set_mode(mode)
                        gw.set_defense_enabled(True)
                        gw.arm_drop_policy(aid, reason="orch_tour_preemptive")
                    except Exception:
                        pass
                    abort_delay = max(0.8, burst - 0.15)
                else:
                    try:
                        from ids.mav_gateway import get_gateway
                        get_gateway().set_mode(mode)
                    except Exception:
                        pass
                    abort_delay = max(2.5, burst * 0.55)
                try:
                    from ids.defense import _ABORT
                    _ABORT.clear()
                except Exception:
                    pass
                time.sleep(0.05)
                _fire_attack_async(meta["fn"], burst, log)

                def _proactive_abort(delay=abort_delay, hold=burst, sc=aid):
                    time.sleep(delay)
                    try:
                        from ids.defense import _ABORT
                        from ids.mav_gateway import get_gateway
                        get_gateway().arm_drop_policy(sc, reason="orch_timeout_arm")
                        _ABORT.set()
                        time.sleep(max(0.5, hold - delay))
                        _ABORT.clear()
                    except Exception:
                        pass
                threading.Thread(target=_proactive_abort, daemon=True).start()
                pilot.consume_attack_gate()
                _end_attack_window_later(
                    hooks, scenario=aid, t0=t0, entry=entry,
                    idx=0, total=len(schedule), windows=windows,
                    post_s=0.0, delay_s=burst + 0.15,
                    start_rel=a0, tour=True)
                continue

            hard = aid not in ("gps_spoofing",)
            pilot.freeze_for_attack(hard=hard)
            if aid == "gps_spoofing":
                drift = float(getattr(C, "GPS_SPOOF_DRIFT", 3e-5))
                v_walk = drift * 111320.0
                pilot.set_nav_bias_rate(v_walk, v_walk)
            log("orch", f"TOUR FIRE '{aid}' after {entry['wp_id']} @ t={a0:.1f}s "
                        f"({'hard-freeze' if hard else 'unprotected GPS'})")
            hooks.state(phase="attack", scenario=aid,
                        attack_start_rel=a0,
                        title=meta.get("title", aid),
                        effect=meta.get("effect", ""),
                        attack_wp=entry["wp_id"],
                        tour=True, unprotected=True)
            time.sleep(0.15)
            meta["fn"](float(C.ATTACK_DUR_S), log)
            a1 = time.time() - t0
            windows.append({"attack": aid, "wp_id": entry["wp_id"],
                            "after_wp": entry["after_wp"],
                            "start_rel": a0, "end_rel": a1})
            if aid == "gps_spoofing":
                pilot.clear_nav_bias(reset_offset=False)
            hooks.state(phase="post_attack", scenario=aid,
                        attack_end_rel=a1, attack_wp=entry["wp_id"], tour=True)
            pilot.resume_after_attack()

        wait_extra = 0.0 if defended else float(C.ATTACK_DUR_S) * len(schedule)
        _wait_mission_interruptible(
            pilot, hooks, C.mission_duration_s() + wait_extra + 60)
        run_total = time.time() - t0

        hooks.state(phase="landing", scenario=scenario)
        twin = None
        from recorders.twin_bridge import handoff_phys_to_twin
        twin = handoff_phys_to_twin(phys, hooks.on_phys, t0)
        if live_net:
            live_net.stop()
        if net:
            net.stop()
        if twin is not None:
            log("orch", "twin bridge live for landing follow-through")
        elif hooks.on_phys is not None:
            log("orch", "twin bridge could not bind 14550 — DT may freeze during land")

        if pilot is not None:
            try:
                if not hooks.stopped():
                    pilot._stream = False
                    pilot._freeze = True
                    try:
                        pilot.mav.set_mode("AUTO_LAND")
                        time.sleep(0.1)
                        pilot.mav.set_mode("AUTO_LAND")
                        pilot.mav.land()
                    except Exception:
                        pass
            except Exception as exc:  # noqa: BLE001
                log("orch", f"begin-land warning: {exc}")
            try:
                pilot.abort_now()
                pilot.close()
            except Exception:
                pass
            _register_pilot(None)
            pilot = None

        meta_out = {
            "scenario": scenario,
            "run": run_idx,
            "is_attack": True,
            "attack_schedule": schedule,
            "attack_windows": windows,
            "run_duration_s": run_total,
            "flight_profile": "multi_attack_tour",
            "mission_plan": C.MISSION_PLAN,
            "physical_msgs": phys.n_msgs,
            "network_capture": bool(net),
            "t0_wall": t0,
            "seed": seed,
        }
        (run_dir / "metadata.json").write_text(json.dumps(meta_out, indent=2))

        try:
            if stop_sitl_after:
                ssh.stop_sitl()
                hooks.state(phase="sitl_stopped", scenario=scenario)
            else:
                _land_disarm_reset(hooks)
                hooks.state(phase="sitl_ready", scenario=scenario, reused=True)
        finally:
            if twin is not None:
                twin.stop()

        hooks.state(phase="done", scenario=scenario, run=run_idx,
                    run_name=run_name, attack_windows=windows,
                    physical_msgs=phys.n_msgs, run_dir=str(run_dir))
        return run_dir
    finally:
        if hooks.on_log:
            mav_common.remove_log_sink(hooks.on_log)


def run_pipeline(runs: int, scenarios: Optional[list], net_ok: bool,
                 hooks: Optional[Hooks] = None) -> dict:
    """Run the full matrix (scenarios x runs) then build the labeled datasets.

    Designed for the dashboard's one-click flow: keeps Gazebo warm between runs
    and resets the vehicle to home (0,0) after each recording so the next
    scenario can arm/takeoff immediately. Stops the sim after datasets are built.
    """
    hooks = hooks or Hooks()
    if hooks.on_log:
        mav_common.add_log_sink(hooks.on_log)
    scen_list = scenarios if scenarios else pipeline_scenario_ids(
        getattr(C, "PIPELINE_SCOPE_DEFAULT", "core"))
    total = len(scen_list) * runs
    done = 0
    try:
        C.RUNS_DIR.mkdir(parents=True, exist_ok=True)
        log("orch", f"PIPELINE start: {len(scen_list)} scenarios x {runs} "
                    f"run(s) = {total} runs, then preprocess "
                    f"(scope={'custom' if scenarios else getattr(C,'PIPELINE_SCOPE_DEFAULT','core')})")
        hooks.state(phase="pipeline_start", total=total, runs=runs,
                    scenarios=scen_list, done=0)
        for scenario in scen_list:
            for _ in range(runs):
                if hooks.stopped():
                    log("orch", "PIPELINE stopped by user")
                    hooks.state(phase="pipeline_stopped", done=done, total=total)
                    return {"stopped": True, "done": done, "total": total}
                idx = _next_run_idx(scenario)
                hooks.state(phase="pipeline_progress", scenario=scenario,
                            run=idx, done=done, total=total)
                # keep Gazebo warm; reset to home (0,0) after each run
                run_scenario(scenario, idx, net_ok, hooks=hooks,
                             reuse_sitl=True, stop_sitl_after=False)
                done += 1
                hooks.state(phase="pipeline_progress", scenario=scenario,
                            run=idx, done=done, total=total)

        # preprocess / merge into labeled ML-ready datasets
        log("orch", "PIPELINE building merged + labeled datasets…")
        hooks.state(phase="pipeline_build", done=done, total=total)
        import build_dataset
        summary = build_dataset.build()
        for f in summary["files"]:
            log("orch", f"  {f['name']}: {f['rows']} rows, {f['cols']} cols")

        # task complete — keep Gazebo warm for the next click (intentional).
        # Operators who want a full shutdown can use the dashboard Stop button.
        hooks.state(phase="pipeline_done", done=done, total=total,
                    datasets=summary)
        try:
            ssh.ensure_gzclient()
        except Exception:
            pass
        hooks.state(phase="sitl_ready", reused=True)
        log("orch", "PIPELINE complete. Datasets written to datasets/. "
                    "Gazebo kept warm.")
        return {"stopped": False, "done": done, "total": total,
                "datasets": summary}
    finally:
        if hooks.on_log:
            mav_common.remove_log_sink(hooks.on_log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=None,
                    help="comma list of scenarios (overrides --scope)")
    ap.add_argument("--scope", default=None,
                    choices=["core", "all", "attacks", "benign"],
                    help="research scope: core=benign+Tier A (default)")
    ap.add_argument("--runs", type=int, default=1, help="runs per scenario")
    ap.add_argument("--no-network", action="store_true", help="skip pcap capture")
    ap.add_argument("--profile", choices=["mission", "hover"], default=None,
                    help="flight profile (default: config.FLIGHT_PROFILE)")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = ap.parse_args()

    if args.profile:
        C.FLIGHT_PROFILE = args.profile
    log("orch", f"flight profile: {C.FLIGHT_PROFILE}")

    if args.list:
        print("Tier A (core):")
        print(f"  {'benign':22s} baseline  {BENIGN_META['desc'][:50]}")
        for s in core_attack_ids():
            m = ATTACKS[s]
            pnt = "".join(k for k, v in m.get("effects", {}).items() if v)
            print(f"  {s:22s} [{pnt}] {m.get('title')}")
        print("Tier B (support):")
        from attacks.suite import support_attack_ids
        for s in support_attack_ids():
            m = ATTACKS[s]
            pnt = "".join(k for k, v in m.get("effects", {}).items() if v)
            print(f"  {s:22s} [{pnt}] {m.get('title')}")
        return

    if args.scenarios:
        scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    else:
        scope = args.scope or getattr(C, "PIPELINE_SCOPE_DEFAULT", "core")
        scenarios = pipeline_scenario_ids(scope)
        log("orch", f"scope={scope} → {scenarios}")

    if not preflight():
        return

    net_ok = (not args.no_network) and sudo_prime()
    if not net_ok:
        log("orch", "network capture DISABLED (physical layer only)")

    C.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    total = len(scenarios) * args.runs
    done = 0
    for scenario in scenarios:
        for i in range(args.runs):
            run_scenario(scenario, i, net_ok)
            done += 1
            log("orch", f"progress {done}/{total}")

    log("orch", "ALL RUNS COMPLETE. Build dataset with: python3 build_dataset.py")


if __name__ == "__main__":
    main()
