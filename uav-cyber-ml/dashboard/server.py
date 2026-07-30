"""UAV Digital-Twin dashboard backend (FastAPI + WebSocket).

Serves a rich single-page dashboard that:
  * drives any scenario (benign + every attack) on the real PX4 SITL,
  * streams live physical telemetry (for the 3D twin + graphs),
  * streams live network-layer features (per-second),
  * relays all orchestrator / pilot / attack logs,
  * lets you browse the recorded raw + processed datasets per scenario.

Run it with:  ./run_dashboard.sh   (primes sudo for tcpdump), then open
http://127.0.0.1:8000
"""

from __future__ import annotations

import asyncio
import subprocess
import threading
import time
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import config as C
import orchestrator as orch
import ssh_control as ssh
from attacks.suite import ATTACKS, BENIGN_META, pipeline_scenario_ids
from ids.live_bridge import LiveIDSEngine
from ids import online_train

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"

app = FastAPI(title="UAV Cyber Digital Twin")


# --------------------------------------------------------------------- bridge
class Bus:
    """Thread-safe -> asyncio bridge that fan-outs messages to websockets."""

    def __init__(self):
        self.loop: asyncio.AbstractEventLoop | None = None
        self.queue: asyncio.Queue | None = None
        self.clients: set[WebSocket] = set()

    def bind(self, loop):
        self.loop = loop
        self.queue = asyncio.Queue(maxsize=4000)

    def publish(self, msg: dict):
        """Called from any thread."""
        if self.loop is None or self.queue is None:
            return
        try:
            self.loop.call_soon_threadsafe(self._put, msg)
        except RuntimeError:
            pass

    def _put(self, msg):
        try:
            self.queue.put_nowait(msg)
        except asyncio.QueueFull:
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(msg)
            except Exception:
                pass


bus = Bus()
ids_engine = LiveIDSEngine(publish=bus.publish)

# ------------------------------------------------------------------ sim mgr
class SimControl:
    """Tracks + controls the PX4 SITL lifecycle on the UAV, independent of runs.

    A background monitor probes the vehicle while idle so the UI always shows an
    accurate simulator status (offline / booting / ready / airborne / busy).
    """

    def __init__(self):
        self.status = "unknown"          # unknown|offline|booting|ready|airborne|busy|stopping
        self._busy = False               # a run/pipeline owns the sim
        self._thread: threading.Thread | None = None
        self._io = threading.Lock()      # serialize passive 14550 probes

    def set_busy(self, busy: bool):
        self._busy = busy
        if busy:
            self._set("busy")

    def _set(self, status: str):
        if status != self.status:
            self.status = status
            bus.publish({"type": "sim", "status": status})

    def start(self) -> tuple[bool, str]:
        if self._busy:
            return False, "simulator is in use by a run"
        if self._thread and self._thread.is_alive():
            return False, "simulator is already (re)starting"

        def _boot():
            self._set("booting")
            bus.publish({"type": "log", "tag": "sim",
                         "msg": "booting PX4 SITL + Gazebo…", "ts": time.time()})
            ssh.start_sitl()
            ok = ssh.wait_ready(timeout=150)
            gui = ssh.ensure_gzclient()
            pt = ssh.pt_status()
            self._set("ready" if ok else "offline")
            bus.publish({"type": "log", "tag": "sim",
                         "msg": (("simulator ready" if ok else "simulator failed to start")
                                 + f" · PT gui={gui} gzclient={pt.get('gzclient', 0)}"),
                         "ts": time.time()})
            bus.publish({"type": "pt", "data": pt})

        self._thread = threading.Thread(target=_boot, daemon=True)
        self._thread.start()
        return True, "starting"

    def stop(self) -> tuple[bool, str]:
        if self._busy:
            return False, "cannot stop: a run is in progress"

        def _kill():
            self._set("stopping")
            bus.publish({"type": "log", "tag": "sim",
                         "msg": "shutting simulator down…", "ts": time.time()})
            ssh.stop_sitl()
            self._set("offline")

        threading.Thread(target=_kill, daemon=True).start()
        return True, "stopping"

    def refresh(self):
        """Guarded, one-shot passive status probe. Safe only while idle.

        We deliberately do NOT run a continuous background probe: binding 14550
        or touching the command link while a run needs it caused PX4's link to
        become unreliable. Status is otherwise kept accurate via run lifecycle
        events (busy / ready / offline)."""
        def _go():
            if self._busy or (self._thread and self._thread.is_alive()):
                return
            if self.status in ("booting", "stopping"):
                return
            if not self._io.acquire(blocking=False):
                return
            try:
                if not orch.port_free(C.GCS_PORT):
                    return  # 14550 in use (a run/QGC) — don't interfere
                alive, grounded, _, _ = orch.probe_vehicle(timeout=4.0)
                self._set("ready" if grounded else
                          "airborne" if alive else "offline")
                # Keep Physical Twin GUI alive whenever PX4/gzserver are up.
                if alive:
                    gui = ssh.ensure_gzclient()
                    pt = ssh.pt_status()
                    bus.publish({"type": "pt", "data": pt})
                    if not pt.get("gui"):
                        bus.publish({
                            "type": "log", "tag": "pt",
                            "msg": f"Physical Twin GUI missing — gzclient={gui}",
                            "ts": time.time(),
                        })
            except Exception:
                pass
            finally:
                self._io.release()

        threading.Thread(target=_go, daemon=True).start()


sim = SimControl()


# ------------------------------------------------------------------- run mgr
class RunManager:
    def __init__(self):
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.status = "idle"          # idle | running
        self.mode = "idle"            # idle | run | pipeline
        self.current: dict = {}

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def request_stop(self):
        self._stop.set()
        try:
            orch.request_run_abort(reason="dashboard_stop")
        except Exception:
            pass
        bus.publish({
            "type": "log", "tag": "dashboard",
            "msg": "stop requested — aborting mission…",
            "ts": time.time(),
        })
        bus.publish({"type": "state", "data": {"phase": "stopping",
                                               "message": "stop requested"}})

    def _hooks(self) -> "orch.Hooks":
        def _on_phys(d):
            bus.publish({"type": "phys", "data": d})
            try:
                ids_engine.on_phys(d)
            except Exception:
                pass

        def _on_net(d):
            bus.publish({"type": "net", "data": d})
            try:
                ids_engine.on_net(d)
            except Exception:
                pass

        def _on_state(d):
            bus.publish({"type": "state", "data": d})
            # Arm IDS buffers when recording starts; keep scoring through attack.
            phase = (d or {}).get("phase")
            if phase == "recording":
                ids_engine.begin_run()
            try:
                ids_engine.set_ground_truth(phase or "", (d or {}).get("scenario"))
            except Exception:
                pass

        return orch.Hooks(
            on_log=lambda tag, msg: bus.publish(
                {"type": "log", "tag": tag, "msg": msg, "ts": time.time()}),
            on_phys=_on_phys,
            on_net=_on_net,
            on_state=_on_state,
            should_stop=self._stop.is_set,
        )

    def _preconditions(self, network: bool) -> tuple[bool, str, bool]:
        if self.running:
            return False, "a run is already in progress", False
        # Fail fast: without the UAV PC there is no PT and no DT telemetry.
        try:
            ok_uav, msg_uav = ssh.uav_reachable()
        except Exception as exc:  # noqa: BLE001
            ok_uav, msg_uav = False, f"Physical Twin check failed: {exc}"
        if not ok_uav:
            return False, msg_uav, False
        if not orch.port_free(C.GCS_PORT):
            return False, (f"UDP {C.GCS_PORT} is busy — close QGroundControl or a "
                           "stale recorder, then retry"), False
        if bool(network) and not _sudo_ready():
            # network capture needs tcpdump (sudo). Fail loudly instead of
            # silently recording physical-only, since both layers are required.
            return False, (
                "network capture needs sudo for tcpdump, but it is not primed. "
                "Enable passwordless capture with:\n"
                "  ./scripts/enable_network_capture.sh\n"
                "or relaunch the dashboard via ./run_dashboard.sh (prompts once). "
                "Uncheck 'Network capture' to record physical-only."), False
        return True, "", bool(network)

    def start(self, scenario: str, profile: str, network: bool) -> tuple[bool, str]:
        if scenario != "benign" and scenario not in ATTACKS:
            return False, f"unknown scenario '{scenario}'"
        ok, msg, net_ok = self._preconditions(network)
        if not ok:
            return False, msg
        if profile in ("mission", "hover"):
            C.FLIGHT_PROFILE = profile
        attack_seed = None
        attack_schedule = []
        if scenario != "benign":
            attack_seed = int(time.time() * 1000) % 2_000_000_000
            attack_schedule = C.build_repeated_attack_schedule(
                scenario, seed=attack_seed)

        self._stop.clear()
        self.status = "running"
        self.mode = "run"
        self.current = {"scenario": scenario, "profile": C.FLIGHT_PROFILE,
                        "network": net_ok, "started": time.time(),
                        "schedule": attack_schedule, "attack_seed": attack_seed}
        hooks = self._hooks()
        # If Gazebo is cold, kick a boot before marking busy so SimControl.start
        # is allowed; orch will reuse when ready.
        if sim.status not in ("ready", "airborne", "booting"):
            try:
                sim.start()
            except Exception:
                pass
        sim.set_busy(True)

        def _worker():
            try:
                idx = orch._next_run_idx(scenario)
                # Reuse warm Gazebo when the vehicle is already at home; after
                # the run land + teleport to (0,0) so the next click is fast.
                orch.run_scenario(scenario, idx, net_ok, hooks=hooks,
                                  reuse_sitl=True, stop_sitl_after=False,
                                  attack_schedule=attack_schedule,
                                  attack_seed=attack_seed)
            except Exception as exc:  # noqa: BLE001
                _report_error(exc)
            finally:
                self._finish(scenario)

        self.thread = threading.Thread(target=_worker, daemon=True)
        self.thread.start()
        return True, "started"

    def start_multi_tour(self, network: bool, seed: int | None = None) -> tuple[bool, str]:
        ok, msg, net_ok = self._preconditions(network)
        if not ok:
            return False, msg
        self._stop.clear()
        self.status = "running"
        self.mode = "multi_tour"
        self.current = {"scenario": "multi_attack_tour", "network": net_ok,
                        "seed": seed, "started": time.time()}
        hooks = self._hooks()
        sim.set_busy(True)

        def _worker():
            try:
                orch.run_multi_attack_tour(net_ok, hooks=hooks, seed=seed,
                                           reuse_sitl=True, stop_sitl_after=False)
            except Exception as exc:  # noqa: BLE001
                _report_error(exc)
            finally:
                self._finish("multi_attack_tour")

        self.thread = threading.Thread(target=_worker, daemon=True)
        self.thread.start()
        return True, "started"

    def start_pipeline(self, runs_per: int, scenarios: list | None,
                       network: bool) -> tuple[bool, str]:
        ok, msg, net_ok = self._preconditions(network)
        if not ok:
            return False, msg
        runs_per = max(1, min(int(runs_per or 1), 50))

        self._stop.clear()
        self.status = "running"
        self.mode = "pipeline"
        self.current = {"pipeline": True, "runs": runs_per,
                        "scenarios": scenarios or "all", "network": net_ok,
                        "started": time.time()}
        hooks = self._hooks()
        sim.set_busy(True)

        def _worker():
            try:
                orch.run_pipeline(runs_per, scenarios, net_ok, hooks=hooks)
            except Exception as exc:  # noqa: BLE001
                _report_error(exc)
            finally:
                self._finish("pipeline")

        self.thread = threading.Thread(target=_worker, daemon=True)
        self.thread.start()
        return True, "started"

    def _finish(self, scenario: str):
        self.status = "idle"
        self.mode = "idle"
        self.current = {}
        sim.set_busy(False)
        try:
            ids_engine.end_run()
        except Exception:
            pass
        # keep sim warm after single runs and pipelines (Stop button kills Gazebo)
        sim._set("ready")
        bus.publish({"type": "run_end", "scenario": scenario})
        try:
            sim.refresh()
        except Exception:
            pass
        # If refresh thinks we're offline, re-warm in background.
        if sim.status in ("offline", "unknown", ""):
            def _rewarm():
                time.sleep(0.5)
                if not runs.running and sim.status not in ("ready", "airborne", "booting"):
                    bus.publish({"type": "log", "tag": "sim",
                                 "msg": "re-warming Gazebo after run…",
                                 "ts": time.time()})
                    sim.start()
            threading.Thread(target=_rewarm, daemon=True).start()
        # Live training: fine-tune on new runs + hot-reload for the next flight.
        if online_train.live_train_enabled() and scenario not in ("", "pipeline"):
            bus.publish({
                "type": "log", "tag": "train",
                "msg": "live train armed — refreshing primary TinyMAV 1D-CNN on new runs…",
                "ts": time.time(),
            })

            def _after(report):
                if report and report.get("ok"):
                    try:
                        ids_engine.reload_models()
                    except Exception as exc:  # noqa: BLE001
                        bus.publish({
                            "type": "log", "tag": "train",
                            "msg": f"model reload failed: {exc}",
                            "ts": time.time(),
                        })

            online_train.retrain_async(publish=bus.publish, on_done=_after)
        elif online_train.live_train_enabled() and scenario == "pipeline":
            # Pipeline already built datasets at the end — still fine-tune once.
            def _after(report):
                if report and report.get("ok"):
                    try:
                        ids_engine.reload_models()
                    except Exception:
                        pass
            online_train.retrain_async(publish=bus.publish, on_done=_after)


def _report_error(exc: Exception):
    bus.publish({"type": "log", "tag": "dashboard",
                 "msg": f"run error: {exc}", "ts": time.time()})
    bus.publish({"type": "state", "data": {"phase": "error",
                                           "message": str(exc)}})


runs = RunManager()


def _tcpdump_bin() -> str:
    import shutil
    return shutil.which("tcpdump") or "/usr/sbin/tcpdump"


def _sudo_ready() -> bool:
    """True if tcpdump can run under sudo without a password prompt.

    Passes when either the sudo timestamp is cached (run_dashboard.sh) OR a
    scoped NOPASSWD rule permits tcpdump (scripts/enable_network_capture.sh).
    """
    return subprocess.run(["sudo", "-n", _tcpdump_bin(), "--version"],
                          capture_output=True).returncode == 0


# ---------------------------------------------------------------- lifecycle
@app.on_event("startup")
async def _startup():
    bus.bind(asyncio.get_running_loop())
    asyncio.create_task(_broadcaster())
    sim.refresh()   # one-shot: detect a sim that is already running
    bus.publish({"type": "log", "tag": "ids",
                 "msg": ("cascade IDS ready (" + ", ".join(
                             ids_engine.status().get("modalities") or []) + ")"
                         if ids_engine.ready else
                         "IDS unprotected: no trained model — attacks run without defence"),
                 "ts": time.time()})

    def _prewarm():
        # Boot SITL ASAP so the first scenario click does not wait on cold Gazebo.
        time.sleep(0.4)
        if sim._busy or sim.status in ("ready", "airborne", "busy", "booting"):
            return
        if not orch.port_free(C.GCS_PORT):
            # Port busy often means SITL is already up — just ensure GUI.
            try:
                ssh.ensure_gzclient()
                sim._set("ready")
            except Exception:
                pass
            return
        bus.publish({"type": "log", "tag": "sim",
                     "msg": "pre-warming simulator for faster arm/takeoff…",
                     "ts": time.time()})
        sim.start()

    threading.Thread(target=_prewarm, daemon=True).start()


async def _broadcaster():
    assert bus.queue is not None
    while True:
        msg = await bus.queue.get()
        dead = []
        for ws in list(bus.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            bus.clients.discard(ws)


# --------------------------------------------------------------------- API
@app.get("/api/scenarios")
def api_scenarios():
    def _item(sid: str, m: dict, is_attack: bool) -> dict:
        eff = m.get("effects") or {}
        return {
            "id": sid,
            "title": m.get("title", sid),
            "category": m.get("category", "Attack"),
            "desc": m.get("desc", ""),
            "effect": m.get("effect", ""),
            "needs_airborne": m.get("needs_airborne", False),
            "is_attack": is_attack,
            "tier": m.get("tier", "B"),
            "order": m.get("order", 999),
            "hypothesis": m.get("hypothesis", ""),
            "defense": m.get("defense", ""),
            "effects": {
                "P": bool(eff.get("P")),
                "N": bool(eff.get("N")),
                "T": bool(eff.get("T")),
            },
            "metrics": m.get("metrics") or [],
        }

    items = [_item("benign", BENIGN_META, False)]
    for sid, m in sorted(ATTACKS.items(), key=lambda kv: kv[1].get("order", 999)):
        items.append(_item(sid, m, True))
    return {
        "scenarios": items,
        "core_ids": pipeline_scenario_ids("core"),
        "pipeline_scope_default": getattr(C, "PIPELINE_SCOPE_DEFAULT", "core"),
        "profile": "shared_mission",
        "run_duration_s": C.RUN_DURATION_S,
        "attack_run_duration_s": C.attack_run_duration_s(),
        "pre_attack_s": C.mission_pre_duration_s(),
        "attack_dur_s": C.ATTACK_DUR_S,
        "post_attack_s": C.mission_post_duration_s(),
        "attack_at_s": C.ATTACK_AT_S,
        "attack_after_wp": C.ATTACK_AFTER_WP,
        "attack_repeats_per_run": C.attack_gates_per_run(),
        "attack_gate_fraction": getattr(C, "ATTACK_GATE_FRACTION", 0.5),
        "attack_gate_candidates": len(C.attack_gate_candidates()),
        "mission_plan": C.MISSION_PLAN,
        "mission_wp_count": len(C.MISSION_PLAN),
        "multi_tour_duration_s": C.multi_attack_tour_duration_s(),
        "phys_hz": C.PHYS_SAMPLE_HZ,
        "uav_host": C.UAV_HOST,
        "gps_spoof_drift": getattr(C, "GPS_SPOOF_DRIFT", 1e-5),
        "case_studies": "/CASE_STUDIES.md",
    }


@app.get("/api/state")
def api_state():
    return {"status": runs.status, "mode": runs.mode, "current": runs.current,
            "sim": sim.status, "sudo": _sudo_ready(),
            "port_free": orch.port_free(C.GCS_PORT),
            "pt": ssh.pt_status(),
            "ids": {**ids_engine.status(),
                    "live_train": online_train.training_status()}}


@app.get("/api/ids")
def api_ids():
    st = ids_engine.status()
    st["live_train"] = online_train.training_status()
    try:
        from ids.mav_gateway import get_gateway
        st["gateway"] = get_gateway().status()
        st["defense_mode"] = st.get("defense_mode") or get_gateway()._mode
    except Exception:
        st["gateway"] = {"running": False}
    return st


@app.post("/api/ids")
async def api_ids_set(payload: dict):
    if "enabled" in payload:
        ids_engine.set_enabled(bool(payload["enabled"]))
    if "defense_enabled" in payload:
        ids_engine.set_defense_enabled(bool(payload["defense_enabled"]))
    if "defense_mode" in payload:
        mode = str(payload["defense_mode"]).strip().lower()
        import config as _C
        _C.DEFENSE_MODE = mode
        try:
            from ids import defense as _def
            _def.DEFENSE_MODE = mode
            from ids.mav_gateway import get_gateway
            get_gateway().set_mode(mode)
        except Exception:
            pass
        bus.publish({
            "type": "log", "tag": "defense",
            "msg": f"Defense mode set to {mode}",
            "ts": time.time(),
        })
    if "live_train" in payload:
        online_train.set_live_train(bool(payload["live_train"]))
        bus.publish({
            "type": "log", "tag": "train",
            "msg": ("Live train ON — models fine-tune on new runs after each SITL run"
                    if online_train.live_train_enabled() else
                    "Live train OFF"),
            "ts": time.time(),
        })
    if payload.get("reload"):
        ids_engine.reload_models()
    if payload.get("retrain_now"):
        def _after(report):
            if report and report.get("ok"):
                try:
                    ids_engine.reload_models()
                except Exception:
                    pass
        online_train.retrain_async(publish=bus.publish, on_done=_after)
    parts = [
        f"IDS {'enabled' if ids_engine.enabled else 'disabled'}",
        f"Defense {'ON' if ids_engine.status().get('defense_enabled') else 'OFF'}",
        f"LiveTrain {'ON' if online_train.live_train_enabled() else 'OFF'}",
    ]
    if ids_engine.ready:
        parts.append(f"modalities={sorted(ids_engine.models)}")
    else:
        parts.append(f"offline ({ids_engine.load_error})")
    bus.publish({"type": "log", "tag": "ids",
                 "msg": " · ".join(parts),
                 "ts": time.time()})
    st = ids_engine.status()
    st["live_train"] = online_train.training_status()
    try:
        from ids.mav_gateway import get_gateway
        st["gateway"] = get_gateway().status()
        st["defense_mode"] = st.get("defense_mode") or get_gateway()._mode
    except Exception:
        st["gateway"] = {"running": False}
    return st


@app.get("/api/train")
def api_train_status():
    return online_train.training_status()


@app.post("/api/train")
async def api_train(payload: dict | None = None):
    payload = payload or {}
    if "live_train" in payload:
        online_train.set_live_train(bool(payload["live_train"]))
    if payload.get("retrain_now"):
        def _after(report):
            if report and report.get("ok"):
                try:
                    ids_engine.reload_models()
                except Exception:
                    pass
        online_train.retrain_async(publish=bus.publish, on_done=_after)
        return {"ok": True, "message": "retrain started",
                **online_train.training_status()}
    return online_train.training_status()


@app.get("/api/pt")
def api_pt():
    """Physical Twin process health (PX4 + Gazebo server/GUI)."""
    ensure_msg = None
    pt = ssh.pt_status()
    if pt.get("px4", 0) > 0 and pt.get("gzserver", 0) > 0 and not pt.get("gui"):
        ensure_msg = ssh.ensure_gzclient()
        pt = ssh.pt_status()
    if ensure_msg is not None:
        pt["ensure"] = ensure_msg
    return pt


@app.post("/api/run")
async def api_run(payload: dict):
    scenario = payload.get("scenario", "benign")
    profile = payload.get("profile", C.FLIGHT_PROFILE)
    network = payload.get("network", True)
    ok, msg = runs.start(scenario, profile, network)
    return JSONResponse({"ok": ok, "message": msg}, status_code=200 if ok else 409)


@app.post("/api/multi-tour")
async def api_multi_tour(payload: dict):
    """Run extended mission with all Tier-A attacks at random waypoints."""
    network = payload.get("network", True)
    seed = payload.get("seed")
    try:
        seed = int(seed) if seed is not None else None
    except (TypeError, ValueError):
        seed = None
    ok, msg = runs.start_multi_tour(network, seed=seed)
    return JSONResponse({"ok": ok, "message": msg,
                         "schedule_preview": C.build_random_attack_schedule(seed=seed)},
                        status_code=200 if ok else 409)


@app.post("/api/setup-capture")
async def api_setup_capture(payload: dict):
    """Install a scoped NOPASSWD sudoers rule so tcpdump capture works.

    Accepts the user's Mac password once, runs a single `sudo -S` invocation
    (localhost-only dashboard), and enables passwordless tcpdump permanently.
    """
    import getpass
    import shlex
    import shutil
    if _sudo_ready():
        return JSONResponse({"ok": True, "message": "network capture already enabled"})
    password = (payload or {}).get("password", "")
    if not password:
        return JSONResponse({"ok": False, "message": "password required"},
                            status_code=400)
    tcpdump = _tcpdump_bin()
    pkill = shutil.which("pkill") or "/usr/bin/pkill"
    user = getpass.getuser()
    rule = f"{user} ALL=(root) NOPASSWD: {tcpdump}, /bin/kill, {pkill}\n"
    script = (
        "set -e; tmp=$(mktemp); "
        f"printf '%s' {shlex.quote(rule)} > \"$tmp\"; "
        "visudo -cf \"$tmp\"; "
        "install -m 0440 -o root -g wheel \"$tmp\" /etc/sudoers.d/uav-cyber-capture; "
        "rm -f \"$tmp\""
    )
    try:
        proc = subprocess.run(["sudo", "-S", "-p", "", "bash", "-c", script],
                              input=password + "\n", capture_output=True,
                              text=True, timeout=20)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "message": f"setup error: {exc}"},
                            status_code=500)
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        msg = err[-1] if err else "sudo rejected (wrong password?)"
        return JSONResponse({"ok": False, "message": msg}, status_code=400)
    ready = _sudo_ready()
    return JSONResponse({"ok": ready,
                         "message": "network capture enabled"
                         if ready else "installed but verification failed"})


@app.post("/api/pipeline")
async def api_pipeline(payload: dict):
    runs_per = payload.get("runs", 1)
    network = payload.get("network", True)
    profile = payload.get("profile", C.FLIGHT_PROFILE)
    if profile in ("mission", "hover"):
        C.FLIGHT_PROFILE = profile
    scope = payload.get("scope", getattr(C, "PIPELINE_SCOPE_DEFAULT", "core"))
    if isinstance(payload.get("scenarios"), list) and payload["scenarios"]:
        scenarios = payload["scenarios"]
    else:
        # core | all | attacks | benign  (default core = Tier A research set)
        scenarios = pipeline_scenario_ids(scope)
    ok, msg = runs.start_pipeline(runs_per, scenarios, network)
    return JSONResponse({"ok": ok, "message": msg, "scenarios": scenarios,
                         "scope": scope},
                        status_code=200 if ok else 409)


@app.post("/api/stop")
async def api_stop():
    runs.request_stop()
    return {"ok": True}


@app.post("/api/sim")
async def api_sim(payload: dict):
    action = payload.get("action", "status")
    if action == "start":
        ok, msg = sim.start()
    elif action == "stop":
        ok, msg = sim.stop()
    else:
        ok, msg = True, sim.status
    return JSONResponse({"ok": ok, "message": msg, "status": sim.status},
                        status_code=200 if ok else 409)


@app.get("/api/runs")
def api_runs():
    """List recorded runs on disk for the dataset browser."""
    import json
    out = []
    if C.RUNS_DIR.exists():
        for scen_dir in sorted(C.RUNS_DIR.iterdir()):
            if not scen_dir.is_dir():
                continue
            for run_dir in sorted(scen_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                meta = {}
                mp = run_dir / "metadata.json"
                if mp.exists():
                    try:
                        meta = json.loads(mp.read_text())
                    except Exception:
                        meta = {}
                wins = meta.get("attack_windows") or []
                out.append({
                    "scenario": scen_dir.name, "run": run_dir.name,
                    "attack_start_rel": meta.get("attack_start_rel"),
                    "attack_end_rel": meta.get("attack_end_rel"),
                    "n_attack_windows": len(wins) if wins else (
                        1 if meta.get("attack_start_rel") is not None else 0),
                    "n_attack_gates": meta.get("n_attack_gates"),
                    "n_normal_gates": meta.get("n_normal_gates"),
                    "is_attack": meta.get("is_attack", scen_dir.name != "benign"),
                    "physical_msgs": meta.get("physical_msgs"),
                    "has_network": (run_dir / "network_processed.csv").exists(),
                })
    return {"runs": out}


@app.get("/api/dataset")
def api_dataset(scenario: str, run: str, layer: str, kind: str):
    """Return named series for plotting a recorded CSV.

    layer in {physical, network}; kind in {raw, processed}.
    """
    from dashboard.datasets import load_series
    run_dir = C.RUNS_DIR / scenario / run
    try:
        return load_series(run_dir, layer, kind)
    except FileNotFoundError:
        return JSONResponse({"error": "file not found"}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


# ---------------------------------------------------------------- websocket
@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    bus.clients.add(ws)
    try:
        await ws.send_json({"type": "hello", "status": runs.status,
                            "mode": runs.mode, "sim": sim.status,
                            "current": runs.current,
                            "pt": ssh.pt_status(),
                            "ids": {**ids_engine.status(),
                                    "live_train": online_train.training_status()}})
        while True:
            await ws.receive_text()  # keepalive / ignore
    except WebSocketDisconnect:
        pass
    finally:
        bus.clients.discard(ws)


# ------------------------------------------------------------------- static
@app.get("/CASE_STUDIES.md")
def case_studies_md():
    p = getattr(C, "CASE_STUDIES_PATH", C.ROOT / "CASE_STUDIES.md")
    if not Path(p).exists():
        return JSONResponse({"error": "missing"}, status_code=404)
    return FileResponse(p, media_type="text/markdown")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
