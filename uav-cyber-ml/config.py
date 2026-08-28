"""Central configuration for the Mac-driven UAV cyber-range."""

from __future__ import annotations

import os
from pathlib import Path

# ---- UAV machine (PX4 SITL host) ----
UAV_HOST = os.environ.get("UAV_HOST", "192.168.123.130")
SSH_USER = os.environ.get("UAV_SSH_USER", "danish")
TESTBED_DIR = "~/uav_cyber_testbed"

# ---- MAVLink ports on the UAV (bound to 0.0.0.0, reachable from Mac) ----
GCS_API_PORT = 18570   # onboard GCS API: attacks + telemetry stream requests
GCS_PORT = 14550       # normal GCS (used by QGroundControl)
OFFBOARD_PORT = 14580  # offboard API
RX_PORT = 14540        # telemetry
XRCE_PORT = 8888
# Stable Mac UDP *source* ports for command links (avoids PX4 sticky-peer stalls)
GCS_API_LOCAL_PORT = int(os.environ.get("GCS_API_LOCAL_PORT", "19070"))
# Proactive MAVLink gateway (Mac-local). Lab TX → gateway → UAV:GCS_PORT.
# Set MAV_GATEWAY=0 to bypass (direct udpout to PX4, reactive-only).
MAV_GATEWAY_ENABLED = os.environ.get("MAV_GATEWAY", "1").strip() not in ("0", "false", "off")
MAV_GATEWAY_PORT = int(os.environ.get("MAV_GATEWAY_PORT", "19550"))
MAV_GATEWAY_HOST = os.environ.get("MAV_GATEWAY_HOST", "127.0.0.1")

# PX4 identity
PX4_SYSID = 1
PX4_COMPID = 1

# Mac-side spoofed identities
RECORDER_SYSID = 254
CONTROLLER_SYSID = 252   # benign flight controller
ATTACKER_SYSID = 250
DEFENDER_SYSID = 249     # IPS / recovery GCS (trusted)
# ---- Recording ----
PHYS_SAMPLE_HZ = 20.0           # processed physical feature rate (dataset CSV) — 2×
STREAM_REQUEST_HZ = 50          # legacy data stream rate requested from PX4
TWIN_STREAM_HZ = 60             # high-rate telemetry from PX4 (SET_MESSAGE_INTERVAL) — 2×
LIVE_EMIT_HZ = 60.0             # live twin/graph push rate (dashboard only) — 2×
def _detect_iface(host: str) -> str:
    """Pick the interface that actually routes to the UAV.

    macOS tcpdump does not reliably support ``-i any`` (BPF-based capture),
    so we resolve the concrete interface (e.g. ``en0``) toward the UAV host.
    Linux (including WSL2) uses ``ip route get`` instead of BSD ``route get``.
    """
    import platform
    import subprocess
    system = platform.system()
    try:
        if system == "Linux":
            out = subprocess.run(["ip", "route", "get", host], capture_output=True,
                                 text=True, timeout=3).stdout
            for line in out.splitlines():
                tokens = line.split()
                if "dev" in tokens:
                    return tokens[tokens.index("dev") + 1]
        else:
            out = subprocess.run(["route", "get", host], capture_output=True,
                                 text=True, timeout=3).stdout
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("interface:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "eth0" if system == "Linux" else "en0"


# tcpdump interface on the Mac (auto-detected toward the UAV; override via env)
NET_IFACE = os.environ.get("NET_IFACE") or _detect_iface(UAV_HOST)

# ---- Shared mission plan (identical for benign AND every attack) ----
# Local-NED: x=North, y=East, z=altitude-up (m). Every scenario flies this
# same multi-point plan; attacks only pause mid-plan so pre/post compare
# the same route — only the attack effect differs.
FLIGHT_PROFILE = os.environ.get("FLIGHT_PROFILE", "mission")
CRUISE_ALT = 4.0
WP_DWELL_S = 4.0  # legacy default (overridden per-leg below)

MISSION_PLAN = [
    # id, north(x), east(y), alt_up(z), dwell_s (fly+hold budget)
    {"id": "WP0_CLIMB", "x": 0.0,   "y": 0.0,   "z": 4.0, "dwell_s": 6.0},
    {"id": "WP1_NORTH", "x": 28.0,  "y": 0.0,   "z": 5.0, "dwell_s": 8.0},
    {"id": "WP2_NE",    "x": 28.0,  "y": 22.0,  "z": 6.0, "dwell_s": 8.0},
    {"id": "WP3_EAST",  "x": 8.0,   "y": 26.0,  "z": 5.5, "dwell_s": 8.0},
    {"id": "WP4_SE",    "x": -12.0, "y": 22.0,  "z": 5.0, "dwell_s": 8.0},
    {"id": "WP5_SOUTH", "x": -22.0, "y": 6.0,   "z": 5.0, "dwell_s": 8.0},
    {"id": "WP6_SW",    "x": -16.0, "y": -16.0, "z": 5.5, "dwell_s": 8.0},
    {"id": "WP7_WEST",  "x": 4.0,   "y": -22.0, "z": 5.0, "dwell_s": 8.0},
    {"id": "WP8_NW",    "x": 20.0,  "y": -10.0, "z": 5.0, "dwell_s": 8.0},
    # ---- second lap (doubled shared plan) ----
    {"id": "WP9_N_EXT",  "x": 34.0,  "y": 4.0,   "z": 5.5, "dwell_s": 8.0},
    {"id": "WP10_NE_EXT", "x": 30.0, "y": 30.0,  "z": 6.0, "dwell_s": 8.0},
    {"id": "WP11_E_EXT", "x": 2.0,   "y": 34.0,  "z": 6.0, "dwell_s": 8.0},
    {"id": "WP12_SE_EXT", "x": -26.0, "y": 28.0, "z": 5.5, "dwell_s": 8.0},
    {"id": "WP13_S_EXT", "x": -32.0, "y": 2.0,   "z": 5.0, "dwell_s": 8.0},
    {"id": "WP14_SW_EXT", "x": -24.0, "y": -28.0, "z": 5.5, "dwell_s": 8.0},
    {"id": "WP15_W_EXT", "x": 0.0,   "y": -34.0, "z": 5.5, "dwell_s": 8.0},
    {"id": "WP16_NW_EXT", "x": 26.0, "y": -24.0, "z": 5.0, "dwell_s": 8.0},
    {"id": "WP17_APPROACH", "x": 12.0, "y": -6.0, "z": 4.5, "dwell_s": 7.0},
    {"id": "WP18_HOME",  "x": 0.0,   "y": 0.0,   "z": 4.0, "dwell_s": 7.0},
]
# Earliest attack gate AFTER this waypoint index finishes (0-based).
# Default 4 = let the UAV fly the normal plan first, then start attack attempts.
ATTACK_AFTER_WP = int(os.environ.get("ATTACK_AFTER_WP", "4"))
# Fraction of eligible mid-mission waypoints that become attack gates each run.
# Remaining eligible WPs stay normal (≈50/50 by default). Random every run.
ATTACK_GATE_FRACTION = float(os.environ.get("ATTACK_GATE_FRACTION", "0.5"))
# Optional hard override of gate count; 0/empty = use 50/50 fraction.
_ATTACK_REPEATS_ENV = os.environ.get("ATTACK_REPEATS_PER_RUN", "").strip()
ATTACK_REPEATS_PER_RUN = int(_ATTACK_REPEATS_ENV) if _ATTACK_REPEATS_ENV else 0

# Back-compat alias used by older code paths
BENIGN_WAYPOINTS = [(w["x"], w["y"], w["z"]) for w in MISSION_PLAN]


def attack_gate_candidates() -> list[int]:
    """Eligible mid-mission WP indices that may host an attack gate.

    Skips early climb/normal lead-in (before ATTACK_AFTER_WP) and the final
    home WP so the UAV always starts and ends on a normal plan segment.
    """
    first_gate = max(1, min(int(ATTACK_AFTER_WP), len(MISSION_PLAN) - 2))
    return list(range(first_gate, max(first_gate + 1, len(MISSION_PLAN) - 1)))


def attack_gates_per_run(n_candidates: int | None = None) -> int:
    """How many attack gates to place this run (~50% of eligible WPs)."""
    n = int(n_candidates if n_candidates is not None else len(attack_gate_candidates()))
    if n <= 0:
        return 0
    if ATTACK_REPEATS_PER_RUN > 0:
        return max(1, min(int(ATTACK_REPEATS_PER_RUN), n))
    # Round to nearest; keep at least one attack and one normal when possible.
    target = int(round(n * float(ATTACK_GATE_FRACTION)))
    if n >= 2:
        target = max(1, min(n - 1, target))
    else:
        target = max(1, min(n, target or 1))
    return target


def build_repeated_attack_schedule(
    attack_id: str,
    repeats: int | None = None,
    seed: int | None = None,
) -> list[dict]:
    """Pick ~50% of eligible waypoints as random attack gates (rest stay normal).

    Each run re-samples distinct gates for the same scenario attack. Sorted into
    mission order: normal lead-in → attack/defend/resume → normal → attack… → home.
    """
    import random as _rnd

    candidates = attack_gate_candidates()
    if not candidates:
        return []
    if repeats is None:
        reps = attack_gates_per_run(len(candidates))
    else:
        reps = max(1, min(int(repeats), len(candidates)))
    rng = _rnd.Random(seed)
    gates = sorted(rng.sample(candidates, reps))
    out = []
    for gate_wp in gates:
        wp = MISSION_PLAN[gate_wp]
        out.append({
            "after_wp": int(gate_wp),
            "wp_id": wp["id"],
            "attack": attack_id,
        })
    return out


def build_random_attack_schedule(
    attack_ids: list[str] | None = None,
    seed: int | None = None,
) -> list[dict]:
    """Back-compat: multi-attack tour schedule (different attack per gate)."""
    import random as _rnd
    from attacks.suite import core_attack_ids
    ids = list(attack_ids or core_attack_ids())
    if not ids:
        return []
    candidates = attack_gate_candidates()
    rng = _rnd.Random(seed)
    # Use up to min(len(ids), len(candidates), attack_gates_per_run) gates
    n = min(len(ids), len(candidates), max(1, attack_gates_per_run(len(candidates))))
    gates = sorted(rng.sample(candidates, n))
    attacks = list(ids)
    rng.shuffle(attacks)
    out = []
    for i, gate_wp in enumerate(gates):
        wp = MISSION_PLAN[gate_wp]
        out.append({
            "after_wp": int(gate_wp),
            "wp_id": wp["id"],
            "attack": attacks[i % len(attacks)],
        })
    return out

def mission_duration_s() -> float:
    """Pure mission flight time (no attack pause)."""
    return float(sum(float(w["dwell_s"]) for w in MISSION_PLAN) + 3.0)


def mission_pre_duration_s() -> float:
    """Flight time from takeoff through ATTACK_AFTER_WP inclusive."""
    n = max(0, min(ATTACK_AFTER_WP + 1, len(MISSION_PLAN)))
    return float(sum(float(w["dwell_s"]) for w in MISSION_PLAN[:n]) + 3.0)


def mission_post_duration_s() -> float:
    """Flight time for remaining waypoints after the attack gate."""
    start = max(0, min(ATTACK_AFTER_WP + 1, len(MISSION_PLAN)))
    return float(sum(float(w["dwell_s"]) for w in MISSION_PLAN[start:]))


# ---- Timing (derived from the shared plan; overridable via env) ----
WARMUP_S = float(os.environ.get("WARMUP_S", "6.0"))
ATTACK_DUR_S = float(os.environ.get("ATTACK_DUR_S", "12.0"))
SETTLE_S = float(os.environ.get("SETTLE_S", "3.0"))
PRE_ATTACK_S = float(os.environ.get("PRE_ATTACK_S", str(mission_pre_duration_s())))
ATTACK_AT_S = PRE_ATTACK_S
POST_ATTACK_S = float(os.environ.get("POST_ATTACK_S", str(mission_post_duration_s())))
_RUN_ENV = os.environ.get("RUN_DURATION_S")
RUN_DURATION_S = float(_RUN_ENV) if _RUN_ENV else mission_duration_s()


def multi_attack_tour_duration_s(n_attacks: int | None = None) -> float:
    """Nominal wall time for a full multi-attack tour (mission + injections)."""
    from attacks.suite import core_attack_ids
    n = int(n_attacks if n_attacks is not None else len(core_attack_ids()))
    return float(mission_duration_s() + n * (ATTACK_DUR_S + 2.0) + 20.0)


def attack_run_duration_s() -> float:
    """Nominal repeated-attack scenario length on the shared mission."""
    reps = attack_gates_per_run()
    return float(mission_duration_s() + max(1, reps) * ATTACK_DUR_S)

# ---- Active defense (IPS) when dashboard "Defense" is checked ----
# Short grace so IDS still sees a signature, then hard prevent/reclaim.
DEFENSE_SIGNATURE_GRACE_S = float(os.environ.get("DEFENSE_SIGNATURE_GRACE_S", "1.0"))
# Keep aborting the attacker + reclaiming control for this long after engage.
DEFENSE_PREVENT_HOLD_S = float(os.environ.get(
    "DEFENSE_PREVENT_HOLD_S", str(max(10.0, float(os.environ.get("ATTACK_DUR_S", "12"))))))
# Engage IPS when score ≥ this *inside* a GT attack window (never on climb/pre/post).
DEFENSE_ENGAGE_SCORE = float(os.environ.get("DEFENSE_ENGAGE_SCORE", "0.72"))
# Single primary IDS model for live detect/defend + live training.
#   cnn1d  = Tiny MAVLink 1D-CNN (default — lightweight, strong on cyber attacks)
#   fusion = legacy LightGBM cascade (fallback)
IDS_PRIMARY_MODEL = os.environ.get("IDS_PRIMARY_MODEL", "cnn1d").strip().lower()
# When True, high-confidence primary-model alerts can engage reclaim even
# outside the orchestrator GT window (real defense, not lab-only).
DEFENSE_TRUST_MODEL = os.environ.get("DEFENSE_TRUST_MODEL", "1").strip() not in (
    "0", "false", "off",
)
# Defense path:
#   proactive — drop attacker MAVLink/GPS at gateway before PX4 (pre-UAV)
#   reactive  — allow injection, detect, then reclaim (post-effect)
#   hybrid    — proactive drops + reactive reclaim fallback (recommended)
#   prevent   — alias of hybrid (kept for older UI / paper scripts)
#   soft      — short reactive reclaim only
DEFENSE_MODE = os.environ.get("DEFENSE_MODE", "proactive").strip().lower()

# When capturing clean attack labels (Defense OFF) the pilot hard-freezes.
# When Defense is ON the pilot keeps OFFBOARD hold (see BenignPilot).

# ---- Paths ----
ROOT = Path(__file__).resolve().parent
DATASETS_DIR = ROOT / "datasets"
RUNS_DIR = DATASETS_DIR / "runs"
CASE_STUDIES_PATH = ROOT / "CASE_STUDIES.md"

# GPS spoof severity (deg/s lat&lon). low≈3e-6, med≈1e-5, high≈5e-5
# ~3e-5 deg/s ≈ 3+ m/s horizontal walk — visible in Gazebo within a few seconds
GPS_SPOOF_DRIFT = float(os.environ.get("GPS_SPOOF_DRIFT", "3e-5"))

# ---- IEEE TIFS / research pipeline defaults ----
# core = benign + Tier A (recommended paper matrix). Tier B = appendix only.
PIPELINE_SCOPE_DEFAULT = os.environ.get("PIPELINE_SCOPE", "core")
# ≥10 runs/scenario is preferred for journal tables; 6 is a lower bound.
PIPELINE_RUNS_DEFAULT = int(os.environ.get("PIPELINE_RUNS", "10"))
# Paper protocol: network capture on, defense on for closed-loop study.
PAPER_PROTOCOL = {
    "venue": "IEEE TIFS",
    "scope": "core",
    "runs_recommended": PIPELINE_RUNS_DEFAULT,
    "attack_gate_fraction": ATTACK_GATE_FRACTION,
    "labels": "pre/post=benign; attack windows only = attack",
    "modalities": ["physical", "network", "fusion"],
    "metrics": [
        "precision", "recall", "f1", "fpr",
        "mean_detection_delay_s", "mean_mitigation_delay_s",
        "defense_success_rate", "mission_resume_ok",
    ],
    "defense": "prevent during GT attack windows only (signature grace + reclaim)",
}

# ARM magic
ARM_FORCE_MAGIC = 21196.0

# PX4 custom flight modes: (main_mode, sub_mode)
PX4_MODES = {
    "MANUAL": (1, 0),
    "ALTCTL": (2, 0),
    "POSCTL": (3, 0),
    "AUTO_READY": (4, 1),
    "AUTO_TAKEOFF": (4, 2),
    "AUTO_LOITER": (4, 3),
    "AUTO_MISSION": (4, 4),
    "AUTO_RTL": (4, 5),
    "AUTO_LAND": (4, 6),
    "OFFBOARD": (6, 0),
    "STABILIZED": (7, 0),
}
