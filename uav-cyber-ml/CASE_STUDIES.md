# UAV Cyber Digital Twin — Case Study Sheet

Research lab: **PX4 Gazebo SITL (Physical Twin)** ↔ **Mac CDT dashboard (Digital Twin)**  
Protocol: one **shared multi-waypoint mission**; attacks inject **after WP2**; pre/post labeled **benign**.

## Research claim

A cyber digital twin synchronized to a physical twin can expose and quantify
MAVLink cyber–physical attacks (and later host defenses) using **aligned**
physical, network, and twin observations on an identical flight plan.

## Experimental protocol (all scenarios)

| Step | Action |
|------|--------|
| 1 | Start warm SITL at home `(0,0)` (or reset) |
| 2 | Record physical (14550) + network (tcpdump) |
| 3 | Fly shared `MISSION_PLAN` OFFBOARD |
| 4 | **Attacks only:** freeze after `ATTACK_AFTER_WP`, inject `ATTACK_DUR_S`, resume |
| 5 | Land, disarm, reset home; twin follows throughout |
| 6 | Labels: `normal_plan` vs `attack`; pre/post = `benign` |

**Labels for ML**

- `label_phase`: `normal_plan` \| `attack`
- `label_binary` / `attack_active`: 1 only in attack window
- `label_class`: `benign` \| `<attack_id>`

**Metrics triad (report per run)**

- **P** — Physical Twin effect (path, alt, mode, armed)
- **N** — Network / MAVLink signature (rates, msg mix, sysid)
- **T** — Digital Twin symptom (live pose/trail/mode match to PT)

---

## Tier A — Core case studies (default pipeline)

| ID | Hypothesis | P | N | T | Defense later |
|----|------------|---|---|---|----------------|
| `benign` | Baseline fingerprints; DT tracks PT on shared route | ✓ | ✓ | ✓ | — |
| `gps_spoofing` | GPS injection → estimator bias → path error mirrored by CDT | ✓ | ✓ | ✓ | GPS integrity / EKF gates |
| `disarm_injection` | Force-disarm is an immediate safety event on PT+DT | ✓ | ✓ | ✓ | Arming auth / allow-list |
| `mode_change_land` | Mode FSM hijack aborts shared plan; DT mode+trail diverge | ✓ | ✓ | ✓ | Mode-transition policy |
| `mission_injection` | Rogue mission ≠ known plan; route residual detects it | ✓ | ✓ | ✓ | Mission signing / WP check |
| `command_flood_dos` | Availability stress: N spike + DT lag; soft P | · | ✓ | ✓ | Rate limits / QoS |
| `rc_override` | Stick hijack → abrupt kinematics on PT+DT | ✓ | ✓ | ✓ | RC / control arbiter |
| `param_injection` | Config tamper is N-first; delayed P when fault triggers | · | ✓ | · | Param allow-list |

### Severity ladder (GPS)

| Level | `GPS_SPOOF_DRIFT` | Intent |
|-------|-------------------|--------|
| Low | `3e-6` | Subtle bias |
| Med (default) | `1e-5` | Clear path error |
| High | `5e-5` | Aggressive drift |

```bash
GPS_SPOOF_DRIFT=5e-5 ./run_dashboard.sh
```

---

## Tier B — Supporting (multiclass / appendix)

| ID | Role |
|----|------|
| `mode_change_rtl` | Mode-hijack variant for class separation |
| `heartbeat_spoof` | Strong **N**, weak **P** — triangulation |
| `takeoff_injection` | Pre-flight / phase-aware case |

Include with pipeline scope **all**.

---

## Defense roadmap (next phase)

| Layer | Targets | Depends on cases |
|-------|---------|------------------|
| Network IDS | flood, heartbeat, param, mission | Tier A + B heartbeat |
| Kinematic / FSM IDS | GPS, disarm, mode, RC | Tier A physical-heavy |
| Twin integrity (DT↔PT residual) | GPS, mission, FDI (future) | Tier A + future Tier C |
| Policy enforcement | disarm, mode, mission, takeoff | Command-injection set |

**Planned Tier C (not implemented yet):** telemetry FDI, replay/delay, selective drop, combined GPS+DoS.

---

## How to run

```bash
# Dashboard (recommended)
./run_dashboard.sh
# open http://127.0.0.1:8000
# Pipeline default scope = core (benign + Tier A)

# CLI core matrix
.venv/bin/python orchestrator.py --scope core --runs 1

# Full including Tier B
.venv/bin/python orchestrator.py --scope all --runs 1
```

## Pass criteria for a valid run

1. Vehicle **arms** and climbs (DT altitude rises)
2. Pre window flies shared plan (green / `normal_plan`)
3. Attack window labels `attack` (red banner)
4. Post resumes remaining WPs when applicable
5. Physical + (if enabled) network CSVs non-empty
6. DT position tracks PT within visual/telemetric lag during flight
