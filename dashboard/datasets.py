"""Turn recorded run CSVs into compact plot-ready panels for the dashboard."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pandas as pd


def _read_csv(f: Path) -> pd.DataFrame:
    """Read a run CSV tolerantly (it may still be growing during a live run)."""
    try:
        return pd.read_csv(f, on_bad_lines="skip")
    except (pd.errors.EmptyDataError, FileNotFoundError):
        return pd.DataFrame()


def _clean(v):
    if v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(f) or math.isinf(f) else round(f, 4)


def _series(df: pd.DataFrame, xcol: str, cols: list[str]) -> list[dict]:
    out = []
    x = df[xcol].tolist()
    for c in cols:
        if c not in df.columns:
            continue
        ys = df[c].tolist()
        pts = [[_clean(xi), _clean(yi)] for xi, yi in zip(x, ys)]
        pts = [p for p in pts if p[0] is not None and p[1] is not None]
        if pts:
            out.append({"name": c, "points": pts})
    return out


def _downsample(df: pd.DataFrame, max_rows: int = 2000) -> pd.DataFrame:
    if len(df) <= max_rows:
        return df
    step = math.ceil(len(df) / max_rows)
    return df.iloc[::step].reset_index(drop=True)


def _rate_by_category(df: pd.DataFrame, tcol: str, catcol: str,
                      top: int = 8, bin_s: float = 1.0) -> list[dict]:
    """Per-bin counts for the most common categories -> one series each."""
    if df.empty or catcol not in df.columns:
        return []
    d = df.copy()
    d["_bin"] = (d[tcol] // bin_s * bin_s).astype(float)
    d[catcol] = d[catcol].fillna("").replace("", "OTHER").astype(str)
    top_cats = d[catcol].value_counts().head(top).index.tolist()
    out = []
    for cat in top_cats:
        g = d[d[catcol] == cat].groupby("_bin").size()
        pts = [[_clean(x), _clean(y / bin_s)] for x, y in g.items()]
        if pts:
            out.append({"name": cat, "points": pts})
    return out


def _attack_window(run_dir: Path) -> dict:
    mp = run_dir / "metadata.json"
    if mp.exists():
        try:
            m = json.loads(mp.read_text())
            windows = []
            for w in (m.get("attack_windows") or []):
                try:
                    s = float(w.get("start_rel"))
                    e = float(w.get("end_rel"))
                except (TypeError, ValueError, AttributeError):
                    continue
                if e > s:
                    windows.append({
                        "start": round(s, 3),
                        "end": round(e, 3),
                        "attack": w.get("attack") or m.get("attack"),
                    })
            # Legacy single-window metadata (older runs).
            if not windows and m.get("attack_start_rel") is not None:
                try:
                    s = float(m["attack_start_rel"])
                    e = float(m.get("attack_end_rel") or s)
                    if e > s:
                        windows.append({"start": round(s, 3), "end": round(e, 3),
                                        "attack": m.get("attack")})
                except (TypeError, ValueError):
                    pass
            n_atk = m.get("n_attack_gates")
            n_nrm = m.get("n_normal_gates")
            if n_atk is None and windows:
                n_atk = len(windows)
            if n_nrm is None and m.get("attack_schedule") is not None:
                try:
                    from config import attack_gate_candidates
                    n_cand = len(attack_gate_candidates())
                    n_sched = len(m.get("attack_schedule") or [])
                    n_atk = n_atk if n_atk is not None else n_sched
                    n_nrm = max(0, n_cand - n_sched)
                except Exception:
                    pass
            return {
                "attack_start": m.get("attack_start_rel"),
                "attack_end": m.get("attack_end_rel"),
                "attack_windows": windows,
                "n_attack_gates": n_atk,
                "n_normal_gates": n_nrm,
                "post_end": m.get("post_end_rel"),
                "pre_s": m.get("pre_s"),
                "post_s": m.get("post_s"),
            }
        except Exception:
            pass
    return {"attack_start": None, "attack_end": None, "attack_windows": [],
            "n_attack_gates": None, "n_normal_gates": None,
            "post_end": None, "pre_s": None, "post_s": None}


def load_series(run_dir: Path, layer: str, kind: str) -> dict:
    run_dir = Path(run_dir)
    win = _attack_window(run_dir)

    if layer == "physical" and kind == "processed":
        f = run_dir / "physical_processed.csv"
        if not f.exists():
            raise FileNotFoundError(str(f))
        df = _downsample(_read_csv(f))
        if df.empty:
            return {"x_label": "t (s)", "panels": [], **win}
        if "z" in df.columns:
            df["altitude_m"] = -df["z"]     # LOCAL_POSITION_NED z is negative-up
        panels = [
            {"title": "Altitude & vertical speed (m, m/s)",
             "series": _series(df, "t_rel", ["altitude_m", "vertical_speed"])},
            {"title": "Speed & tilt (m/s, rad)",
             "series": _series(df, "t_rel", ["speed", "horiz_speed", "tilt_mag"])},
            {"title": "Attitude (rad)",
             "series": _series(df, "t_rel", ["roll", "pitch", "yaw"])},
            {"title": "Actuators & armed",
             "series": _series(df, "t_rel", ["motor_mean", "motor_spread", "armed"])},
        ]
        return {"x_label": "t (s)", "panels": panels, **win}

    if layer == "physical" and kind == "raw":
        f = run_dir / "physical_raw.csv"
        if not f.exists():
            raise FileNotFoundError(str(f))
        df = _read_csv(f)
        panels = [
            {"title": "Raw MAVLink message rate by type (msgs/s, 1s bins)",
             "series": _rate_by_category(df, "t_rel", "msg_type", top=8)},
        ]
        return {"x_label": "t (s)", "panels": panels, **win}

    if layer == "network" and kind == "processed":
        f = run_dir / "network_processed.csv"
        if not f.exists():
            raise FileNotFoundError(str(f))
        df = _read_csv(f)
        panels = [
            {"title": "Packet rate (pkts/s)",
             "series": _series(df, "t_rel", ["pkt_rate", "to_uav_count", "from_uav_count"])},
            {"title": "Byte rate (bytes/s)",
             "series": _series(df, "t_rel", ["byte_rate"])},
            {"title": "MAVLink message mix (msgs/window)",
             "series": _series(df, "t_rel",
                               ["heartbeat_count", "command_long_count",
                                "param_set_count", "rc_override_count",
                                "manual_control_count", "gps_input_count",
                                "set_mode_count", "mission_item_count"])},
        ]
        return {"x_label": "t (s)", "panels": panels, **win}

    if layer == "network" and kind == "raw":
        f = run_dir / "network_raw.csv"
        if not f.exists():
            raise FileNotFoundError(str(f))
        df = _read_csv(f)
        panels = [
            {"title": "Packet rate by direction (pkts/s, 1s bins)",
             "series": _rate_by_category(df, "t_rel", "direction", top=4)},
            {"title": "Packet rate by MAVLink message (pkts/s, 1s bins)",
             "series": _rate_by_category(df, "t_rel", "msg_name", top=8)},
        ]
        return {"x_label": "t (s)", "panels": panels, **win}

    raise ValueError(f"unknown layer/kind: {layer}/{kind}")
