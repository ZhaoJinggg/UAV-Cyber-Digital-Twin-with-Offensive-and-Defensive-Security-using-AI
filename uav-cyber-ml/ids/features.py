"""Feature schemas, physical windowing, and physical+network fusion."""

from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd

META_COLS = {
    "scenario",
    "run",
    "label_phase",
    "attack_active",
    "label_binary",
    "label_class",
    "label_multiclass",
}

# Absolute / non-causal / identity fields — keep out of the onboard model.
PHYSICAL_DROP = META_COLS | {
    "t_wall",
    "t_rel",
    "lat",
    "lon",
    "alt_msl",
    "hdg",  # duplicate of heading (different units/scale)
}

NETWORK_DROP = META_COLS | {"t_rel", "win_s"}

# Core physical columns that survive NaN-heavy early rows well enough for IDS.
PHYSICAL_CORE = [
    "roll",
    "pitch",
    "yaw",
    "rollspeed",
    "pitchspeed",
    "yawspeed",
    "x",
    "y",
    "z",
    "vx",
    "vy",
    "vz",
    "rel_alt",
    "airspeed",
    "groundspeed",
    "heading",
    "throttle",
    "vfr_alt",
    "climb",
    "batt_voltage",
    "batt_current",
    "batt_remaining",
    "cpu_load",
    "m1",
    "m2",
    "m3",
    "m4",
    "m5",
    "m6",
    "m7",
    "m8",
    "tgt_rollrate",
    "tgt_pitchrate",
    "tgt_yawrate",
    "tgt_thrust",
    "armed",
    "custom_mode",
    "base_mode",
    "system_status",
    "speed",
    "horiz_speed",
    "vertical_speed",
    "tilt_mag",
    "motor_mean",
    "motor_spread",
    "pos_err_z",
]

NETWORK_CORE = [
    "pkt_count",
    "byte_count",
    "pkt_rate",
    "byte_rate",
    "mean_len",
    "std_len",
    "mean_iat",
    "std_iat",
    "to_uav_count",
    "from_uav_count",
    "unique_msgids",
    "unique_sysids",
    "heartbeat_count",
    "command_long_count",
    "param_set_count",
    "mission_item_count",
    "rc_override_count",
    "manual_control_count",
    "gps_input_count",
    "set_mode_count",
]

# Stats computed over each 1 s physical bucket for fusion / sliding windows.
PHYS_AGG_STATS = ("mean", "std", "min", "max", "last")
PHYS_WINDOW_FOCUS = [
    "roll",
    "pitch",
    "yaw",
    "rollspeed",
    "pitchspeed",
    "yawspeed",
    "vx",
    "vy",
    "vz",
    "rel_alt",
    "groundspeed",
    "throttle",
    "climb",
    "tilt_mag",
    "motor_mean",
    "motor_spread",
    "pos_err_z",
    "speed",
    "horiz_speed",
    "vertical_speed",
    "armed",
    "custom_mode",
    "cpu_load",
]


def physical_feature_columns(df: pd.DataFrame) -> list[str]:
    cols = [c for c in PHYSICAL_CORE if c in df.columns]
    # Keep any extra numeric processed cols that are not explicitly dropped.
    for c in df.columns:
        if c in PHYSICAL_DROP or c in cols:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return cols


def network_feature_columns(df: pd.DataFrame) -> list[str]:
    cols = [c for c in NETWORK_CORE if c in df.columns]
    for c in df.columns:
        if c in NETWORK_DROP or c in cols:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return cols


def run_key(df: pd.DataFrame) -> pd.Series:
    return df["scenario"].astype(str) + "::" + df["run"].astype(str)


def prepare_physical_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Return cleaned physical matrix + feature names (row-level, ~10 Hz)."""
    out = df.copy()
    feats = physical_feature_columns(out)
    out[feats] = out[feats].replace([np.inf, -np.inf], np.nan)
    # Forward/back fill within each run so early telemetry gaps don't drop rows.
    out[feats] = out.groupby(run_key(out), sort=False)[feats].ffill().bfill()
    out[feats] = out[feats].fillna(0.0)
    out["run_id"] = run_key(out)
    return out, feats


def prepare_network_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    out = df.copy()
    feats = network_feature_columns(out)
    out[feats] = out[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    out["run_id"] = run_key(out)
    return out, feats


def _agg_physical_second(phys: pd.DataFrame, focus: Iterable[str]) -> pd.DataFrame:
    """Bucket physical rows into 1 s bins aligned with network windows."""
    focus = [c for c in focus if c in phys.columns]
    work = phys.copy()
    work["t_bin"] = np.floor(work["t_rel"].astype(float)).astype(int)
    rows: list[dict] = []
    for (run_id, t_bin), g in work.groupby(["run_id", "t_bin"], sort=False):
        row: dict = {
            "run_id": run_id,
            "t_bin": int(t_bin),
            "scenario": g["scenario"].iloc[0],
            "run": int(g["run"].iloc[0]),
            "label_binary": int(g["label_binary"].max()),
            "label_class": (
                g.loc[g["label_binary"] == 1, "label_class"].iloc[0]
                if (g["label_binary"] == 1).any()
                else "benign"
            ),
            "n_phys_samples": len(g),
        }
        for c in focus:
            s = g[c].astype(float)
            row[f"p_{c}_mean"] = float(s.mean())
            row[f"p_{c}_std"] = float(s.std(ddof=0)) if len(s) > 1 else 0.0
            row[f"p_{c}_min"] = float(s.min())
            row[f"p_{c}_max"] = float(s.max())
            row[f"p_{c}_last"] = float(s.iloc[-1])
        rows.append(row)
    return pd.DataFrame(rows)


def build_fused_dataset(
    physical: pd.DataFrame,
    network: pd.DataFrame,
) -> tuple[pd.DataFrame, list[str]]:
    """Align 1 s network windows with physical aggregates from the same second."""
    phys, _ = prepare_physical_frame(physical)
    net, net_feats = prepare_network_frame(network)

    phys_sec = _agg_physical_second(phys, PHYS_WINDOW_FOCUS)
    net = net.copy()
    net["t_bin"] = np.floor(net["t_rel"].astype(float)).astype(int)

    fused = net.merge(
        phys_sec,
        on=["run_id", "t_bin", "scenario", "run"],
        how="inner",
        suffixes=("", "_physlab"),
    )
    # Prefer network labels (same attack window); fall back if needed.
    if "label_binary_physlab" in fused.columns:
        fused["label_binary"] = fused["label_binary"].fillna(fused["label_binary_physlab"])
        fused.drop(columns=["label_binary_physlab"], inplace=True, errors="ignore")
    if "label_class_physlab" in fused.columns:
        fused["label_class"] = fused["label_class"].fillna(fused["label_class_physlab"])
        fused.drop(columns=["label_class_physlab"], inplace=True, errors="ignore")

    phys_feats = [c for c in fused.columns if c.startswith("p_")]
    feat_cols = [c for c in net_feats if c in fused.columns] + phys_feats
    fused[feat_cols] = fused[feat_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    fused["label_multiclass"] = fused["label_class"]
    return fused, feat_cols


def top_k_features(
    importances: np.ndarray,
    feature_names: list[str],
    k: int,
) -> list[str]:
    order = np.argsort(importances)[::-1]
    k = max(1, min(k, len(feature_names)))
    return [feature_names[i] for i in order[:k]]
