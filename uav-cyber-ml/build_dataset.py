"""Merge all recorded runs into labeled ML/DL datasets.

Produces (in datasets/):
  physical_raw_dataset.csv        per-message physical features (all runs)
  physical_processed_dataset.csv  resampled physical feature vectors
  network_raw_dataset.csv         per-packet network features
  network_processed_dataset.csv   windowed network-flow features
  DATA_DICTIONARY.md              column documentation + class balance

Labels added to every row:
  scenario          run scenario (benign or attack name)
  run               run index
  label_phase       normal_plan | attack
                    (pre-attack + post-attack + pure-benign = normal_plan)
  attack_active     1 only while under attack
  label_binary      0 = normal plan, 1 = under attack
  label_class       'benign' | '<attack_name>'
                    (pre and post on an attack run are labeled benign —
                     they fly the same normal plan)
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

import config as C

LABEL_COLS = [
    "scenario", "run", "label_phase", "attack_active",
    "label_binary", "label_class", "label_multiclass",
]


def _phase_for_t(t: float, meta: dict) -> str:
    """Map timestamp → normal_plan or attack (pre/post = normal plan)."""
    if not meta.get("is_attack"):
        return "normal_plan"
    a0 = meta.get("attack_start_rel")
    a1 = meta.get("attack_end_rel")
    if a0 is None:
        return "normal_plan"
    if t < a0:
        return "normal_plan"   # pre-attack: normal shared plan
    if a1 is None or t <= a1:
        return "attack"
    return "normal_plan"       # post-attack: resume same normal plan


def _label_rows(df: pd.DataFrame, meta: dict) -> pd.DataFrame:
    if df.empty or "t_rel" not in df.columns:
        return df
    scenario = meta["scenario"]
    df = df.copy()
    for c in LABEL_COLS:
        if c in df.columns:
            df.drop(columns=[c], inplace=True)

    phases = df["t_rel"].map(lambda t: _phase_for_t(float(t), meta))
    under = phases == "attack"
    df["scenario"] = scenario
    df["run"] = meta["run"]
    df["label_phase"] = phases
    df["attack_active"] = under.astype(int)
    df["label_binary"] = under.astype(int)
    # Binary class name for ML: pre/post = benign (normal plan), not a 3rd class
    df["label_class"] = under.map(
        lambda x: scenario if x else "benign")
    # keep label_multiclass as alias of label_class for older pipelines
    df["label_multiclass"] = df["label_class"]
    return df


def annotate_run_dir(run_dir: Path, meta: dict | None = None) -> None:
    """Write ML label columns into each CSV inside a single run folder."""
    run_dir = Path(run_dir)
    if meta is None:
        mp = run_dir / "metadata.json"
        if not mp.exists():
            return
        meta = json.loads(mp.read_text())
    for name in ("physical_raw.csv", "physical_processed.csv",
                 "network_raw.csv", "network_processed.csv"):
        f = run_dir / name
        if not f.exists():
            continue
        try:
            df = pd.read_csv(f)
        except Exception:
            continue
        if df.empty:
            continue
        _label_rows(df, meta).to_csv(f, index=False)


def _collect(filename: str) -> pd.DataFrame:
    frames = []
    for meta_path in sorted(C.RUNS_DIR.glob("*/run_*/metadata.json")):
        run_dir = meta_path.parent
        f = run_dir / filename
        if not f.exists():
            continue
        try:
            df = pd.read_csv(f)
        except Exception:
            continue
        if df.empty:
            continue
        meta = json.loads(meta_path.read_text())
        frames.append(_label_rows(df, meta))
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def _write(df: pd.DataFrame, name: str) -> str:
    if df.empty:
        return f"{name}: (no data)"
    out = C.DATASETS_DIR / name
    df.to_csv(out, index=False)
    return f"{name}: {len(df)} rows, {len(df.columns)} cols"


def _class_balance(df: pd.DataFrame) -> str:
    if df.empty or "label_multiclass" not in df:
        return "  (none)"
    vc = df["label_multiclass"].value_counts()
    return "\n".join(f"  {k}: {v}" for k, v in vc.items())


def list_run_keys() -> list[str]:
    """Stable keys like 'gps_spoofing/run_15' for all recorded runs."""
    keys = []
    for meta_path in sorted(C.RUNS_DIR.glob("*/run_*/metadata.json")):
        keys.append(f"{meta_path.parent.parent.name}/{meta_path.parent.name}")
    return keys


def _collect_runs(filename: str, run_keys: set[str] | None = None) -> pd.DataFrame:
    """Collect labeled frames, optionally filtered to specific run keys."""
    frames = []
    for meta_path in sorted(C.RUNS_DIR.glob("*/run_*/metadata.json")):
        key = f"{meta_path.parent.parent.name}/{meta_path.parent.name}"
        if run_keys is not None and key not in run_keys:
            continue
        run_dir = meta_path.parent
        f = run_dir / filename
        if not f.exists():
            continue
        try:
            df = pd.read_csv(f)
        except Exception:
            continue
        if df.empty:
            continue
        meta = json.loads(meta_path.read_text())
        frames.append(_label_rows(df, meta))
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def _run_key_series(df: pd.DataFrame) -> pd.Series:
    return df["scenario"].astype(str) + "/run_" + df["run"].astype(int).astype(str).str.zfill(2)


def append_runs(run_keys: list[str]) -> dict:
    """Append only the given runs onto existing merged CSVs (fast live path).

    Falls back to a full rebuild if merged files are missing or schemas diverge.
    """
    keys = sorted(set(run_keys))
    if not keys:
        return {"mode": "noop", "files": [], "appended_runs": []}

    C.DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    key_set = set(keys)
    for key in keys:
        scen, run = key.split("/", 1)
        run_dir = C.RUNS_DIR / scen / run
        mp = run_dir / "metadata.json"
        if mp.exists():
            try:
                annotate_run_dir(run_dir, json.loads(mp.read_text()))
            except Exception:
                pass

    names = (
        "physical_raw_dataset.csv",
        "physical_processed_dataset.csv",
        "network_raw_dataset.csv",
        "network_processed_dataset.csv",
    )
    src_map = {
        "physical_raw_dataset.csv": "physical_raw.csv",
        "physical_processed_dataset.csv": "physical_processed.csv",
        "network_raw_dataset.csv": "network_raw.csv",
        "network_processed_dataset.csv": "network_processed.csv",
    }

    # Require existing processed merges; otherwise do a full build.
    need_full = False
    for name in ("physical_processed_dataset.csv", "network_processed_dataset.csv"):
        if not (C.DATASETS_DIR / name).exists():
            need_full = True
            break
    if need_full:
        summary = build()
        summary["mode"] = "full_fallback"
        summary["appended_runs"] = keys
        return summary

    summary = {"mode": "append", "files": [], "appended_runs": keys, "class_balance": {}}
    outputs = {}
    for name in names:
        path = C.DATASETS_DIR / name
        try:
            old = pd.read_csv(path) if path.exists() else pd.DataFrame()
        except Exception:
            return {**build(), "mode": "full_fallback", "appended_runs": keys}

        # Drop any prior rows for these runs (re-run / overwrite safety).
        if not old.empty and {"scenario", "run"}.issubset(old.columns):
            rk = _run_key_series(old)
            # Also accept unpadded run_N keys from older merges.
            alt = old["scenario"].astype(str) + "/" + old["run"].map(
                lambda r: f"run_{int(r)}" if str(r).isdigit() else str(r))
            keep = ~rk.isin(key_set) & ~alt.isin(key_set)
            old = old.loc[keep].reset_index(drop=True)

        new = _collect_runs(src_map[name], key_set)
        if old.empty and new.empty:
            outputs[name] = pd.DataFrame()
            summary["files"].append({"name": name, "rows": 0, "cols": 0})
            continue
        if old.empty:
            merged = new
        elif new.empty:
            merged = old
        else:
            # Align columns (union); missing → NaN
            cols = list(dict.fromkeys(list(old.columns) + list(new.columns)))
            merged = pd.concat([old.reindex(columns=cols),
                                new.reindex(columns=cols)], ignore_index=True)
        _write(merged, name)
        outputs[name] = merged
        summary["files"].append({
            "name": name,
            "rows": int(len(merged)),
            "cols": int(len(merged.columns)) if not merged.empty else 0,
        })

    pp = outputs.get("physical_processed_dataset.csv", pd.DataFrame())
    npx = outputs.get("network_processed_dataset.csv", pd.DataFrame())
    if not pp.empty and "label_class" in pp:
        summary["class_balance"] = {
            str(k): int(v) for k, v in pp["label_class"].value_counts().items()
        }
    if not pp.empty and "label_phase" in pp:
        summary["phase_balance"] = {
            str(k): int(v) for k, v in pp["label_phase"].value_counts().items()
        }
    try:
        _write_dictionary(pp, npx)
    except Exception:
        pass
    return summary


def build() -> dict:
    """Merge + label all runs, write dataset CSVs, and return a summary dict."""
    C.DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    # Also re-annotate every run folder so live explorer sees labels
    for meta_path in sorted(C.RUNS_DIR.glob("*/run_*/metadata.json")):
        try:
            annotate_run_dir(meta_path.parent, json.loads(meta_path.read_text()))
        except Exception:
            pass

    outputs = {
        "physical_raw_dataset.csv": _collect("physical_raw.csv"),
        "physical_processed_dataset.csv": _collect("physical_processed.csv"),
        "network_raw_dataset.csv": _collect("network_raw.csv"),
        "network_processed_dataset.csv": _collect("network_processed.csv"),
    }
    summary = {"mode": "full", "files": [], "class_balance": {},
               "appended_runs": list_run_keys()}
    for name, df in outputs.items():
        _write(df, name)
        summary["files"].append({
            "name": name,
            "rows": int(len(df)),
            "cols": int(len(df.columns)) if not df.empty else 0,
        })

    pp = outputs["physical_processed_dataset.csv"]
    npx = outputs["network_processed_dataset.csv"]
    if not pp.empty and "label_class" in pp:
        summary["class_balance"] = {
            str(k): int(v) for k, v in pp["label_class"].value_counts().items()
        }
    elif not pp.empty and "label_multiclass" in pp:
        summary["class_balance"] = {
            str(k): int(v) for k, v in pp["label_multiclass"].value_counts().items()
        }
    if not pp.empty and "label_phase" in pp:
        summary["phase_balance"] = {
            str(k): int(v) for k, v in pp["label_phase"].value_counts().items()
        }
    _write_dictionary(pp, npx)
    return summary


def _write_dictionary(pp: pd.DataFrame, npx: pd.DataFrame) -> None:
    bal_col = "label_class" if (not pp.empty and "label_class" in pp) else "label_multiclass"
    doc = ["# UAV Cyber-Attack Dataset — Data Dictionary\n",
           "Two independent feature layers, each with raw and processed forms.\n",
           "## Timeline (attack scenarios)\n",
           "All scenarios fly the **same shared multi-waypoint mission plan**. "
           "Attacks pause mid-plan:\n",
           "1. **pre** — normal plan (benign label)\n",
           "2. **attack** — injection (attack label)\n",
           "3. **post** — resume normal plan (benign label)\n\n",
           "Pre and post are **benign** — same normal plan flight; only the "
           "attack window is labeled as attack.\n\n",
           "## Label columns (all files)\n",
           "- `scenario` — which scenario was run\n"
           "- `run` — run index\n"
           "- `label_phase` — `normal_plan` | `attack`\n"
           "- `attack_active` / `label_binary` — 1 only during attack\n"
           "- `label_class` — `benign` | `<attack_name>` "
           "(pre + post = benign; no separate post class)\n"
           "- `label_multiclass` — alias of `label_class`\n",
           "\n## Class balance (physical_processed)\n",
           ]
    if not pp.empty and bal_col in pp:
        doc.append("\n".join(f"  {k}: {v}" for k, v in pp[bal_col].value_counts().items()))
    else:
        doc.append("  (none)")
    doc += ["\n\n## Phase balance (physical_processed)\n"]
    if not pp.empty and "label_phase" in pp:
        doc.append("\n".join(f"  {k}: {v}" for k, v in
                             pp["label_phase"].value_counts().items()))
    else:
        doc.append("  (none)")
    doc += ["\n\n## Physical processed columns\n",
            ", ".join(pp.columns.tolist()) if not pp.empty else "(empty)",
            "\n\n## Network processed columns\n",
            ", ".join(npx.columns.tolist()) if not npx.empty else "(empty)",
            "\n"]
    (C.DATASETS_DIR / "DATA_DICTIONARY.md").write_text("".join(doc))


def main():
    summary = build()
    print("Built datasets:")
    for f in summary["files"]:
        print(f"  {f['name']}: {f['rows']} rows, {f['cols']} cols")
    if summary.get("class_balance"):
        print("Class balance (physical_processed):")
        for k, v in summary["class_balance"].items():
            print(f"  {k}: {v}")
    if summary.get("phase_balance"):
        print("Phase balance:")
        for k, v in summary["phase_balance"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
