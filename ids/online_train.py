"""Online / live IDS training after SITL runs.

Default behavior (fast):
  * append only NEW runs into the merged CSVs
  * fine-tune existing LightGBM models via init_model on the new rows
  * keep prior trees (old knowledge) and add a few boosting rounds

Falls back to a full cold retrain when artifacts are missing, feature
schemas diverge, or a brand-new attack class appears.
"""

from __future__ import annotations

import json
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

from ids.features import (
    build_fused_dataset,
    prepare_network_frame,
    prepare_physical_frame,
    top_k_features,
)
from ids.rules import DEFENSE_ACTIONS

try:
    from config import DATASETS_DIR, ROOT
except ImportError:  # pragma: no cover
    ROOT = Path(__file__).resolve().parent.parent
    DATASETS_DIR = ROOT / "datasets"

ARTIFACTS = ROOT / "ids" / "artifacts"
PublishFn = Callable[[dict], None]

_LOCK = threading.Lock()
_LAST_REPORT: dict[str, Any] | None = None
_TRAINING = False
_STATE_FILE = ARTIFACTS / "live_train_state.json"

# Fine-tune adds this many new trees on top of the existing booster.
_FINETUNE_ROUNDS = 40
_FINETUNE_LR = 0.05


def _default_state() -> dict:
    return {
        "live_train": True,
        "trained_run_ids": [],
        "updated_at": None,
        "last_mode": None,
    }


def _read_state() -> dict:
    st = _default_state()
    try:
        if _STATE_FILE.exists():
            data = json.loads(_STATE_FILE.read_text())
            st["live_train"] = bool(data.get("live_train", True))
            st["trained_run_ids"] = list(data.get("trained_run_ids") or [])
            st["updated_at"] = data.get("updated_at")
            st["last_mode"] = data.get("last_mode")
    except Exception:
        pass
    return st


def _write_state(**updates) -> dict:
    st = _read_state()
    st.update(updates)
    st["updated_at"] = datetime.now(timezone.utc).isoformat()
    try:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(st, indent=2))
    except Exception:
        pass
    return st


_LIVE_TRAIN = bool(_read_state().get("live_train", True))


def live_train_enabled() -> bool:
    return _LIVE_TRAIN


def set_live_train(enabled: bool) -> None:
    global _LIVE_TRAIN
    _LIVE_TRAIN = bool(enabled)
    _write_state(live_train=_LIVE_TRAIN)


def training_status() -> dict:
    st = _read_state()
    return {
        "live_train": _LIVE_TRAIN,
        "training": _TRAINING,
        "mode": st.get("last_mode"),
        "trained_runs": len(st.get("trained_run_ids") or []),
        "last": dict(_LAST_REPORT) if _LAST_REPORT else None,
    }


def _class_weights(y: np.ndarray) -> dict[int, float]:
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    return {int(c): float(w) for c, w in zip(classes, weights)}


def _artifacts_ready(out: Path, name: str) -> bool:
    return all((out / f).exists() for f in (
        f"{name}_binary.joblib",
        f"{name}_multiclass.joblib",
        f"{name}_label_encoder.joblib",
        f"{name}_bundle.json",
    ))


def _load_bundle(out: Path, name: str) -> dict:
    return json.loads((out / f"{name}_bundle.json").read_text())


def _run_keys_to_frame_ids(run_keys: set[str]) -> set[str]:
    """Map 'gps_spoofing/run_15' → feature run_id forms like 'gps_spoofing::15'."""
    out: set[str] = set()
    for k in run_keys:
        if "/" not in k:
            out.add(k)
            continue
        scen, run = k.split("/", 1)
        out.add(k)
        out.add(f"{scen}::{run}")
        if run.startswith("run_"):
            num = run.split("_", 1)[1]
            out.add(f"{scen}::{num}")
            try:
                out.add(f"{scen}::{int(num)}")
                out.add(f"{scen}::run_{int(num)}")
                out.add(f"{scen}/run_{int(num):02d}")
            except Exception:
                pass
        else:
            out.add(f"{scen}::{run}")
    return out


def _filter_new_runs(frame: pd.DataFrame, new_keys: set[str]) -> pd.DataFrame:
    if frame.empty or not new_keys:
        return frame.iloc[0:0].copy()
    ids = _run_keys_to_frame_ids(new_keys)
    rid = frame["run_id"].astype(str)
    return frame.loc[rid.isin(ids)].reset_index(drop=True)


def _quick_binary(X, y, groups, feature_cols, top_k: int = 30):
    sw = np.array([_class_weights(y).get(int(v), 1.0) for v in y])
    model = lgb.LGBMClassifier(
        n_estimators=120, learning_rate=0.08, num_leaves=24, max_depth=5,
        subsample=0.9, colsample_bytree=0.8, min_child_samples=15,
        reg_lambda=1.0, random_state=42, n_jobs=-1, verbosity=-1,
    )
    model.fit(X, y, sample_weight=sw)
    selected = top_k_features(model.feature_importances_.astype(float),
                              feature_cols, k=min(top_k, len(feature_cols)))
    sel_idx = [feature_cols.index(c) for c in selected]
    X_sel = X[:, sel_idx]
    compact = lgb.LGBMClassifier(
        n_estimators=140, learning_rate=0.08, num_leaves=24, max_depth=5,
        subsample=0.9, colsample_bytree=0.8, min_child_samples=12,
        reg_lambda=1.0, random_state=42, n_jobs=-1, verbosity=-1,
    )
    compact.fit(X_sel, y, sample_weight=sw)
    runs = np.unique(groups)
    n_te = max(1, len(runs) // 5)
    te_runs = set(runs[-n_te:])
    mask = np.array([g in te_runs for g in groups])
    if mask.any() and (~mask).any():
        from sklearn.metrics import f1_score, roc_auc_score
        prob = compact.predict_proba(X_sel[mask])[:, 1]
        pred = (prob >= 0.5).astype(int)
        f1 = float(f1_score(y[mask], pred, average="binary", zero_division=0))
        try:
            auc = float(roc_auc_score(y[mask], prob))
        except ValueError:
            auc = None
    else:
        f1, auc = None, None
    return compact, selected, {"f1_attack": f1, "roc_auc": auc, "n_rows": int(len(y))}


def _quick_multi(X, y_cls, groups, feature_cols, selected):
    le = LabelEncoder()
    y = le.fit_transform(y_cls)
    sw = np.array([_class_weights(y).get(int(v), 1.0) for v in y])
    sel_idx = [feature_cols.index(c) for c in selected if c in feature_cols]
    X_sel = X[:, sel_idx]
    model = lgb.LGBMClassifier(
        objective="multiclass", num_class=len(le.classes_),
        n_estimators=160, learning_rate=0.08, num_leaves=24, max_depth=5,
        subsample=0.9, colsample_bytree=0.8, min_child_samples=10,
        reg_lambda=1.0, random_state=42, n_jobs=-1, verbosity=-1,
    )
    model.fit(X_sel, y, sample_weight=sw)
    from sklearn.metrics import f1_score
    runs = np.unique(groups)
    n_te = max(1, len(runs) // 5)
    te_runs = set(runs[-n_te:])
    mask = np.array([g in te_runs for g in groups])
    f1 = None
    if mask.any() and (~mask).any():
        pred = model.predict(X_sel[mask])
        f1 = float(f1_score(y[mask], pred, average="macro", zero_division=0))
    return model, le, {"f1_macro": f1, "classes": list(le.classes_)}


def _finetune_binary(X, y, selected, feature_cols, prev_model):
    """Continue boosting from prev_model using NEW rows only."""
    sel_idx = [feature_cols.index(c) for c in selected]
    X_sel = X[:, sel_idx]
    sw = np.array([_class_weights(y).get(int(v), 1.0) for v in y])
    model = lgb.LGBMClassifier(
        n_estimators=_FINETUNE_ROUNDS, learning_rate=_FINETUNE_LR,
        num_leaves=24, max_depth=5, subsample=0.9, colsample_bytree=0.8,
        min_child_samples=8, reg_lambda=1.0, random_state=42,
        n_jobs=-1, verbosity=-1,
    )
    model.fit(X_sel, y, sample_weight=sw, init_model=prev_model)
    return model, {"f1_attack": None, "roc_auc": None, "n_rows": int(len(y)),
                   "finetune_rounds": _FINETUNE_ROUNDS}


def _pad_missing_classes(
    X_sel: np.ndarray,
    y: np.ndarray,
    sw: np.ndarray,
    n_classes: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Ensure every class id appears so LightGBM keeps num_class stable.

    Fine-tuning on a single new attack run often only contains 1–2 labels.
    Without placeholders, sklearn/LightGBM shrinks ``n_classes_`` and the next
    ``init_model`` call dies with: ``Number of class for initial score error``.
    """
    present = set(int(v) for v in np.unique(y))
    missing = [c for c in range(int(n_classes)) if c not in present]
    if not missing:
        return X_sel, y, sw
    if X_sel.size == 0:
        proto = np.zeros((1, X_sel.shape[1] if X_sel.ndim == 2 else 1), dtype=np.float32)
    else:
        proto = np.mean(X_sel, axis=0, keepdims=True).astype(np.float32)
    pads_x = np.repeat(proto, len(missing), axis=0)
    pads_y = np.asarray(missing, dtype=y.dtype)
    pads_w = np.full(len(missing), 1e-6, dtype=np.float64)
    return (
        np.vstack([X_sel, pads_x]),
        np.concatenate([y, pads_y]),
        np.concatenate([sw.astype(np.float64), pads_w]),
    )


def _multiclass_compatible(prev_model, le: LabelEncoder) -> tuple[bool, str]:
    """True when prev multiclass model can be safely continued via init_model."""
    classes = getattr(le, "classes_", None)
    n_le = len(classes) if classes is not None else 0
    if n_le < 2:
        return False, "label encoder has <2 classes"
    n_sk = int(getattr(prev_model, "n_classes_", 0) or 0)
    if n_sk != n_le:
        return False, f"multiclass n_classes_={n_sk} != encoder {n_le} (corrupted fine-tune)"
    try:
        booster = getattr(prev_model, "booster_", None)
        if booster is not None:
            n_boost = int((booster.params or {}).get("num_class") or 0)
            if n_boost and n_boost != n_le:
                return False, f"booster num_class={n_boost} != encoder {n_le}"
    except Exception:
        pass
    return True, "ok"


def _finetune_multi(X, y_cls, selected, feature_cols, prev_model, le: LabelEncoder):
    # Map with the existing encoder — unknown labels already gated outside.
    y = le.transform(y_cls)
    sel_idx = [feature_cols.index(c) for c in selected if c in feature_cols]
    X_sel = X[:, sel_idx]
    sw = np.array([_class_weights(y).get(int(v), 1.0) for v in y], dtype=np.float64)
    n_classes = len(le.classes_)
    X_sel, y, sw = _pad_missing_classes(X_sel, y, sw, n_classes)
    ok, why = _multiclass_compatible(prev_model, le)
    if not ok:
        raise RuntimeError(f"cannot fine-tune multiclass: {why}")
    model = lgb.LGBMClassifier(
        objective="multiclass", num_class=n_classes,
        n_estimators=_FINETUNE_ROUNDS, learning_rate=_FINETUNE_LR,
        num_leaves=24, max_depth=5, subsample=0.9, colsample_bytree=0.8,
        min_child_samples=8, reg_lambda=1.0, random_state=42,
        n_jobs=-1, verbosity=-1,
    )
    model.fit(X_sel, y, sample_weight=sw, init_model=prev_model)
    # Guard against silent class collapse on save
    if int(getattr(model, "n_classes_", 0) or 0) != n_classes:
        raise RuntimeError(
            f"fine-tune collapsed classes ({model.n_classes_} != {n_classes})"
        )
    return model, {"f1_macro": None, "classes": list(le.classes_),
                   "finetune_rounds": _FINETUNE_ROUNDS}


def _save_modality(name: str, out: Path, binary, multi, le, selected, feature_cols, metrics):
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bak = out / "history" / stamp
    bak.mkdir(parents=True, exist_ok=True)
    for fname in (f"{name}_binary.joblib", f"{name}_multiclass.joblib",
                  f"{name}_label_encoder.joblib", f"{name}_bundle.json"):
        src = out / fname
        if src.exists():
            shutil.copy2(src, bak / fname)

    joblib.dump(binary, out / f"{name}_binary.joblib")
    joblib.dump(multi, out / f"{name}_multiclass.joblib")
    joblib.dump(le, out / f"{name}_label_encoder.joblib")
    bundle = {
        "modality": name,
        "feature_cols_full": feature_cols,
        "feature_cols": selected,
        "label_encoder_classes": list(le.classes_),
        "defense_actions": DEFENSE_ACTIONS,
        "binary_threshold": 0.5,
        "top_k": len(selected),
        "trained_at": stamp,
        "online": True,
        "metrics": metrics,
    }
    (out / f"{name}_bundle.json").write_text(json.dumps(bundle, indent=2))
    (out / f"{name}_online_metrics.json").write_text(json.dumps(metrics, indent=2))


def _can_finetune(out_dir: Path, modalities: list[tuple], new_frames: dict) -> tuple[bool, str]:
    for name, _frame, feats, _k in modalities:
        if not _artifacts_ready(out_dir, name):
            return False, f"missing {name} artifacts"
        try:
            bundle = _load_bundle(out_dir, name)
            le = joblib.load(out_dir / f"{name}_label_encoder.joblib")
            prev_multi = joblib.load(out_dir / f"{name}_multiclass.joblib")
        except Exception as exc:
            return False, f"cannot load {name}: {exc}"
        ok_m, why_m = _multiclass_compatible(prev_multi, le)
        if not ok_m:
            return False, f"{name}: {why_m}"
        selected = list(bundle.get("feature_cols") or [])
        if not selected or any(c not in feats for c in selected):
            return False, f"{name} feature schema changed"
        nf = new_frames.get(name)
        if nf is None or nf.empty:
            return False, f"no new rows for {name}"
        new_classes = set(nf["label_class"].astype(str).unique())
        known = set(map(str, le.classes_))
        unknown = new_classes - known
        if unknown:
            return False, f"new classes {sorted(unknown)} need full retrain"
    return True, "ok"


def _load_new_run_frames(new_keys: list[str]):
    """Load/prepare only the newly recorded runs (skip giant merged CSVs)."""
    import build_dataset as bd
    from config import RUNS_DIR

    phys_parts, net_parts = [], []
    for key in new_keys:
        scen, run = key.split("/", 1)
        run_dir = RUNS_DIR / scen / run
        mp = run_dir / "metadata.json"
        meta = json.loads(mp.read_text()) if mp.exists() else {
            "scenario": scen, "run": int(run.split("_")[-1]) if "_" in run else 0,
            "is_attack": scen != "benign",
        }
        try:
            bd.annotate_run_dir(run_dir, meta)
        except Exception:
            pass
        pf = run_dir / "physical_processed.csv"
        nf = run_dir / "network_processed.csv"
        if pf.exists():
            try:
                pdf = pd.read_csv(pf)
                if not pdf.empty:
                    phys_parts.append(bd._label_rows(pdf, meta))
            except Exception:
                pass
        if nf.exists():
            try:
                ndf = pd.read_csv(nf)
                if not ndf.empty:
                    net_parts.append(bd._label_rows(ndf, meta))
            except Exception:
                pass

    phys_raw = pd.concat(phys_parts, ignore_index=True) if phys_parts else pd.DataFrame()
    net_raw = pd.concat(net_parts, ignore_index=True) if net_parts else pd.DataFrame()
    if phys_raw.empty:
        raise RuntimeError("no physical rows in new runs for fine-tune")
    phys, phys_feats = prepare_physical_frame(phys_raw)
    if not net_raw.empty:
        net, net_feats = prepare_network_frame(net_raw)
        fused, fused_feats = build_fused_dataset(phys_raw, net_raw)
    else:
        # Network missing: still fine-tune physical; reuse empty net/fusion frames
        net, net_feats = prepare_network_frame(phys_raw.iloc[0:0].copy())
        fused, fused_feats = phys.copy(), phys_feats
    return phys, phys_feats, net, net_feats, fused, fused_feats, phys_raw, net_raw


def retrain_and_save(
    datasets_dir: Path | None = None,
    out_dir: Path | None = None,
    publish: PublishFn | None = None,
    force_full: bool = False,
) -> dict:
    """Live train: fine-tune on new runs when possible, else full retrain."""
    global _TRAINING, _LAST_REPORT
    publish = publish or (lambda _m: None)
    with _LOCK:
        if _TRAINING:
            return {"ok": False, "message": "retrain already in progress"}
        _TRAINING = True

    t0 = time.time()
    try:
        import build_dataset as bd

        datasets_dir = Path(datasets_dir or DATASETS_DIR)
        out_dir = Path(out_dir or ARTIFACTS)
        out_dir.mkdir(parents=True, exist_ok=True)

        all_keys = bd.list_run_keys()
        state = _read_state()
        trained = set(state.get("trained_run_ids") or [])
        new_keys = [k for k in all_keys if k not in trained]

        from ids.cnn_model import META_NAME, WEIGHTS_NAME
        import config as _cfg
        primary = str(getattr(_cfg, "IDS_PRIMARY_MODEL", "cnn1d")).lower()
        have_cnn = (out_dir / WEIGHTS_NAME).exists() and (out_dir / META_NAME).exists()
        have_lgbm = all(_artifacts_ready(out_dir, n)
                        for n in ("physical", "network", "fusion"))
        # cnn1d primary: CNN weights are enough to treat models as present.
        have_models = have_cnn if primary == "cnn1d" else have_lgbm
        mode = "full"
        summary: dict[str, Any] = {}

        if force_full or not have_models:
            publish({"type": "log", "tag": "train",
                     "msg": "full retrain — rebuilding all datasets + models…",
                     "ts": time.time()})
            publish({"type": "ids", "data": {
                "event": "retrain", "status": "running", "mode": "full",
                "message": "Full retrain in progress…",
            }})
            summary = bd.build()
            new_keys = all_keys
            phys_raw = pd.read_csv(datasets_dir / "physical_processed_dataset.csv")
            net_raw = pd.read_csv(datasets_dir / "network_processed_dataset.csv")
            phys, phys_feats = prepare_physical_frame(phys_raw)
            net, net_feats = prepare_network_frame(net_raw)
            fused, fused_feats = build_fused_dataset(phys_raw, net_raw)
            fused.to_csv(out_dir / "fused_1s_dataset.csv", index=False)
        elif not new_keys:
            report = {
                "ok": True, "mode": "noop",
                "message": "no new runs since last train",
                "elapsed_s": round(time.time() - t0, 2),
            }
            _LAST_REPORT = report
            publish({"type": "log", "tag": "train",
                     "msg": "live train skipped — no new runs (already trained)",
                     "ts": time.time()})
            publish({"type": "ids", "data": {
                "event": "retrain", "status": "done", "mode": "noop",
                "message": "No new runs to fine-tune",
            }})
            return report
        else:
            # Models exist + there are untrained runs (including first time
            # after a manual cnn train with empty live_train_state).
            # Always refresh CNN/LGBM — never "seed" and skip learning.
            if not trained:
                publish({"type": "log", "tag": "train",
                         "msg": (f"model present but no train history — "
                                 f"fine-tuning on {len(new_keys)} run(s)…"),
                         "ts": time.time()})
            else:
                publish({"type": "log", "tag": "train",
                         "msg": (f"fine-tune — {len(new_keys)} new run(s) only, "
                                 f"keeping prior trees + {_FINETUNE_ROUNDS} rounds"),
                         "ts": time.time()})
            publish({"type": "ids", "data": {
                "event": "retrain", "status": "running", "mode": "finetune",
                "message": f"Fine-tuning on {len(new_keys)} new run(s)…",
                "new_runs": new_keys,
            }})
            mode = "finetune"
            try:
                (phys, phys_feats, net, net_feats, fused, fused_feats,
                 phys_raw, net_raw) = _load_new_run_frames(new_keys)
            except Exception:
                # Fallback: rebuild merged tables then train on everything.
                summary = bd.build()
                new_keys = all_keys
                phys_raw = pd.read_csv(datasets_dir / "physical_processed_dataset.csv")
                net_raw = pd.read_csv(datasets_dir / "network_processed_dataset.csv")
                phys, phys_feats = prepare_physical_frame(phys_raw)
                net, net_feats = prepare_network_frame(net_raw)
                fused, fused_feats = build_fused_dataset(phys_raw, net_raw)
                fused.to_csv(out_dir / "fused_1s_dataset.csv", index=False)
                mode = "full"
            else:
                summary = {
                    "mode": "finetune",
                    "appended_runs": new_keys,
                    "files": [
                        {"name": "new_physical", "rows": int(len(phys_raw))},
                        {"name": "new_network", "rows": int(len(net_raw))},
                    ],
                }

        modalities = [
            ("physical", phys, phys_feats, 30),
            ("network", net, net_feats, min(30, max(1, len(net_feats)))),
            ("fusion", fused, fused_feats, 30),
        ]

        new_frames = {n: f for n, f, _, _ in modalities}
        if mode == "finetune":
            ok, reason = _can_finetune(out_dir, modalities, new_frames)
            if not ok:
                publish({"type": "log", "tag": "train",
                         "msg": f"fine-tune blocked ({reason}) — falling back to full retrain",
                         "ts": time.time()})
                summary = bd.build()
                phys_raw = pd.read_csv(datasets_dir / "physical_processed_dataset.csv")
                net_raw = pd.read_csv(datasets_dir / "network_processed_dataset.csv")
                phys, phys_feats = prepare_physical_frame(phys_raw)
                net, net_feats = prepare_network_frame(net_raw)
                fused, fused_feats = build_fused_dataset(phys_raw, net_raw)
                fused.to_csv(out_dir / "fused_1s_dataset.csv", index=False)
                modalities = [
                    ("physical", phys, phys_feats, 30),
                    ("network", net, net_feats, min(30, len(net_feats))),
                    ("fusion", fused, fused_feats, 30),
                ]
                mode = "full"
                new_frames = {n: f for n, f, _, _ in modalities}

        report = {"modalities": {}, "dataset": summary, "elapsed_s": None,
                  "mode": mode, "new_runs": new_keys, "primary_model": primary}

        # LightGBM is optional backup — never let it fail the primary CNN live train.
        if have_lgbm or mode == "full":
            for name, frame, feats, k in modalities:
                if frame is None or frame.empty or not feats:
                    publish({"type": "log", "tag": "train",
                             "msg": f"{name}: skipped (no rows/features)",
                             "ts": time.time()})
                    continue
                try:
                    if mode == "finetune":
                        nf = new_frames[name]
                        if nf.empty:
                            continue
                        X = nf[feats].to_numpy(dtype=np.float32)
                        y_bin = nf["label_binary"].astype(int).to_numpy()
                        y_cls = nf["label_class"].astype(str).to_numpy()
                        bundle = _load_bundle(out_dir, name)
                        selected = list(bundle["feature_cols"])
                        prev_bin = joblib.load(out_dir / f"{name}_binary.joblib")
                        prev_multi = joblib.load(out_dir / f"{name}_multiclass.joblib")
                        le = joblib.load(out_dir / f"{name}_label_encoder.joblib")
                        binary, bm = _finetune_binary(
                            X, y_bin, selected, feats, prev_bin)
                        multi, mm = _finetune_multi(
                            X, y_cls, selected, feats, prev_multi, le)
                        metrics = {"binary": bm, "multiclass": mm,
                                   "n_features": len(selected), "selected": selected,
                                   "mode": "finetune"}
                    else:
                        X = frame[feats].to_numpy(dtype=np.float32)
                        y_bin = frame["label_binary"].astype(int).to_numpy()
                        y_cls = frame["label_class"].astype(str).to_numpy()
                        groups = frame["run_id"].astype(str).to_numpy()
                        binary, selected, bm = _quick_binary(
                            X, y_bin, groups, feats, top_k=k)
                        multi, le, mm = _quick_multi(
                            X, y_cls, groups, feats, selected)
                        metrics = {"binary": bm, "multiclass": mm,
                                   "n_features": len(selected), "selected": selected,
                                   "mode": "full"}
                    _save_modality(
                        name, out_dir, binary, multi, le, selected, feats, metrics)
                    report["modalities"][name] = metrics
                    publish({"type": "log", "tag": "train",
                             "msg": (f"{name} [{mode}]: rows={metrics['binary']['n_rows']} "
                                     f"F1_atk={metrics['binary'].get('f1_attack')} "
                                     f"multi_F1={metrics['multiclass'].get('f1_macro')}"),
                             "ts": time.time()})
                except Exception as exc:  # noqa: BLE001
                    publish({"type": "log", "tag": "train",
                             "msg": f"{name} LightGBM skipped ({exc})",
                             "ts": time.time()})

        # ---- PRIMARY live model: Tiny MAVLink 1D-CNN (always refresh)
        publish({"type": "log", "tag": "train",
                 "msg": "live train primary model — TinyMAV 1D-CNN…",
                 "ts": time.time()})
        # Ensure merged CSVs include new runs before CNN train
        if mode == "finetune" and new_keys:
            try:
                bd.append_runs(list(new_keys))
            except Exception:
                pass
        try:
            from ids.cnn_train import train_cnn
            cnn_epochs = 8 if mode == "finetune" else 14
            cnn_meta = train_cnn(
                datasets_dir=datasets_dir, out_dir=out_dir, epochs=cnn_epochs)
            report["cnn1d"] = {
                "ok": True,
                **(cnn_meta.get("holdout") or {}),
                "epochs": cnn_epochs,
            }
            publish({"type": "log", "tag": "train",
                     "msg": (f"cnn1d live train OK — F1_atk="
                             f"{(cnn_meta.get('holdout') or {}).get('f1_attack')} "
                             f"lat={(cnn_meta.get('holdout') or {}).get('latency_ms_single')}ms"),
                     "ts": time.time()})
        except Exception as exc:  # noqa: BLE001
            report["cnn1d"] = {"ok": False, "error": str(exc)}
            publish({"type": "log", "tag": "train",
                     "msg": f"cnn1d live train FAILED: {exc}",
                     "ts": time.time()})
            if primary == "cnn1d":
                raise RuntimeError(f"primary cnn1d live train failed: {exc}") from exc

        report["elapsed_s"] = round(time.time() - t0, 2)
        report["ok"] = bool((report.get("cnn1d") or {}).get("ok", primary != "cnn1d"))
        report["artifacts_dir"] = str(out_dir)
        report["trained_at"] = datetime.now(timezone.utc).isoformat()
        (out_dir / "online_summary.json").write_text(json.dumps(report, indent=2))
        _LAST_REPORT = report
        _write_state(
            live_train=_LIVE_TRAIN,
            trained_run_ids=all_keys,
            last_mode=f"{mode}+cnn1d",
        )
        cnn_f1 = (report.get("cnn1d") or {}).get("f1_attack")
        publish({"type": "log", "tag": "train",
                 "msg": (f"live train done in {report['elapsed_s']}s — "
                         f"primary=cnn1d F1_atk={cnn_f1}"
                         + (f" ({len(new_keys)} new runs)" if new_keys else "")),
                 "ts": time.time()})
        publish({"type": "ids", "data": {
            "event": "retrain", "status": "done", "mode": f"{mode}+cnn1d",
            "message": (f"Primary TinyMAV 1D-CNN updated ({report['elapsed_s']}s)"
                        + (f" F1={cnn_f1}" if cnn_f1 is not None else "")),
            "primary_model": "cnn1d",
            "cnn1d": report.get("cnn1d"),
            "report": {
                k: {
                    "f1_attack": v["binary"].get("f1_attack"),
                    "f1_macro": v["multiclass"].get("f1_macro"),
                    "n_rows": v["binary"].get("n_rows"),
                } for k, v in report["modalities"].items()
            },
        }})
        return report
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        class_mismatch = (
            "Number of class for initial score" in msg
            or "cannot fine-tune multiclass" in msg
            or "collapsed classes" in msg
        )
        if class_mismatch and not force_full:
            publish({"type": "log", "tag": "train",
                     "msg": (f"fine-tune class mismatch ({msg}) — "
                             "auto-recovering with full retrain…"),
                     "ts": time.time()})
            # Release the training lock before the recursive full retrain.
            with _LOCK:
                _TRAINING = False
            return retrain_and_save(
                datasets_dir=datasets_dir, out_dir=out_dir,
                publish=publish, force_full=True,
            )
        err = {"ok": False, "message": msg}
        _LAST_REPORT = err
        publish({"type": "log", "tag": "train",
                 "msg": f"live retrain FAILED: {exc}", "ts": time.time()})
        publish({"type": "ids", "data": {
            "event": "retrain", "status": "error", "message": msg,
        }})
        return err
    finally:
        _TRAINING = False


def retrain_async(publish: PublishFn | None = None, on_done: Callable | None = None,
                  force_full: bool = False):
    """Fire-and-forget retrain in a daemon thread."""
    def _go():
        report = retrain_and_save(publish=publish, force_full=force_full)
        if on_done:
            try:
                on_done(report)
            except Exception:
                pass
    threading.Thread(target=_go, daemon=True).start()
