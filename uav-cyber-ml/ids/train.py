"""Train lightweight LightGBM IDS models with run-wise validation."""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
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

MODELS_DIR = ROOT / "ids" / "artifacts"


@dataclass
class SplitResult:
    modality: str
    task: str
    fold: int
    accuracy: float
    f1_macro: float
    f1_weighted: float
    recall_attack: float | None
    precision_attack: float | None
    roc_auc: float | None
    n_train: int
    n_test: int


def _load_csvs(datasets_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    phys = pd.read_csv(datasets_dir / "physical_processed_dataset.csv")
    net = pd.read_csv(datasets_dir / "network_processed_dataset.csv")
    return phys, net


def _class_weights(y: np.ndarray) -> dict[int, float]:
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    return {int(c): float(w) for c, w in zip(classes, weights)}


def _lgbm_binary(**overrides: Any) -> lgb.LGBMClassifier:
    params = dict(
        n_estimators=200,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=6,
        subsample=0.9,
        colsample_bytree=0.8,
        min_child_samples=20,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbosity=-1,
    )
    params.update(overrides)
    return lgb.LGBMClassifier(**params)


def _lgbm_multi(n_class: int, **overrides: Any) -> lgb.LGBMClassifier:
    params = dict(
        objective="multiclass",
        num_class=n_class,
        n_estimators=250,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=6,
        subsample=0.9,
        colsample_bytree=0.8,
        min_child_samples=15,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbosity=-1,
    )
    params.update(overrides)
    return lgb.LGBMClassifier(**params)


def _binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, y_pred: np.ndarray) -> dict:
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    try:
        auc = float(roc_auc_score(y_true, y_prob))
    except ValueError:
        auc = None
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "precision_attack": float(prec),
        "recall_attack": float(rec),
        "f1_attack": float(f1),
        "roc_auc": auc,
    }


def _multi_metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str]) -> dict:
    label_ids = list(range(len(labels)))
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1_macro": float(
            f1_score(y_true, y_pred, labels=label_ids, average="macro", zero_division=0)
        ),
        "f1_weighted": float(
            f1_score(y_true, y_pred, labels=label_ids, average="weighted", zero_division=0)
        ),
        "report": classification_report(
            y_true,
            y_pred,
            labels=label_ids,
            target_names=labels,
            zero_division=0,
            output_dict=True,
        ),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=label_ids).tolist(),
        "labels": labels,
    }


def run_group_cv_binary(
    X: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray,
    n_splits: int = 5,
) -> tuple[list[dict], dict]:
    gkf = GroupKFold(n_splits=min(n_splits, len(np.unique(groups))))
    fold_metrics: list[dict] = []
    oof_prob = np.zeros(len(y), dtype=float)
    oof_pred = np.zeros(len(y), dtype=int)

    for fold, (tr, te) in enumerate(gkf.split(X, y, groups), start=1):
        model = _lgbm_binary()
        sw = np.array([_class_weights(y[tr]).get(int(v), 1.0) for v in y[tr]])
        model.fit(X[tr], y[tr], sample_weight=sw)
        prob = model.predict_proba(X[te])[:, 1]
        pred = (prob >= 0.5).astype(int)
        oof_prob[te] = prob
        oof_pred[te] = pred
        m = _binary_metrics(y[te], prob, pred)
        m.update({"fold": fold, "n_train": int(len(tr)), "n_test": int(len(te))})
        fold_metrics.append(m)

    overall = _binary_metrics(y, oof_prob, oof_pred)
    return fold_metrics, overall


def run_group_cv_multi(
    X: np.ndarray,
    y_enc: np.ndarray,
    groups: np.ndarray,
    class_names: list[str],
    n_splits: int = 5,
) -> tuple[list[dict], dict]:
    gkf = GroupKFold(n_splits=min(n_splits, len(np.unique(groups))))
    fold_metrics: list[dict] = []
    oof_pred = np.zeros(len(y_enc), dtype=int)

    for fold, (tr, te) in enumerate(gkf.split(X, y_enc, groups), start=1):
        model = _lgbm_multi(n_class=len(class_names))
        sw = np.array([_class_weights(y_enc[tr]).get(int(v), 1.0) for v in y_enc[tr]])
        model.fit(X[tr], y_enc[tr], sample_weight=sw)
        pred = model.predict(X[te])
        oof_pred[te] = pred
        m = {
            "fold": fold,
            "accuracy": float(accuracy_score(y_enc[te], pred)),
            "f1_macro": float(f1_score(y_enc[te], pred, average="macro", zero_division=0)),
            "f1_weighted": float(
                f1_score(y_enc[te], pred, average="weighted", zero_division=0)
            ),
            "n_train": int(len(tr)),
            "n_test": int(len(te)),
        }
        fold_metrics.append(m)

    overall = _multi_metrics(y_enc, oof_pred, class_names)
    return fold_metrics, overall


def _holdout_indices(groups: np.ndarray, test_size: float = 0.25, seed: int = 42):
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    X_dummy = np.zeros(len(groups))
    y_dummy = np.zeros(len(groups))
    tr, te = next(splitter.split(X_dummy, y_dummy, groups))
    return tr, te


def _bench_latency(model, X: np.ndarray, loops: int = 200) -> dict:
    # Warmup
    for _ in range(10):
        model.predict(X[:1])
    t0 = time.perf_counter()
    for _ in range(loops):
        model.predict(X[:1])
    elapsed = time.perf_counter() - t0
    per = (elapsed / loops) * 1000.0
    batch = X[: min(64, len(X))]
    t1 = time.perf_counter()
    for _ in range(50):
        model.predict(batch)
    batch_ms = ((time.perf_counter() - t1) / 50.0) * 1000.0
    return {
        "single_sample_ms": round(per, 4),
        "batch64_ms": round(batch_ms, 4),
        "loops": loops,
    }


def train_modality(
    name: str,
    frame: pd.DataFrame,
    feature_cols: list[str],
    out_dir: Path,
    top_k: int,
    n_splits: int,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    X = frame[feature_cols].to_numpy(dtype=np.float32)
    y_bin = frame["label_binary"].astype(int).to_numpy()
    y_cls = frame["label_class"].astype(str).to_numpy()
    groups = frame["run_id"].astype(str).to_numpy()

    print(f"\n=== Modality: {name} | rows={len(frame)} feats={len(feature_cols)} "
          f"runs={len(np.unique(groups))} ===")

    # ---- Binary CV ----
    bin_folds, bin_overall = run_group_cv_binary(X, y_bin, groups, n_splits=n_splits)
    print(
        f"[{name}] binary CV  acc={bin_overall['accuracy']:.3f}  "
        f"F1_atk={bin_overall['f1_attack']:.3f}  "
        f"recall={bin_overall['recall_attack']:.3f}  "
        f"AUC={bin_overall['roc_auc']}"
    )

    # ---- Multiclass CV ----
    le = LabelEncoder()
    y_enc = le.fit_transform(y_cls)
    class_names = list(le.classes_)
    multi_folds, multi_overall = run_group_cv_multi(
        X, y_enc, groups, class_names, n_splits=n_splits
    )
    print(
        f"[{name}] multi  CV  acc={multi_overall['accuracy']:.3f}  "
        f"F1_macro={multi_overall['f1_macro']:.3f}"
    )

    # ---- Final holdout train (export) ----
    tr, te = _holdout_indices(groups, test_size=0.25, seed=42)
    sw_bin = np.array([_class_weights(y_bin[tr]).get(int(v), 1.0) for v in y_bin[tr]])
    bin_model = _lgbm_binary()
    bin_model.fit(X[tr], y_bin[tr], sample_weight=sw_bin)

    # Feature selection from binary importances → compact onboard set
    imp = bin_model.feature_importances_.astype(float)
    selected = top_k_features(imp, feature_cols, k=min(top_k, len(feature_cols)))
    sel_idx = [feature_cols.index(c) for c in selected]
    X_sel = X[:, sel_idx]

    bin_compact = _lgbm_binary(n_estimators=180, num_leaves=24, max_depth=5)
    bin_compact.fit(X_sel[tr], y_bin[tr], sample_weight=sw_bin)
    te_prob = bin_compact.predict_proba(X_sel[te])[:, 1]
    te_pred = (te_prob >= 0.5).astype(int)
    holdout_bin = _binary_metrics(y_bin[te], te_prob, te_pred)

    sw_multi = np.array([_class_weights(y_enc[tr]).get(int(v), 1.0) for v in y_enc[tr]])
    multi_model = _lgbm_multi(n_class=len(class_names), n_estimators=220, num_leaves=24)
    multi_model.fit(X_sel[tr], y_enc[tr], sample_weight=sw_multi)
    multi_pred = multi_model.predict(X_sel[te])
    holdout_multi = _multi_metrics(y_enc[te], multi_pred, class_names)

    latency = _bench_latency(bin_compact, X_sel[te])
    latency_multi = _bench_latency(multi_model, X_sel[te])

    # Persist
    bundle = {
        "modality": name,
        "feature_cols_full": feature_cols,
        "feature_cols": selected,
        "label_encoder_classes": class_names,
        "defense_actions": DEFENSE_ACTIONS,
        "binary_threshold": 0.5,
        "top_k": len(selected),
    }
    joblib.dump(bin_compact, out_dir / f"{name}_binary.joblib")
    joblib.dump(multi_model, out_dir / f"{name}_multiclass.joblib")
    joblib.dump(le, out_dir / f"{name}_label_encoder.joblib")
    (out_dir / f"{name}_bundle.json").write_text(json.dumps(bundle, indent=2))

    # Importance table
    compact_imp = sorted(
        zip(selected, bin_compact.feature_importances_.tolist()),
        key=lambda x: x[1],
        reverse=True,
    )
    (out_dir / f"{name}_feature_importance.json").write_text(
        json.dumps([{"feature": f, "importance": float(i)} for f, i in compact_imp], indent=2)
    )

    model_bytes = (out_dir / f"{name}_binary.joblib").stat().st_size
    multi_bytes = (out_dir / f"{name}_multiclass.joblib").stat().st_size

    report = {
        "modality": name,
        "n_rows": int(len(frame)),
        "n_runs": int(len(np.unique(groups))),
        "n_features_full": len(feature_cols),
        "n_features_selected": len(selected),
        "selected_features": selected,
        "cv_binary": {"folds": bin_folds, "overall": bin_overall},
        "cv_multiclass": {"folds": multi_folds, "overall": {
            k: multi_overall[k] for k in ("accuracy", "f1_macro", "f1_weighted", "labels")
        }},
        "holdout_binary": holdout_bin,
        "holdout_multiclass": {
            "accuracy": holdout_multi["accuracy"],
            "f1_macro": holdout_multi["f1_macro"],
            "f1_weighted": holdout_multi["f1_weighted"],
            "labels": holdout_multi["labels"],
            "confusion_matrix": holdout_multi["confusion_matrix"],
            "per_class_f1": {
                lbl: holdout_multi["report"][lbl]["f1-score"]
                for lbl in class_names
                if lbl in holdout_multi["report"]
            },
        },
        "deploy": {
            "binary_model_kb": round(model_bytes / 1024.0, 2),
            "multiclass_model_kb": round(multi_bytes / 1024.0, 2),
            "latency_binary_ms": latency,
            "latency_multiclass_ms": latency_multi,
            "target_loop_hz": 10 if name == "physical" else 1,
            "notes": (
                "Run-wise GroupKFold + GroupShuffleSplit holdout. "
                "Compact LightGBM ready for companion-computer joblib/ONNX export."
            ),
        },
    }
    (out_dir / f"{name}_metrics.json").write_text(json.dumps(report, indent=2))
    print(
        f"[{name}] holdout binary F1_atk={holdout_bin['f1_attack']:.3f} "
        f"recall={holdout_bin['recall_attack']:.3f} | "
        f"multi F1_macro={holdout_multi['f1_macro']:.3f} | "
        f"latency={latency['single_sample_ms']:.3f} ms | "
        f"size={report['deploy']['binary_model_kb']} KB"
    )
    return report


def train_all(
    datasets_dir: Path | None = None,
    out_dir: Path | None = None,
    top_k: int = 30,
    n_splits: int = 5,
) -> dict:
    datasets_dir = Path(datasets_dir or DATASETS_DIR)
    out_dir = Path(out_dir or MODELS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    phys_raw, net_raw = _load_csvs(datasets_dir)

    phys, phys_feats = prepare_physical_frame(phys_raw)
    net, net_feats = prepare_network_frame(net_raw)
    fused, fused_feats = build_fused_dataset(phys_raw, net_raw)

    # Persist fused table for inspection / future live alignment tests
    fused_path = out_dir / "fused_1s_dataset.csv"
    fused.to_csv(fused_path, index=False)
    print(f"Wrote fused dataset → {fused_path} ({len(fused)} rows, {len(fused_feats)} feats)")

    reports = {}
    reports["physical"] = train_modality(
        "physical", phys, phys_feats, out_dir, top_k=top_k, n_splits=n_splits
    )
    reports["network"] = train_modality(
        "network", net, net_feats, out_dir, top_k=min(top_k, len(net_feats)), n_splits=n_splits
    )
    reports["fusion"] = train_modality(
        "fusion", fused, fused_feats, out_dir, top_k=top_k, n_splits=n_splits
    )

    summary = {
        "artifacts_dir": str(out_dir),
        "recommendation": _recommend(reports),
        "modalities": {
            k: {
                "holdout_binary_f1_attack": v["holdout_binary"]["f1_attack"],
                "holdout_binary_recall": v["holdout_binary"]["recall_attack"],
                "holdout_binary_precision": v["holdout_binary"]["precision_attack"],
                "holdout_multi_f1_macro": v["holdout_multiclass"]["f1_macro"],
                "latency_ms": v["deploy"]["latency_binary_ms"]["single_sample_ms"],
                "model_kb": v["deploy"]["binary_model_kb"],
                "n_features": v["n_features_selected"],
            }
            for k, v in reports.items()
        },
    }
    # Lightweight MAVLink 1D-CNN (optional — requires torch)
    try:
        from ids.cnn_train import train_cnn
        print("\n[cnn] training TinyMAV 1D-CNN …")
        summary["cnn1d"] = train_cnn(datasets_dir=datasets_dir, out_dir=out_dir)
    except Exception as exc:  # noqa: BLE001
        summary["cnn1d"] = {"skipped": True, "error": str(exc)}
        print(f"[cnn] skipped: {exc}")

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (out_dir / "full_report.json").write_text(json.dumps(reports, indent=2))
    print("\n==== IDS TRAINING SUMMARY ====")
    print(json.dumps(summary, indent=2))
    return summary


def _recommend(reports: dict) -> str:
    # Prefer fusion when binary F1 is within 1 pt of the best modality —
    # it wins on attack typing (multiclass) for closed-loop defense.
    scored = []
    for name, r in reports.items():
        f1 = r["holdout_binary"]["f1_attack"]
        mf1 = r["holdout_multiclass"]["f1_macro"]
        lat = r["deploy"]["latency_binary_ms"]["single_sample_ms"]
        scored.append((name, f1, mf1, lat))
    best_f1 = max(t[1] for t in scored)
    candidates = [t for t in scored if t[1] >= best_f1 - 0.01]
    candidates.sort(key=lambda t: (t[2], t[1], -t[3]), reverse=True)
    best = candidates[0][0]
    return (
        f"Primary deploy modality: '{best}'. "
        "Always run Stage-0 rules; Stage-1 binary every network/physical tick; "
        "Stage-2 multiclass only on alert to choose the defense action. "
        "If onboard capture is unavailable, fall back to 'physical' (~10 Hz). "
        "Keep 'network' as a fast cyber-only detector when MAVLink counters exist."
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Train UAV cyber-physical IDS models")
    p.add_argument("--datasets-dir", type=Path, default=None)
    p.add_argument("--out-dir", type=Path, default=None)
    p.add_argument("--top-k", type=int, default=30, help="Max features kept for onboard model")
    p.add_argument("--splits", type=int, default=5, help="GroupKFold splits (by run)")
    args = p.parse_args(argv)
    train_all(
        datasets_dir=args.datasets_dir,
        out_dir=args.out_dir,
        top_k=args.top_k,
        n_splits=args.splits,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
