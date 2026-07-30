"""Train the tiny MAVLink 1D-CNN on stacked network windows."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

from ids.cnn_model import (
    DEFAULT_SEQ_LEN,
    META_NAME,
    WEIGHTS_NAME,
    TinyMAV1DCNN,
    default_feature_cols,
)
from ids.features import NETWORK_CORE

try:
    from config import DATASETS_DIR, ROOT
except ImportError:  # pragma: no cover
    ROOT = Path(__file__).resolve().parent.parent
    DATASETS_DIR = ROOT / "datasets"

ARTIFACTS = ROOT / "ids" / "artifacts"


def _require_torch():
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "PyTorch required. Install:\n"
            "  pip install torch --index-url https://download.pytorch.org/whl/cpu"
        ) from exc
    return torch, nn, DataLoader, TensorDataset


def build_sequences(
    df: pd.DataFrame,
    feature_cols: list[str],
    seq_len: int = DEFAULT_SEQ_LEN,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Return X (N,C,T), y_bin, y_cls (str), groups (run ids)."""
    need = ["scenario", "run", "t_rel", "label_binary", "label_class", *feature_cols]
    missing = [c for c in need if c not in df.columns]
    if missing:
        raise ValueError(f"network dataset missing columns: {missing}")

    work = df[need].copy()
    work["run_id"] = work["scenario"].astype(str) + "|" + work["run"].astype(str)
    work = work.sort_values(["run_id", "t_rel"])

    xs, yb, yc, groups = [], [], [], []
    for rid, g in work.groupby("run_id", sort=False):
        feats = g[feature_cols].to_numpy(dtype=np.float32)
        bins = g["label_binary"].to_numpy(dtype=np.int64)
        clss = g["label_class"].astype(str).to_numpy()
        n = len(g)
        if n < 3:
            continue
        for i in range(n):
            start = max(0, i - seq_len + 1)
            window = feats[start : i + 1]
            if len(window) < seq_len:
                pad = np.repeat(window[:1], seq_len - len(window), axis=0)
                window = np.concatenate([pad, window], axis=0)
            # (T, C) -> (C, T)
            xs.append(window.T)
            yb.append(int(bins[i]))
            yc.append(clss[i])
            groups.append(rid)
    X = np.stack(xs, axis=0)
    return X, np.asarray(yb), np.asarray(yc), np.asarray(groups)


def train_cnn(
    datasets_dir: Path | None = None,
    out_dir: Path | None = None,
    seq_len: int = DEFAULT_SEQ_LEN,
    epochs: int = 18,
    batch_size: int = 256,
    lr: float = 1e-3,
    width: int = 32,
    seed: int = 42,
) -> dict[str, Any]:
    torch, nn, DataLoader, TensorDataset = _require_torch()
    torch.manual_seed(seed)
    np.random.seed(seed)

    datasets_dir = Path(datasets_dir or DATASETS_DIR)
    out_dir = Path(out_dir or ARTIFACTS)
    out_dir.mkdir(parents=True, exist_ok=True)

    path = datasets_dir / "network_processed_dataset.csv"
    if not path.exists():
        raise FileNotFoundError(path)

    df = pd.read_csv(path)
    feature_cols = [c for c in NETWORK_CORE if c in df.columns]
    if len(feature_cols) < 8:
        feature_cols = default_feature_cols()
        feature_cols = [c for c in feature_cols if c in df.columns]

    print(f"[cnn] building sequences seq_len={seq_len} feats={len(feature_cols)} …")
    X, y_bin, y_cls, groups = build_sequences(df, feature_cols, seq_len=seq_len)
    if len(X) < 4:
        raise ValueError(
            f"Too few network sequences to train CNN (got {len(X)}). "
            "Re-run with Network capture ON and wait for a fuller flight."
        )
    print(f"[cnn] sequences={len(X)} attack_rate={float(y_bin.mean()):.3f} "
          f"runs={len(np.unique(groups))}")

    # Run-wise holdout when we have ≥2 runs; otherwise split windows inside
    # the single run (common after the first dashboard scenario).
    n_groups = len(np.unique(groups))
    holdout_mode = "group"
    if n_groups >= 2 and len(X) >= 12:
        test_size = 0.22 if n_groups >= 3 else 0.5
        # Need at least 1 group in each split
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        try:
            tr_idx, te_idx = next(gss.split(X, y_bin, groups))
        except ValueError:
            holdout_mode = "window"
            tr_idx = te_idx = None  # type: ignore[assignment]
    else:
        holdout_mode = "window"
        tr_idx = te_idx = None  # type: ignore[assignment]

    if holdout_mode == "window" or tr_idx is None:
        from sklearn.model_selection import train_test_split
        idx = np.arange(len(X))
        strat = y_bin if len(np.unique(y_bin)) > 1 else None
        try:
            tr_idx, te_idx = train_test_split(
                idx,
                test_size=max(0.15, min(0.30, max(2, int(0.2 * len(X))) / len(X))),
                random_state=seed,
                stratify=strat,
            )
        except ValueError:
            # Tiny / unbalanced — take a simple tail holdout
            n_te = max(1, min(len(X) // 5, len(X) - 2))
            tr_idx = idx[:-n_te]
            te_idx = idx[-n_te:]
        print(f"[cnn] single-run/window holdout "
              f"(train={len(tr_idx)} test={len(te_idx)})")
    else:
        print(f"[cnn] group holdout train={len(tr_idx)} test={len(te_idx)} "
              f"runs={n_groups}")

    Xtr, Xte = X[tr_idx], X[te_idx]
    yb_tr, yb_te = y_bin[tr_idx], y_bin[te_idx]
    yc_tr, yc_te = y_cls[tr_idx], y_cls[te_idx]

    mean = Xtr.mean(axis=(0, 2)).astype(np.float32)
    std = Xtr.std(axis=(0, 2)).astype(np.float32)
    std = np.where(std < 1e-6, 1.0, std)

    def _norm(a: np.ndarray) -> np.ndarray:
        return ((a - mean[:, None]) / std[:, None]).astype(np.float32)

    Xtr_n, Xte_n = _norm(Xtr), _norm(Xte)

    le = LabelEncoder()
    # Fit on all classes present in full data for stable head size
    le.fit(sorted(set(y_cls.tolist()) | {"benign"}))
    ym_tr = le.transform(yc_tr)
    ym_te = le.transform(yc_te)
    n_classes = len(le.classes_)

    device = torch.device("cpu")
    model = TinyMAV1DCNN(in_ch=len(feature_cols), n_classes=n_classes, width=width).to(device)

    # Class weights (tolerate single-class early datasets)
    try:
        bw = compute_class_weight("balanced", classes=np.array([0, 1]), y=yb_tr)
        pos_w = float(bw[1] / max(bw[0], 1e-6)) if len(bw) > 1 else 1.0
    except ValueError:
        pos_w = 1.0
    pos_weight = torch.tensor([pos_w], device=device)
    try:
        present = np.unique(ym_tr)
        cw = np.ones(n_classes, dtype=np.float32)
        if len(present) > 1:
            w = compute_class_weight("balanced", classes=present, y=ym_tr)
            for c, wi in zip(present, w):
                cw[int(c)] = float(wi)
        multi_w = torch.tensor(cw, dtype=torch.float32, device=device)
    except ValueError:
        multi_w = torch.ones(n_classes, dtype=torch.float32, device=device)

    bce = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    ce = nn.CrossEntropyLoss(weight=multi_w)

    ds = TensorDataset(
        torch.from_numpy(Xtr_n),
        torch.from_numpy(yb_tr.astype(np.float32)),
        torch.from_numpy(ym_tr.astype(np.int64)),
    )
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True, drop_last=False)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

    t0 = time.time()
    model.train()
    for epoch in range(1, epochs + 1):
        total, n = 0.0, 0
        for xb, yb, ym in loader:
            xb = xb.to(device)
            yb = yb.to(device)
            ym = ym.to(device)
            opt.zero_grad(set_to_none=True)
            logit, multi = model(xb)
            loss = bce(logit, yb) + 0.85 * ce(multi, ym)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 2.0)
            opt.step()
            total += float(loss.item()) * len(xb)
            n += len(xb)
        if epoch == 1 or epoch % 3 == 0 or epoch == epochs:
            print(f"[cnn] epoch {epoch:02d}/{epochs} loss={total / max(n, 1):.4f}")

    # Eval
    model.eval()
    with torch.no_grad():
        logit, multi = model(torch.from_numpy(Xte_n).to(device))
        proba = torch.sigmoid(logit).cpu().numpy()
        pred_bin = (proba >= 0.55).astype(int)
        pred_cls = multi.argmax(dim=-1).cpu().numpy()

    prec, rec, f1, _ = precision_recall_fscore_support(
        yb_te, pred_bin, average="binary", zero_division=0
    )
    try:
        auc = float(roc_auc_score(yb_te, proba))
    except ValueError:
        auc = None
    f1_macro = float(f1_score(
        ym_te, pred_cls,
        labels=list(range(n_classes)),
        average="macro",
        zero_division=0,
    ))
    # Holdout may lack some rare attack classes; pin labels to the full encoder
    # so target_names length always matches (avoids sklearn ValueError).
    report = classification_report(
        ym_te, pred_cls,
        labels=list(range(n_classes)),
        target_names=[str(c) for c in le.classes_],
        zero_division=0,
    )

    # Latency probe
    x1 = torch.from_numpy(Xte_n[:1]).to(device)
    for _ in range(8):
        model(x1)
    t_lat0 = time.perf_counter()
    for _ in range(50):
        model(x1)
    lat_ms = (time.perf_counter() - t_lat0) / 50 * 1000.0

    torch.save(model.state_dict(), out_dir / WEIGHTS_NAME)
    meta = {
        "model": "TinyMAV1DCNN",
        "feature_cols": feature_cols,
        "seq_len": seq_len,
        "width": width,
        "classes": list(le.classes_),
        "mean": mean.tolist(),
        "std": std.tolist(),
        "binary_threshold": 0.55,
        "live_binary_threshold": 0.72,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_train": int(len(Xtr)),
        "n_test": int(len(Xte)),
        "holdout_mode": holdout_mode,
        "holdout": {
            "precision_attack": float(prec),
            "recall_attack": float(rec),
            "f1_attack": float(f1),
            "roc_auc": auc,
            "f1_macro_multiclass": f1_macro,
            "latency_ms_single": round(lat_ms, 4),
        },
        "epochs": epochs,
        "train_seconds": round(time.time() - t0, 2),
        "notes": (
            "Lightweight 1D-CNN on stacked 1s MAVLink windows. "
            "Fuse with LightGBM cascade at live inference."
        ),
    }
    (out_dir / META_NAME).write_text(json.dumps(meta, indent=2))
    (out_dir / "cnn_mav1d_report.txt").write_text(report)
    print("\n==== TINY MAV 1D-CNN SUMMARY ====")
    print(json.dumps(meta["holdout"], indent=2))
    print(f"Wrote {out_dir / WEIGHTS_NAME}")
    print(f"Wrote {out_dir / META_NAME}")
    return meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Train tiny MAVLink 1D-CNN IDS")
    p.add_argument("--datasets-dir", type=Path, default=None)
    p.add_argument("--out-dir", type=Path, default=None)
    p.add_argument("--seq-len", type=int, default=DEFAULT_SEQ_LEN)
    p.add_argument("--epochs", type=int, default=18)
    p.add_argument("--batch-size", type=int, default=256)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--width", type=int, default=32)
    args = p.parse_args(argv)
    train_cnn(
        datasets_dir=args.datasets_dir,
        out_dir=args.out_dir,
        seq_len=args.seq_len,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        width=args.width,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
