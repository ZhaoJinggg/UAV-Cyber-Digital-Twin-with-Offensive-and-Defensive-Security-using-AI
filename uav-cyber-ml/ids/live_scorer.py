"""Realtime cascade scorer: Stage-0 rules → Stage-1 binary → Stage-2 multiclass."""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from ids.rules import DEFENSE_ACTIONS, RuleResult, evaluate_rules

try:
    from config import ROOT
except ImportError:  # pragma: no cover
    ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ARTIFACTS = ROOT / "ids" / "artifacts"


@dataclass
class IDSDecision:
    timestamp: float
    modality: str
    rules_triggered: bool
    rules_severity: str
    rule_hits: list[dict]
    attack_score: float
    attack_pred: int
    attack_class: str | None
    class_confidence: float | None
    action: str
    latency_ms: float


class CascadeIDS:
    """Load trained artifacts and score one feature vector at a time."""

    def __init__(self, artifacts_dir: Path | str, modality: str = "fusion"):
        self.artifacts_dir = Path(artifacts_dir)
        self.modality = modality
        bundle_path = self.artifacts_dir / f"{modality}_bundle.json"
        if not bundle_path.exists():
            raise FileNotFoundError(
                f"Missing {bundle_path}. Train first: python -m ids.train"
            )
        self.bundle = json.loads(bundle_path.read_text())
        self.feature_cols: list[str] = list(self.bundle["feature_cols"])
        self.threshold = float(self.bundle.get("binary_threshold", 0.5))
        self.binary = joblib.load(self.artifacts_dir / f"{modality}_binary.joblib")
        self.multi = joblib.load(self.artifacts_dir / f"{modality}_multiclass.joblib")
        self.label_encoder = joblib.load(
            self.artifacts_dir / f"{modality}_label_encoder.joblib"
        )
        self.defense = dict(self.bundle.get("defense_actions") or DEFENSE_ACTIONS)

    def _vectorize(self, features: dict[str, Any]) -> np.ndarray:
        vec = np.zeros(len(self.feature_cols), dtype=np.float32)
        for i, name in enumerate(self.feature_cols):
            v = features.get(name, 0.0)
            try:
                vec[i] = 0.0 if v is None or (isinstance(v, float) and np.isnan(v)) else float(v)
            except (TypeError, ValueError):
                vec[i] = 0.0
        return vec.reshape(1, -1)

    def score(self, features: dict[str, Any]) -> IDSDecision:
        t0 = time.perf_counter()
        rules: RuleResult = evaluate_rules(features)
        x = self._vectorize(features)
        proba = float(self.binary.predict_proba(x)[0, 1])
        attack_pred = int(proba >= self.threshold or rules.max_severity == "critical")

        attack_class = None
        class_conf = None
        if attack_pred:
            probs = self.multi.predict_proba(x)[0]
            idx = int(np.argmax(probs))
            attack_class = str(self.label_encoder.classes_[idx])
            class_conf = float(probs[idx])
            # If rules strongly suggest a class-like hit, prefer mapped action.
            action = self.defense.get(attack_class, "hold_or_rtl")
        else:
            action = "none"

        if rules.triggered and rules.max_severity == "critical":
            # Prefer first critical rule action when ML is uncertain.
            crit = next(h for h in rules.hits if h.severity == "critical")
            if attack_class is None or class_conf is None or class_conf < 0.45:
                action = crit.suggested_action
                attack_class = attack_class or crit.name.replace("_suspected", "")
                attack_pred = 1

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return IDSDecision(
            timestamp=time.time(),
            modality=self.modality,
            rules_triggered=rules.triggered,
            rules_severity=rules.max_severity,
            rule_hits=[asdict(h) for h in rules.hits],
            attack_score=proba,
            attack_pred=attack_pred,
            attack_class=attack_class,
            class_confidence=class_conf,
            action=action,
            latency_ms=round(latency_ms, 4),
        )


def score_fused_csv(
    csv_path: Path,
    artifacts_dir: Path,
    modality: str = "fusion",
    limit: int | None = None,
) -> pd.DataFrame:
    """Offline replay of the cascade on a fused CSV (for validation)."""
    ids = CascadeIDS(artifacts_dir, modality=modality)
    df = pd.read_csv(csv_path)
    if limit:
        df = df.head(limit)
    rows = []
    for _, row in df.iterrows():
        feats = row.to_dict()
        decision = ids.score(feats)
        rows.append(
            {
                **asdict(decision),
                "true_binary": int(row.get("label_binary", -1)),
                "true_class": row.get("label_class", ""),
                "run_id": row.get("run_id", ""),
            }
        )
    return pd.DataFrame(rows)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Cascade IDS live/offline scorer")
    p.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    p.add_argument("--modality", default="fusion", choices=["fusion", "physical", "network"])
    p.add_argument(
        "--replay",
        type=Path,
        default=None,
        help="Optional fused CSV to replay (default: artifacts/fused_1s_dataset.csv)",
    )
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)

    replay = args.replay or (args.artifacts / "fused_1s_dataset.csv")
    if args.modality != "fusion" and args.replay is None:
        raise SystemExit(
            "For physical/network replay, pass --replay pointing at a matching CSV."
        )
    out_df = score_fused_csv(replay, args.artifacts, modality=args.modality, limit=args.limit)
    out = args.out or (args.artifacts / f"replay_{args.modality}.csv")
    out_df.to_csv(out, index=False)

    if "true_binary" in out_df.columns:
        pred = out_df["attack_pred"].to_numpy()
        true = out_df["true_binary"].to_numpy()
        acc = float((pred == true).mean()) if len(true) else 0.0
        print(f"Replay rows={len(out_df)} accuracy≈{acc:.3f} → {out}")
    else:
        print(f"Wrote {out}")

    # Show a few attack detections
    hits = out_df[out_df["attack_pred"] == 1].head(5)
    if len(hits):
        print(hits[["attack_score", "attack_class", "action", "true_class", "latency_ms"]].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
