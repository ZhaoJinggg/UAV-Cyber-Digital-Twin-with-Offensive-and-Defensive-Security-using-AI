"""Tiny 1D-CNN for MAVLink network-window sequences (UAV cyber defense).

Designed for edge / GCS latency: two Conv1d layers + global pool + dual heads
(binary attack + multiclass attack type). Input is a short temporal stack of
``NETWORK_CORE`` counters (default 8 × 1 s windows).
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ids.features import NETWORK_CORE

try:
    import torch
    import torch.nn as nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore
    nn = None  # type: ignore

META_NAME = "cnn_mav1d_meta.json"
WEIGHTS_NAME = "cnn_mav1d.pt"
DEFAULT_SEQ_LEN = 8


def _require_torch() -> None:
    if torch is None or nn is None:
        raise ImportError(
            "PyTorch is required for the MAVLink 1D-CNN. "
            "Install with: pip install torch --index-url "
            "https://download.pytorch.org/whl/cpu"
        )


class TinyMAV1DCNN(nn.Module if nn is not None else object):  # type: ignore[misc]
    """Lightweight temporal CNN: (B, C, T) → binary logit + class logits."""

    def __init__(self, in_ch: int, n_classes: int, width: int = 32):
        _require_torch()
        super().__init__()
        self.in_ch = int(in_ch)
        self.n_classes = int(n_classes)
        hid = int(width)
        self.backbone = nn.Sequential(
            nn.Conv1d(self.in_ch, hid, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm1d(hid),
            nn.ReLU(inplace=True),
            nn.Conv1d(hid, hid * 2, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm1d(hid * 2),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool1d(1),
        )
        self.binary_head = nn.Linear(hid * 2, 1)
        self.multi_head = nn.Linear(hid * 2, self.n_classes)

    def forward(self, x: "torch.Tensor") -> tuple["torch.Tensor", "torch.Tensor"]:
        # x: (B, C, T)
        h = self.backbone(x).flatten(1)
        return self.binary_head(h).squeeze(-1), self.multi_head(h)


@dataclass
class CNNDecision:
    attack_score: float
    attack_pred: int
    attack_class: str | None
    class_confidence: float | None
    latency_ms: float
    ready: bool = True


class NetSeqCNNScorer:
    """Live / offline scorer with rolling network-window buffer."""

    def __init__(self, artifacts_dir: Path | str, device: str | None = None):
        _require_torch()
        self.artifacts_dir = Path(artifacts_dir)
        meta_path = self.artifacts_dir / META_NAME
        weights_path = self.artifacts_dir / WEIGHTS_NAME
        if not meta_path.exists() or not weights_path.exists():
            raise FileNotFoundError(
                f"Missing CNN artifacts ({META_NAME} / {WEIGHTS_NAME}). "
                "Train with: python -m ids.cnn_train"
            )
        self.meta = json.loads(meta_path.read_text())
        self.feature_cols: list[str] = list(self.meta["feature_cols"])
        self.seq_len = int(self.meta.get("seq_len", DEFAULT_SEQ_LEN))
        self.threshold = float(self.meta.get("live_binary_threshold",
                              self.meta.get("binary_threshold", 0.55)))
        self.classes: list[str] = list(self.meta["classes"])
        # Early 1–2 class models need a milder live gate; multi-attack models
        # stay stricter to limit cruise false positives.
        if len(self.classes) <= 2:
            self.threshold = float(min(max(self.threshold, 0.50), 0.58))
        else:
            self.threshold = max(self.threshold, 0.65)
        self.mean = np.asarray(self.meta["mean"], dtype=np.float32)
        self.std = np.asarray(self.meta["std"], dtype=np.float32)
        self.std = np.where(self.std < 1e-6, 1.0, self.std)

        self.device = torch.device(device or "cpu")
        self.model = TinyMAV1DCNN(
            in_ch=len(self.feature_cols),
            n_classes=len(self.classes),
            width=int(self.meta.get("width", 32)),
        )
        state = torch.load(weights_path, map_location=self.device, weights_only=True)
        self.model.load_state_dict(state)
        self.model.to(self.device)
        self.model.eval()
        self._buf: deque[np.ndarray] = deque(maxlen=self.seq_len)

    def reset(self) -> None:
        self._buf.clear()

    def _vectorize(self, features: dict[str, Any]) -> np.ndarray:
        vec = np.zeros(len(self.feature_cols), dtype=np.float32)
        for i, name in enumerate(self.feature_cols):
            v = features.get(name, 0.0)
            try:
                x = float(v)
                if np.isnan(x) or np.isinf(x):
                    x = 0.0
            except (TypeError, ValueError):
                x = 0.0
            vec[i] = x
        return (vec - self.mean) / self.std

    def push(self, features: dict[str, Any]) -> None:
        self._buf.append(self._vectorize(features))

    def ready_seq(self) -> bool:
        return len(self._buf) >= max(3, self.seq_len // 2)

    def score(self, features: dict[str, Any] | None = None) -> CNNDecision:
        import time

        t0 = time.perf_counter()
        if features is not None:
            self.push(features)
        if not self.ready_seq():
            return CNNDecision(
                attack_score=0.0,
                attack_pred=0,
                attack_class=None,
                class_confidence=None,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                ready=False,
            )
        # Pad left with first frame if buffer still warming
        frames = list(self._buf)
        while len(frames) < self.seq_len:
            frames.insert(0, frames[0])
        seq = np.stack(frames[-self.seq_len :], axis=1)  # (C, T)
        x = torch.from_numpy(seq).unsqueeze(0).to(self.device)  # (1, C, T)
        with torch.no_grad():
            logit, multi = self.model(x)
            proba = float(torch.sigmoid(logit).item())
            probs = torch.softmax(multi, dim=-1)[0].cpu().numpy()
        idx = int(np.argmax(probs))
        top = self.classes[idx]
        # Trust multiclass: if top class is benign, do not invent an attack
        # label (previously remapped to command_flood_dos and pinned the UI).
        if top == "benign":
            attack_pred = 0
            cls = None
            conf = None
            score_out = min(proba, 0.35)
        else:
            attack_pred = int(proba >= self.threshold)
            cls = top if attack_pred else None
            conf = float(probs[idx]) if attack_pred else None
            score_out = proba
        return CNNDecision(
            attack_score=score_out,
            attack_pred=attack_pred,
            attack_class=cls,
            class_confidence=conf,
            latency_ms=round((time.perf_counter() - t0) * 1000.0, 4),
            ready=True,
        )


def default_feature_cols() -> list[str]:
    return list(NETWORK_CORE)
