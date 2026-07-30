"""Live IDS evaluation metrics (confusion, F1, detection delay, per-class counts)."""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class LiveMetrics:
    """Online confusion matrix vs ground-truth attack windows from the orchestrator.

    Also tracks named attack detections and preventions for the dashboard.
    """

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    scores: list[float] = field(default_factory=list)
    detection_delays_s: list[float] = field(default_factory=list)
    defenses: int = 0
    defense_success: int = 0
    mitigation_delays_s: list[float] = field(default_factory=list)
    mission_resume_ok: int = 0
    mission_resume_fail: int = 0

    # Named attack tallies (for proactive defense dashboard)
    alerts_by_class: Counter = field(default_factory=Counter)
    preventions_by_class: Counter = field(default_factory=Counter)
    prevention_ok_by_class: Counter = field(default_factory=Counter)
    gt_windows_by_class: Counter = field(default_factory=Counter)
    detected_windows_by_class: Counter = field(default_factory=Counter)
    # Split: pre-PX4 gateway drops vs post-detect reclaim
    proactive_blocks: int = 0
    reactive_recovers: int = 0
    proactive_ok: int = 0
    reactive_ok: int = 0
    proactive_by_class: Counter = field(default_factory=Counter)
    reactive_by_class: Counter = field(default_factory=Counter)
    proactive_ok_by_class: Counter = field(default_factory=Counter)
    reactive_ok_by_class: Counter = field(default_factory=Counter)
    proactive_block_latencies_ms: list[float] = field(default_factory=list)

    _gt_attack: bool = False
    _gt_class: str | None = None
    _attack_t0: float | None = None
    _detected_this_window: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last_publish: float = 0.0

    def reset(self) -> None:
        with self._lock:
            self.tp = self.fp = self.tn = self.fn = 0
            self.scores.clear()
            self.detection_delays_s.clear()
            self.mitigation_delays_s.clear()
            self.defenses = 0
            self.defense_success = 0
            self.mission_resume_ok = 0
            self.mission_resume_fail = 0
            self.alerts_by_class.clear()
            self.preventions_by_class.clear()
            self.prevention_ok_by_class.clear()
            self.gt_windows_by_class.clear()
            self.detected_windows_by_class.clear()
            self.proactive_blocks = 0
            self.reactive_recovers = 0
            self.proactive_ok = 0
            self.reactive_ok = 0
            self.proactive_by_class.clear()
            self.reactive_by_class.clear()
            self.proactive_ok_by_class.clear()
            self.reactive_ok_by_class.clear()
            self.proactive_block_latencies_ms.clear()
            self._gt_attack = False
            self._gt_class = None
            self._attack_t0 = None
            self._detected_this_window = False

    def set_ground_truth(self, attack_active: bool, attack_class: str | None = None) -> None:
        with self._lock:
            if attack_active and not self._gt_attack:
                self._attack_t0 = time.time()
                self._detected_this_window = False
                self._gt_class = attack_class
                if attack_class:
                    self.gt_windows_by_class[str(attack_class)] += 1
            if not attack_active:
                self._attack_t0 = None
                self._detected_this_window = False
                self._gt_class = None
            self._gt_attack = bool(attack_active)

    def observe(
        self,
        attack_pred: bool,
        score: float,
        defended: bool = False,
        pred_class: str | None = None,
        is_alert: bool = False,
    ) -> dict:
        with self._lock:
            self.scores.append(float(score))
            if len(self.scores) > 2000:
                self.scores = self.scores[-1000:]
            if self._gt_attack and attack_pred:
                self.tp += 1
                if not self._detected_this_window and self._attack_t0 is not None:
                    delay = max(0.0, time.time() - self._attack_t0)
                    self.detection_delays_s.append(delay)
                    self._detected_this_window = True
                    if self._gt_class:
                        self.detected_windows_by_class[str(self._gt_class)] += 1
            elif self._gt_attack and not attack_pred:
                self.fn += 1
            elif (not self._gt_attack) and attack_pred:
                self.fp += 1
            else:
                self.tn += 1

            # Count named detections on UI alert edges (not every score tick)
            if is_alert and attack_pred:
                name = str(pred_class or self._gt_class or "attack")
                self.alerts_by_class[name] += 1

            if defended:
                self.defenses += 1
                name = str(pred_class or self._gt_class or "attack")
                self.preventions_by_class[name] += 1
            return self.snapshot_unlocked()

    def note_defense_result(
        self,
        ok: bool,
        attack_class: str | None = None,
        mitigation_delay_s: float | None = None,
        resume_ok: bool | None = None,
        kind: str = "reactive",
    ) -> None:
        with self._lock:
            name = str(attack_class or self._gt_class or "attack")
            if ok:
                self.defense_success += 1
                self.prevention_ok_by_class[name] += 1
            if mitigation_delay_s is not None and mitigation_delay_s >= 0:
                self.mitigation_delays_s.append(float(mitigation_delay_s))
            if resume_ok is True:
                self.mission_resume_ok += 1
            elif resume_ok is False:
                self.mission_resume_fail += 1
            if kind == "proactive":
                # Engage-level proactive success only. Per-packet drops are
                # counted separately via note_proactive_block() from the gateway.
                if ok:
                    self.proactive_ok += 1
                    self.proactive_ok_by_class[name] += 1
            elif kind == "reactive":
                self.reactive_recovers += 1
                self.reactive_by_class[name] += 1
                if ok:
                    self.reactive_ok += 1
                    self.reactive_ok_by_class[name] += 1

    def note_proactive_block(
        self,
        attack_class: str | None = None,
        latency_ms: float | None = None,
    ) -> dict:
        """Count a pre-PX4 gateway drop (may fire many times per window)."""
        with self._lock:
            name = str(attack_class or self._gt_class or "attack")
            self.proactive_blocks += 1
            self.proactive_by_class[name] += 1
            self.proactive_ok += 1
            self.proactive_ok_by_class[name] += 1
            # Also mirror into legacy prevention counters for overall rate
            self.defenses += 1
            self.defense_success += 1
            self.preventions_by_class[name] += 1
            self.prevention_ok_by_class[name] += 1
            if latency_ms is not None and latency_ms >= 0:
                self.proactive_block_latencies_ms.append(float(latency_ms))
                if len(self.proactive_block_latencies_ms) > 500:
                    self.proactive_block_latencies_ms = self.proactive_block_latencies_ms[-250:]
            return self.snapshot_unlocked()

    @property
    def gt_attack(self) -> bool:
        with self._lock:
            return bool(self._gt_attack)

    def snapshot(self) -> dict:
        with self._lock:
            return self.snapshot_unlocked()

    def snapshot_unlocked(self) -> dict:
        total = self.tp + self.fp + self.tn + self.fn
        prec = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        rec = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        acc = ((self.tp + self.tn) / total) if total else 0.0
        fpr = self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0
        delays = self.detection_delays_s
        mit = self.mitigation_delays_s
        def_rate = (self.defense_success / self.defenses) if self.defenses else None
        resume_n = self.mission_resume_ok + self.mission_resume_fail
        resume_rate = (self.mission_resume_ok / resume_n) if resume_n else None

        # Unified per-attack rows for the dashboard table
        names = sorted(set(self.alerts_by_class)
                       | set(self.preventions_by_class)
                       | set(self.gt_windows_by_class)
                       | set(self.detected_windows_by_class)
                       | set(self.prevention_ok_by_class)
                       | set(self.proactive_by_class)
                       | set(self.reactive_by_class))
        by_attack = []
        for name in names:
            gt_windows = int(self.gt_windows_by_class.get(name, 0))
            # True injected class has GT windows; anything else is a classifier
            # mislabel kept in the same table for research transparency.
            misprediction = gt_windows <= 0
            pro = int(self.proactive_by_class.get(name, 0))
            rea = int(self.reactive_by_class.get(name, 0))
            pro_ok = int(self.proactive_ok_by_class.get(name, 0))
            rea_ok = int(self.reactive_ok_by_class.get(name, 0))
            by_attack.append({
                "attack": name,
                "detections": int(self.alerts_by_class.get(name, 0)),
                "gt_windows": gt_windows,
                "windows_detected": int(self.detected_windows_by_class.get(name, 0)),
                "preventions": int(self.preventions_by_class.get(name, 0)),
                "prevent_ok": int(self.prevention_ok_by_class.get(name, 0)),
                "proactive_blocks": pro,
                "proactive_ok": pro_ok,
                "reactive_recovers": rea,
                "reactive_ok": rea_ok,
                "misprediction": misprediction,
                "note": ("model misprediction (not injected this run)"
                         if misprediction else "true attack window"),
            })
        # True attacks first, then mispredictions
        by_attack.sort(key=lambda r: (1 if r["misprediction"] else 0, r["attack"]))
        pro_lats = self.proactive_block_latencies_ms

        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "accuracy": round(acc, 4),
            "fpr": round(fpr, 4),
            "n_scores": total,
            "mean_detection_delay_s": round(sum(delays) / len(delays), 3) if delays else None,
            "last_detection_delay_s": round(delays[-1], 3) if delays else None,
            "mean_mitigation_delay_s": round(sum(mit) / len(mit), 3) if mit else None,
            "last_mitigation_delay_s": round(mit[-1], 3) if mit else None,
            "detections": len(delays),
            "alerts_total": int(sum(self.alerts_by_class.values())),
            "defenses": self.defenses,
            "defense_success": self.defense_success,
            "defense_success_rate": round(def_rate, 4) if def_rate is not None else None,
            "mission_resume_ok": self.mission_resume_ok,
            "mission_resume_fail": self.mission_resume_fail,
            "mission_resume_rate": round(resume_rate, 4) if resume_rate is not None else None,
            "gt_attack": self._gt_attack,
            "gt_class": self._gt_class,
            "mean_score": round(sum(self.scores[-50:]) / max(1, len(self.scores[-50:])), 4)
            if self.scores else 0.0,
            "alerts_by_class": dict(self.alerts_by_class),
            "preventions_by_class": dict(self.preventions_by_class),
            "prevention_ok_by_class": dict(self.prevention_ok_by_class),
            "gt_windows_by_class": dict(self.gt_windows_by_class),
            "detected_windows_by_class": dict(self.detected_windows_by_class),
            "proactive_blocks": self.proactive_blocks,
            "reactive_recovers": self.reactive_recovers,
            "proactive_ok": self.proactive_ok,
            "reactive_ok": self.reactive_ok,
            "proactive_by_class": dict(self.proactive_by_class),
            "reactive_by_class": dict(self.reactive_by_class),
            "mean_proactive_block_ms": (
                round(sum(pro_lats) / len(pro_lats), 3) if pro_lats else None),
            "by_attack": by_attack,
        }
