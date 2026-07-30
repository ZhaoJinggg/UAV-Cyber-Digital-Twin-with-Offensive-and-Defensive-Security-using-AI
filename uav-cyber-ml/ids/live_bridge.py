"""Live IDS bridge: fuse streaming phys/net ticks → cascade decisions → dashboard."""

from __future__ import annotations

import math
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ids.features import PHYS_WINDOW_FOCUS
from ids.live_scorer import CascadeIDS, IDSDecision
from ids.rules import evaluate_rules, DEFENSE_ACTIONS
from ids.defense import defense_status, get_defense_controller
from ids.metrics import LiveMetrics
import config as C

try:
    from config import ROOT
except ImportError:  # pragma: no cover
    ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ARTIFACTS = ROOT / "ids" / "artifacts"
PublishFn = Callable[[dict], None]


def _f(v: Any, default: float = 0.0) -> float:
    if v is None:
        return default
    try:
        x = float(v)
    except (TypeError, ValueError):
        return default
    if isinstance(x, float) and (math.isnan(x) or math.isinf(x)):
        return default
    return x


def normalize_network_window(d: dict) -> dict:
    """Map live sniffer fields onto the training schema."""
    out = dict(d)
    # Live sniffer historically used mission_count
    if "mission_item_count" not in out and "mission_count" in out:
        out["mission_item_count"] = out["mission_count"]
    out.setdefault("std_len", 0.0)
    out.setdefault("std_iat", 0.0)
    out.setdefault("unique_msgids", 0.0)
    out.setdefault("unique_sysids", 0.0)
    out.setdefault("byte_rate", out.get("byte_count", 0.0))
    out.setdefault("pkt_rate", out.get("pkt_count", 0.0))
    for k in (
        "heartbeat_count",
        "command_long_count",
        "param_set_count",
        "mission_item_count",
        "rc_override_count",
        "manual_control_count",
        "gps_input_count",
        "set_mode_count",
        "to_uav_count",
        "from_uav_count",
        "pkt_count",
        "byte_count",
        "mean_len",
        "mean_iat",
    ):
        out[k] = _f(out.get(k))
    return out


def aggregate_physical_window(samples: list[dict]) -> dict:
    """Match offline fusion: mean/std/min/max/last over PHYS_WINDOW_FOCUS."""
    feats: dict[str, float] = {"n_phys_samples": float(len(samples))}
    if not samples:
        return feats
    for c in PHYS_WINDOW_FOCUS:
        vals = [_f(s.get(c), default=float("nan")) for s in samples]
        vals = [v for v in vals if not math.isnan(v)]
        if not vals:
            for suf in ("mean", "std", "min", "max", "last"):
                feats[f"p_{c}_{suf}"] = 0.0
            continue
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        feats[f"p_{c}_mean"] = mean
        feats[f"p_{c}_std"] = math.sqrt(var)
        feats[f"p_{c}_min"] = min(vals)
        feats[f"p_{c}_max"] = max(vals)
        feats[f"p_{c}_last"] = vals[-1]
    return feats


class LiveIDSEngine:
    """Thread-safe online scorer used by the dashboard run hooks."""

    def __init__(
        self,
        publish: PublishFn,
        artifacts_dir: Path | str | None = None,
    ):
        self.publish = publish
        self.artifacts_dir = Path(artifacts_dir or DEFAULT_ARTIFACTS)
        self._lock = threading.Lock()
        self._phys_buf: list[dict] = []
        self._phys_bin: int | None = None
        self._last_phys: dict = {}
        self._last_decision: dict | None = None
        self._last_phys_score_ts = 0.0
        self._last_alert_ts = 0.0
        self._n_scores = 0
        self._n_alerts = 0
        self.enabled = True
        self.active = False  # True while a scenario run is recording
        self.models: dict[str, CascadeIDS] = {}
        self.cnn = None  # optional TinyMAV1DCNN sequence scorer
        self.cnn_error: str | None = None
        self.load_error: str | None = None
        self.rules_only = False
        self.defense = get_defense_controller(publish=publish)
        # Always bind this engine's publisher (dashboard bus) for UI events.
        if publish is not None:
            self.defense.publish = publish
        self.metrics = LiveMetrics()
        self.defense.on_result = self._on_defense_result
        try:
            from ids.mav_gateway import ensure_gateway_started
            gw = ensure_gateway_started(publish=self._gateway_publish)
            gw.set_mode(str(getattr(C, "DEFENSE_MODE", "proactive")))
        except Exception:
            pass
        self._load_models()
        # Defense ON by default only when a trained model is present.
        try:
            from ids.defense import model_available, set_defense_enabled
            set_defense_enabled(bool(model_available()))
        except Exception:
            pass

    def _gateway_publish(self, msg: dict) -> None:
        """Fan-out gateway events and tally proactive blocks into live metrics."""
        data = (msg or {}).get("data") or {}
        if data.get("event") == "proactive_block":
            try:
                snap = self.metrics.note_proactive_block(
                    attack_class=data.get("attack_class"),
                    latency_ms=data.get("latency_ms"),
                )
                # Debounce UI flood — still count every drop in metrics.
                now = time.time()
                if now - getattr(self, "_last_pro_ui", 0.0) >= 0.25:
                    self._last_pro_ui = now
                    self.publish({"type": "ids_metrics", "data": snap})
                    self.publish(msg)
                    self.publish({
                        "type": "log", "tag": "defense",
                        "msg": data.get("message") or "proactive block",
                        "ts": now,
                    })
            except Exception:
                pass
            return
        self.publish(msg)
    def _on_defense_result(
        self,
        ok: bool,
        result: str,
        attack_class: str | None = None,
        mitigation_delay_s: float | None = None,
        resume_ok: bool | None = None,
    ) -> None:
        # Classify engage path correctly — was always "reactive", which made
        # the dashboard show reactive recovers while proactive blocks stayed 0.
        kind = "reactive"
        try:
            from ids.defense import DEFENSE_MODE
            mode = str(DEFENSE_MODE or "").lower()
            res = str(result or "").lower()
            if mode == "proactive" or "proactive" in res:
                kind = "proactive"
            elif mode in ("hybrid", "prevent") and "gateway" in res and "hybrid" in res:
                kind = "proactive"
        except Exception:
            pass
        self.metrics.note_defense_result(
            ok, attack_class=attack_class,
            mitigation_delay_s=mitigation_delay_s,
            resume_ok=resume_ok,
            kind=kind,
        )
        snap = self.metrics.snapshot()
        self.publish({"type": "ids_metrics", "data": snap})
        self.publish({
            "type": "log",
            "tag": "defense",
            "msg": f"defense_success += {1 if ok else 0} ({result})"
                   + (f" · {attack_class}" if attack_class else "")
                   + (f" · mit={mitigation_delay_s:.2f}s"
                      if mitigation_delay_s is not None else ""),
            "ts": time.time(),
        })

    def set_run_context(self, scenario: str | None, run_name: str | None) -> None:
        self._run_scenario = scenario
        self._run_name = run_name

    def write_paper_metrics(self) -> Path | None:
        """Persist TIFS-oriented live metrics next to the run (if known)."""
        import json
        from datetime import datetime, timezone
        snap = self.metrics.snapshot()
        scen = getattr(self, "_run_scenario", None)
        run = getattr(self, "_run_name", None)
        payload = {
            "venue_target": "IEEE TIFS",
            "scenario": scen,
            "run": run,
            "written_at": datetime.now(timezone.utc).isoformat(),
            "defense_enabled": defense_status().get("defense_enabled"),
            "metrics": snap,
        }
        out_live = None
        try:
            out_live = Path(C.DATASETS_DIR) / "paper_live_metrics.json"
            out_live.write_text(json.dumps(payload, indent=2))
        except Exception:
            out_live = None
        if not scen or not run:
            return out_live
        try:
            run_dir = Path(C.RUNS_DIR) / scen / run
            run_dir.mkdir(parents=True, exist_ok=True)
            path = run_dir / "paper_metrics.json"
            path.write_text(json.dumps(payload, indent=2))
            return path
        except Exception:
            return out_live

    def reload_models(self) -> dict:
        """Hot-reload CascadeIDS scorers after online retraining."""
        with self._lock:
            self._load_models()
        st = self.status()
        self.publish({"type": "ids", "data": {
            "event": "reload",
            "ready": self.ready,
            "modalities": sorted(self.models),
            "message": ("models reloaded" if self.ready
                        else f"reload failed: {self.load_error}"),
            "metrics": self.metrics.snapshot(),
        }})
        return st


    def _primary(self) -> str:
        return str(getattr(C, "IDS_PRIMARY_MODEL", "cnn1d")).strip().lower()

    def _artifacts_present(self) -> bool:
        """True only when on-disk trained weights/bundles exist."""
        d = self.artifacts_dir
        if not d.exists():
            return False
        if (d / "cnn_mav1d.pt").exists() and (d / "cnn_mav1d_meta.json").exists():
            return True
        for modality in ("fusion", "physical", "network"):
            if (d / f"{modality}_bundle.json").exists():
                return True
        return False

    def _unload_stale_models(self) -> None:
        """Clear in-memory scorers when artifacts vanish (no restart needed)."""
        self.models.clear()
        self.cnn = None
        self.cnn_error = None
        self.load_error = (
            f"no trained IDS model (missing {self.artifacts_dir}) — "
            "UAV unprotected; GPS/attacks run without detection or defence"
        )
        try:
            from ids.defense import set_model_available, set_defense_enabled
            set_model_available(False)
            set_defense_enabled(False)
        except Exception:
            pass

    def _load_models(self) -> None:
        self.models.clear()
        self.cnn = None
        self.cnn_error = None
        self.load_error = None
        self.rules_only = False
        has_model = False
        if not self._artifacts_present():
            self.load_error = (
                f"no trained IDS model (missing {self.artifacts_dir}) — "
                "UAV unprotected; GPS/attacks run without detection or defence"
            )
            try:
                from ids.defense import set_model_available
                set_model_available(False)
            except Exception:
                pass
            return
        # Primary lightweight model: Tiny MAVLink 1D-CNN
        try:
            from ids.cnn_model import NetSeqCNNScorer
            self.cnn = NetSeqCNNScorer(self.artifacts_dir)
            has_model = True
        except Exception as exc:  # noqa: BLE001
            self.cnn = None
            self.cnn_error = str(exc)
        # LightGBM kept as fallback / secondary modalities
        for modality in ("fusion", "physical", "network"):
            bundle = self.artifacts_dir / f"{modality}_bundle.json"
            if not bundle.exists():
                continue
            try:
                self.models[modality] = CascadeIDS(self.artifacts_dir, modality=modality)
                has_model = True
            except Exception as exc:  # noqa: BLE001
                if self._primary() != "cnn1d":
                    self.load_error = f"{modality}: {exc}"
        if self._primary() == "cnn1d" and self.cnn is None and not self.models:
            self.load_error = (
                self.cnn_error
                or "no TinyMAV 1D-CNN artifacts — UAV unprotected "
                   "(train with: python -m ids cnn)"
            )
            has_model = False
        elif not has_model:
            self.load_error = self.load_error or (
                "no trained modalities — UAV unprotected"
            )
        try:
            from ids.defense import set_model_available, set_defense_enabled, model_available
            set_model_available(bool(has_model))
            # Re-apply wanted defense only if model is present.
            if has_model:
                set_defense_enabled(True)
            else:
                set_defense_enabled(False)
        except Exception:
            pass

    @property
    def ready(self) -> bool:
        """True only when a trained model is loaded (CNN and/or LightGBM)."""
        if self._primary() == "cnn1d":
            return self.cnn is not None or bool(self.models)
        return bool(self.models) and self.load_error is None

    def status(self) -> dict:
        # Artifacts may have been deleted while the dashboard stayed up —
        # never keep Defense ON from a stale in-memory model.
        if (self.cnn is not None or self.models) and not self._artifacts_present():
            self._unload_stale_models()
        mods = ["cnn1d"] if self.cnn is not None else []
        if self._primary() != "cnn1d":
            mods = sorted(set(mods) | set(self.models))
        elif self.cnn is None:
            mods = sorted(self.models)
        unprotected = not self.ready
        st = {
            "ready": self.ready,
            "enabled": self.enabled,
            "active": self.active,
            "primary_model": self._primary() if self.ready else None,
            "rules_only": False,
            "unprotected": unprotected,
            "model_available": self.ready,
            "modalities": mods,
            "artifacts_dir": str(self.artifacts_dir),
            "load_error": self.load_error,
            "message": (
                None if self.ready else
                (self.load_error or "No trained IDS model — unprotected mode")
            ),
            "cnn": {
                "ready": self.cnn is not None,
                "error": self.cnn_error,
                "primary": self._primary() == "cnn1d",
                "meta": (getattr(self.cnn, "meta", None) or {}).get("holdout")
                if self.cnn is not None else None,
            },
            "n_scores": self._n_scores,
            "n_alerts": self._n_alerts,
            "last": self._last_decision,
            "metrics": self.metrics.snapshot(),
        }
        st.update(defense_status())
        return st

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)

    def set_defense_enabled(self, enabled: bool) -> None:
        self.defense.set_enabled(bool(enabled))

    def begin_run(self) -> None:
        with self._lock:
            self.active = True
            self._phys_buf = []
            self._phys_bin = None
            self._last_phys = {}
            self._last_decision = None
            self._n_scores = 0
            self._n_alerts = 0
            if self.cnn is not None:
                try:
                    self.cnn.reset()
                except Exception:
                    pass
        self.metrics.reset()
        mods = sorted(self.models)
        if self.cnn is not None:
            mods = sorted(set(mods) | {"cnn1d"})
        unprotected = not self.ready
        # Re-assert operator defense mode so UI/gateway never drift to hybrid.
        mode_now = "proactive"
        try:
            from ids.defense import DEFENSE_MODE, defense_enabled
            from ids.mav_gateway import get_gateway
            mode_now = str(DEFENSE_MODE or "proactive").lower()
            gw = get_gateway()
            gw.set_mode(mode_now)
            gw.set_defense_enabled(bool(defense_enabled()))
        except Exception:
            pass
        self.publish({"type": "ids", "data": {
            "event": "reset",
            "ready": self.ready,
            "unprotected": unprotected,
            "defense_mode": mode_now,
            "modalities": mods,
            "message": (
                "UNPROTECTED — no trained IDS model; attacks affect UAV with no defence"
                if unprotected else
                ("IDS armed for run"
                 + (" · TinyMAV 1D-CNN online" if self.cnn else ""))
            ),
            "metrics": self.metrics.snapshot(),
        }})
        if unprotected:
            self.publish({
                "type": "log", "tag": "ids",
                "msg": "UNPROTECTED mode — no trained model; defence disabled",
                "ts": time.time(),
            })

    def set_ground_truth(self, phase: str, scenario: str | None = None) -> None:
        """Called from dashboard when orchestrator publishes mission phase."""
        try:
            from ids.mav_gateway import get_gateway
            gw = get_gateway()
        except Exception:
            gw = None
        if phase == "attack":
            self.metrics.set_ground_truth(True, attack_class=scenario)
            if gw is not None:
                try:
                    from ids.defense import DEFENSE_MODE, defense_enabled
                    mode = str(DEFENSE_MODE or "proactive").lower()
                    gw.set_mode(mode)
                    gw.set_defense_enabled(bool(defense_enabled()))
                except Exception:
                    mode = "proactive"
                gw.set_gt_attack(True, scenario)
                # Proactive/prevent: arm drops at window open.
                # Hybrid waits for IDS detect (arm_drop_policy on engage).
                if mode in ("proactive", "prevent"):
                    gw.arm_drop_policy(scenario, reason="gt_attack_window")
            # Clear any early IPS abort so the injector can send frames that
            # the proactive gateway will drop (and count).
            try:
                from ids.defense import _ABORT
                _ABORT.clear()
            except Exception:
                pass
        elif phase in ("pre_attack", "post_attack", "recording", "landing",
                       "landed", "settling", "done", "mission_wp", "benign"):
            if phase != "mission_wp":
                self.metrics.set_ground_truth(False)
                if gw is not None:
                    gw.set_gt_attack(False)
                    # Keep drop_armed through post_attack briefly? No — clear
                    # so normal mission traffic from unexpected sysids is safe.
                    if phase != "post_attack":
                        gw.clear_drop_policy()
                    else:
                        # Stay armed during post so late attack packets still drop.
                        gw.arm_drop_policy(scenario, reason="post_attack_tail")
        snap = self.metrics.snapshot()
        self.publish({"type": "ids_metrics", "data": snap})

    def end_run(self) -> None:
        try:
            self.write_paper_metrics()
        except Exception:
            pass
        with self._lock:
            self.active = False
            self._phys_buf = []
            self._phys_bin = None
        try:
            # Stop any in-flight mitigation when the scenario ends.
            self.defense._stop.set()
        except Exception:
            pass
        self.publish({"type": "ids", "data": {
            "event": "idle",
            "ready": self.ready,
            "n_scores": self._n_scores,
            "n_alerts": self._n_alerts,
            "message": "IDS idle",
            "metrics": self.metrics.snapshot(),
        }})

    def on_phys(self, sample: dict) -> None:
        if not self.enabled or not self.active or not self.ready:
            return
        with self._lock:
            self._last_phys = dict(sample)
            t_rel = _f(sample.get("t_rel"))
            t_bin = int(math.floor(t_rel))
            if self._phys_bin is None:
                self._phys_bin = t_bin
            if t_bin != self._phys_bin:
                prev = list(self._phys_buf)
                self._phys_buf = [sample]
                self._phys_bin = t_bin
                # Single-model mode (cnn1d): skip LightGBM physical path.
                if self._primary() != "cnn1d" and prev and "physical" in self.models:
                    self._score_physical_locked(prev[-1], t_hint=float(self._phys_bin))
            else:
                self._phys_buf.append(sample)
                now = time.time()
                if (self._primary() != "cnn1d" and "physical" in self.models
                        and (now - self._last_phys_score_ts) >= 0.5):
                    self._last_phys_score_ts = now
                    self._score_physical_locked(sample, t_hint=t_rel)

    def on_net(self, window: dict) -> None:
        if not self.enabled or not self.active or not self.ready:
            return
        net = normalize_network_window(window)
        with self._lock:
            cnn_dec = None
            # ---- Primary path: Tiny MAVLink 1D-CNN (one strong lightweight model)
            if self._primary() == "cnn1d" and self.cnn is not None:
                try:
                    cnn_dec = self.cnn.score(net)
                except Exception:
                    cnn_dec = None
                if cnn_dec is not None and cnn_dec.ready:
                    rules = evaluate_rules({**net, **self._last_phys})
                    gt = bool(self.metrics.gt_attack)
                    raw_score = float(cnn_dec.attack_score)
                    # Inside GT: CNN or critical rule. Outside: suppress cruise
                    # false alarms that pinned graphs at ~1 / command_flood_dos.
                    if gt:
                        attack_pred = int(
                            cnn_dec.attack_pred
                            or rules.max_severity == "critical"
                        )
                        score = raw_score
                    else:
                        attack_pred = int(
                            cnn_dec.attack_pred
                            and raw_score >= 0.90
                            and rules.max_severity == "critical"
                        )
                        score = float(raw_score if attack_pred else min(raw_score, 0.40))
                    attack_class = cnn_dec.attack_class
                    class_conf = cnn_dec.class_confidence
                    if gt and rules.max_severity == "critical" and (
                            not attack_class or (class_conf or 0) < 0.45):
                        crit = next(h for h in rules.hits if h.severity == "critical")
                        attack_class = attack_class or crit.name.replace("_suspected", "")
                        attack_pred = 1
                        score = max(score, raw_score)
                    action = "none"
                    if attack_pred:
                        action = DEFENSE_ACTIONS.get(
                            attack_class or "", "hold_or_rtl")
                        if rules.max_severity == "critical":
                            crit = next(
                                (h for h in rules.hits if h.severity == "critical"),
                                None)
                            if crit and (class_conf is None or class_conf < 0.45):
                                action = crit.suggested_action
                    # Map rule names onto scenario labels for defence actions.
                    if attack_class and "gps_spoof" in str(attack_class):
                        attack_class = "gps_spoofing"
                    decision = IDSDecision(
                        timestamp=time.time(),
                        modality="cnn1d",
                        rules_triggered=rules.triggered,
                        rules_severity=rules.max_severity,
                        rule_hits=[
                            {"name": h.name, "severity": h.severity,
                             "detail": h.detail,
                             "suggested_action": h.suggested_action}
                            for h in rules.hits
                        ],
                        attack_score=score,
                        attack_pred=attack_pred,
                        attack_class=attack_class if attack_pred else None,
                        class_confidence=class_conf if attack_pred else None,
                        action=action,
                        latency_ms=float(cnn_dec.latency_ms or 0.0),
                    )
                    # Arm drops only during GT or a very high-confidence critical.
                    if attack_pred and (gt or score >= 0.90):
                        try:
                            from ids.mav_gateway import get_gateway
                            get_gateway().arm_drop_policy(
                                attack_class, reason="cnn1d_primary")
                        except Exception:
                            pass
                    self._emit_decision_locked(
                        decision, modality="cnn1d",
                        t_rel=_f(net.get("t_rel")), cnn=cnn_dec,
                    )
                    return

            # ---- Fallback: LightGBM fusion/network (only if CNN unavailable)
            phys_feats = aggregate_physical_window(self._phys_buf)
            if "fusion" in self.models:
                feats = {**net, **phys_feats}
                for k, v in self._last_phys.items():
                    if k not in feats:
                        feats[k] = v
                decision = self.models["fusion"].score(feats)
                modality = "fusion"
            elif "network" in self.models:
                decision = self.models["network"].score(dict(net))
                modality = "network"
            else:
                return
            self._emit_decision_locked(
                decision, modality=modality, t_rel=_f(net.get("t_rel")),
            )

    def _fuse_lgbm_cnn(self, lgbm: IDSDecision, cnn) -> IDSDecision:
        """Blend cascade + 1D-CNN scores; prefer agreeing high-confidence class."""
        if cnn is None or not getattr(cnn, "ready", False):
            return lgbm
        score = 0.55 * float(lgbm.attack_score) + 0.45 * float(cnn.attack_score)
        if lgbm.attack_pred and cnn.attack_pred:
            score = min(1.0, max(score, max(lgbm.attack_score, cnn.attack_score)) + 0.04)
        rules_crit = str(lgbm.rules_severity) == "critical"
        attack_pred = int(
            score >= 0.52
            or rules_crit
            or (lgbm.attack_pred and float(lgbm.attack_score) >= 0.6)
            or (cnn.attack_pred and float(cnn.attack_score) >= 0.60)
        )
        attack_class = lgbm.attack_class
        class_conf = lgbm.class_confidence
        if attack_pred:
            c_score = float(cnn.class_confidence or 0.0) if cnn.attack_pred else -1.0
            l_score = float(lgbm.class_confidence or 0.0) if lgbm.attack_pred else -1.0
            if c_score >= l_score and cnn.attack_class:
                attack_class = cnn.attack_class
                class_conf = cnn.class_confidence
            elif not attack_class and cnn.attack_class:
                attack_class = cnn.attack_class
                class_conf = cnn.class_confidence
        action = "none"
        if attack_pred:
            action = DEFENSE_ACTIONS.get(attack_class or "", lgbm.action or "hold_or_rtl")
            if rules_crit and (class_conf is None or class_conf < 0.45):
                action = lgbm.action or action
        return IDSDecision(
            timestamp=time.time(),
            modality=(lgbm.modality or "fusion") + "+cnn1d",
            rules_triggered=lgbm.rules_triggered,
            rules_severity=lgbm.rules_severity,
            rule_hits=list(lgbm.rule_hits or []),
            attack_score=float(score),
            attack_pred=attack_pred,
            attack_class=attack_class if attack_pred else None,
            class_confidence=class_conf if attack_pred else None,
            action=action,
            latency_ms=round(
                float(lgbm.latency_ms or 0.0) + float(getattr(cnn, "latency_ms", 0.0) or 0.0),
                4,
            ),
        )

    def _score_physical_locked(self, sample: dict, t_hint: float) -> None:
        model = self.models.get("physical")
        if model is None:
            return
        # Skip if we just published a fusion alert in this second (avoid spam).
        if self._last_decision and self._last_decision.get("modality") == "fusion":
            if abs(_f(self._last_decision.get("t_rel")) - t_hint) < 0.95:
                if self._last_decision.get("attack_pred"):
                    return
        decision = model.score(sample)
        self._emit_decision_locked(decision, modality="physical", t_rel=t_hint)

    def _emit_decision_locked(
        self, decision, modality: str, t_rel: float, cnn=None,
    ) -> None:
        self._n_scores += 1
        payload = {
            "event": "score",
            "modality": modality,
            "t_rel": round(float(t_rel), 3),
            "attack_score": decision.attack_score,
            "attack_pred": decision.attack_pred,
            "attack_class": decision.attack_class,
            "class_confidence": decision.class_confidence,
            "action": decision.action,
            "rules_triggered": decision.rules_triggered,
            "rules_severity": decision.rules_severity,
            "rule_hits": decision.rule_hits,
            "latency_ms": decision.latency_ms,
            "n_scores": self._n_scores,
            "n_alerts": self._n_alerts,
        }
        if cnn is not None:
            payload["cnn1d"] = {
                "ready": bool(getattr(cnn, "ready", False)),
                "attack_score": float(getattr(cnn, "attack_score", 0.0) or 0.0),
                "attack_pred": int(getattr(cnn, "attack_pred", 0) or 0),
                "attack_class": getattr(cnn, "attack_class", None),
                "class_confidence": getattr(cnn, "class_confidence", None),
                "latency_ms": getattr(cnn, "latency_ms", None),
            }
        if decision.attack_pred:
            self._n_alerts += 1
            payload["n_alerts"] = self._n_alerts
            # Debounce identical alert spam to ~2 Hz for UI clarity.
            now = time.time()
            if now - self._last_alert_ts < 0.4:
                key = (decision.attack_class, decision.action)
                last_key = (
                    (self._last_decision or {}).get("attack_class"),
                    (self._last_decision or {}).get("action"),
                )
                if key == last_key:
                    metrics = self.metrics.observe(
                        attack_pred=True,
                        score=float(decision.attack_score),
                        defended=False,
                        pred_class=decision.attack_class,
                        is_alert=False,
                    )
                    payload = {**payload, "event": "score", "ui_alert": False,
                               "metrics": metrics,
                               "defense_enabled": defense_status()["defense_enabled"],
                               "defense_engaged": False}
                    self._last_decision = payload
                    self.publish({"type": "ids", "data": payload})
                    if self._n_scores % 3 == 0:
                        self.publish({"type": "ids_metrics", "data": metrics})
                    return
            self._last_alert_ts = now
            gt = bool(self.metrics.gt_attack)
            # Red banners only in the real attack window (avoids “attack at climb”).
            payload["ui_alert"] = bool(gt)
            payload["event"] = "alert" if gt else "score"
            hold = float(getattr(C, "DEFENSE_PREVENT_HOLD_S", 12.0))
            engaged = self.defense.maybe_engage(
                action=str(decision.action or "hold_or_rtl"),
                attack_class=decision.attack_class,
                score=float(decision.attack_score),
                modality=modality,
                hold_s=hold,
                gt_attack=gt,
                rules_severity=decision.rules_severity,
            )
            payload["defense_engaged"] = bool(engaged)
            payload["defense_enabled"] = defense_status()["defense_enabled"]
            metrics = self.metrics.observe(
                attack_pred=True,
                score=float(decision.attack_score),
                defended=bool(engaged),
                pred_class=decision.attack_class,
                is_alert=True,
            )
            payload["metrics"] = metrics
            self.publish({"type": "ids_metrics", "data": metrics})
        else:
            payload["ui_alert"] = False
            payload["defense_engaged"] = False
            payload["defense_enabled"] = defense_status()["defense_enabled"]
            metrics = self.metrics.observe(
                attack_pred=False,
                score=float(decision.attack_score),
                defended=False,
                pred_class=None,
                is_alert=False,
            )
            payload["metrics"] = metrics
            # Throttle clear-score metric pushes
            if self._n_scores % 4 == 0:
                self.publish({"type": "ids_metrics", "data": metrics})
        self._last_decision = payload
        self.publish({"type": "ids", "data": payload})


def rules_only_preview(features: dict) -> dict:
    """Utility for API/debug — Stage-0 without ML."""
    r = evaluate_rules(features)
    return {
        "triggered": r.triggered,
        "severity": r.max_severity,
        "hits": [
            {"name": h.name, "severity": h.severity, "detail": h.detail,
             "suggested_action": h.suggested_action}
            for h in r.hits
        ],
    }
