"""Stage-0 deterministic gates (microsecond, interpretable, onboard-safe)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RuleThresholds:
    # Network window (1 s) hard limits — above benign OFFBOARD peaks.
    max_pkt_rate: float = 3500.0
    max_command_long: int = 120
    max_param_set: int = 8
    max_mission_item: int = 12
    max_rc_override: int = 15
    max_gps_input: int = 6

    max_set_mode: int = 6
    max_unique_sysids: int = 6
    # Physical abruptness
    max_tilt_mag: float = 0.85
    max_pos_err_z: float = 8.0


@dataclass
class RuleHit:
    name: str
    severity: str  # info | warn | critical
    detail: str
    suggested_action: str


@dataclass
class RuleResult:
    hits: list[RuleHit] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return bool(self.hits)

    @property
    def max_severity(self) -> str:
        order = {"info": 0, "warn": 1, "critical": 2}
        if not self.hits:
            return "none"
        return max(self.hits, key=lambda h: order.get(h.severity, 0)).severity


def evaluate_rules(
    features: dict,
    thresholds: RuleThresholds | None = None,
) -> RuleResult:
    """Evaluate Stage-0 rules on a fused or network/physical feature dict."""
    th = thresholds or RuleThresholds()
    hits: list[RuleHit] = []

    def g(key: str, default: float = 0.0) -> float:
        # Accept raw network names or fused physical aggregate names.
        if key in features and features[key] is not None:
            try:
                return float(features[key])
            except (TypeError, ValueError):
                return default
        for alt in (f"p_{key}_last", f"p_{key}_max", f"p_{key}_mean"):
            if alt in features and features[alt] is not None:
                try:
                    return float(features[alt])
                except (TypeError, ValueError):
                    continue
        return default

    if g("pkt_rate") > th.max_pkt_rate or g("command_long_count") > th.max_command_long:
        hits.append(
            RuleHit(
                "command_flood_suspected",
                "critical",
                f"pkt_rate={g('pkt_rate'):.0f}, command_long={g('command_long_count'):.0f}",
                "rate_limit_commands",
            )
        )
    if g("param_set_count") > th.max_param_set:
        hits.append(
            RuleHit(
                "param_injection_suspected",
                "critical",
                f"param_set_count={g('param_set_count'):.0f}",
                "block_param_set",
            )
        )
    if g("mission_item_count") > th.max_mission_item:
        hits.append(
            RuleHit(
                "mission_injection_suspected",
                "critical",
                f"mission_item_count={g('mission_item_count'):.0f}",
                "reject_mission_upload",
            )
        )
    if g("rc_override_count") > th.max_rc_override:
        hits.append(
            RuleHit(
                "rc_override_suspected",
                "critical",
                f"rc_override_count={g('rc_override_count'):.0f}",
                "ignore_rc_override",
            )
        )
    if g("gps_input_count") > th.max_gps_input:
        hits.append(
            RuleHit(
                "gps_spoof_traffic_suspected",
                "critical",
                f"gps_input_count={g('gps_input_count'):.0f}",
                "gps_integrity_gate",
            )
        )
    if g("set_mode_count") > th.max_set_mode:
        hits.append(
            RuleHit(
                "mode_hijack_suspected",
                "critical",
                f"set_mode_count={g('set_mode_count'):.0f}",
                "block_mode_change",
            )
        )
    if g("unique_sysids") > th.max_unique_sysids:
        hits.append(
            RuleHit(
                "spoofed_identity_suspected",
                "warn",
                f"unique_sysids={g('unique_sysids'):.0f}",
                "allowlist_sysid",
            )
        )
    if g("tilt_mag") > th.max_tilt_mag:
        hits.append(
            RuleHit(
                "abnormal_attitude",
                "warn",
                f"tilt_mag={g('tilt_mag'):.3f}",
                "hold_or_rtl",
            )
        )
    if abs(g("pos_err_z")) > th.max_pos_err_z:
        hits.append(
            RuleHit(
                "altitude_tracking_error",
                "warn",
                f"pos_err_z={g('pos_err_z'):.2f}",
                "gps_or_setpoint_check",
            )
        )

    return RuleResult(hits=hits)


# Map multiclass labels → default companion actions (Stage-2 response).
DEFENSE_ACTIONS = {
    "benign": "none",
    "command_flood_dos": "rate_limit_commands",
    "param_injection": "block_param_set",
    "disarm_injection": "require_auth_arming",
    "mode_change_land": "block_mode_change",
    "mission_injection": "reject_mission_upload",
    "rc_override": "ignore_rc_override",
    "gps_spoofing": "gps_integrity_gate",
}
