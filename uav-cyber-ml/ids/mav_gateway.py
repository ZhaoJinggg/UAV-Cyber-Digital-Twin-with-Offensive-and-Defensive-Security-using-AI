"""Proactive MAVLink gateway — filter attacker traffic *before* it reaches PX4.

Architecture
------------
Lab TX path (benign / attacker / defender) normally used ``udpout:UAV:14550``.
With the gateway enabled those sockets target ``udpout:127.0.0.1:GATEWAY_PORT``
and this process forwards only *allowed* datagrams to ``UAV_HOST:GCS_TX_PORT``.

Trusted GCS sysids (controller, defender, recorder) always pass.
When Defense is ON and mode is ``proactive`` / ``hybrid``, dangerous messages
from the attacker sysid are dropped at the gateway (true pre-PX4 prevention).
``reactive`` mode forwards everything and relies on post-detect reclaim.

Counters feed the dashboard proactive-vs-reactive table.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from collections import Counter
from typing import Any

import config as C

# MAVLink message IDs we treat as injectable attack surface.
MSG_SET_MODE = 11
MSG_PARAM_SET = 23
MSG_MISSION_ITEM = 39
MSG_MISSION_REQUEST = 40
MSG_MISSION_COUNT = 44
MSG_MISSION_CLEAR_ALL = 45
MSG_MISSION_ITEM_INT = 73
MSG_COMMAND_INT = 75
MSG_COMMAND_LONG = 76
MSG_MANUAL_CONTROL = 69
MSG_HIL_GPS = 113
MSG_GPS_INPUT = 232

DANGEROUS_MSGIDS = {
    MSG_SET_MODE, MSG_PARAM_SET, MSG_MISSION_ITEM, MSG_MISSION_COUNT,
    MSG_MISSION_CLEAR_ALL, MSG_MISSION_ITEM_INT, MSG_COMMAND_INT,
    MSG_COMMAND_LONG, MSG_MANUAL_CONTROL, MSG_HIL_GPS, MSG_GPS_INPUT,
}

# Rough msgid → attack class for dashboard tallies
MSGID_TO_CLASS = {
    MSG_GPS_INPUT: "gps_spoofing",
    MSG_HIL_GPS: "gps_spoofing",
    MSG_PARAM_SET: "param_injection",
    MSG_MISSION_ITEM: "mission_injection",
    MSG_MISSION_ITEM_INT: "mission_injection",
    MSG_MISSION_COUNT: "mission_injection",
    MSG_MISSION_CLEAR_ALL: "mission_injection",
    MSG_MANUAL_CONTROL: "rc_override",
    MSG_SET_MODE: "mode_change_land",
    MSG_COMMAND_LONG: "command_flood_dos",
    MSG_COMMAND_INT: "command_flood_dos",
}

# COMMAND_LONG command ids of interest (MAV_CMD)
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_NAV_TAKEOFF = 22
MAV_CMD_NAV_LAND = 21
MAV_CMD_NAV_RETURN_TO_LAUNCH = 20


def _parse_mavlink(buf: bytes) -> tuple[int, int, int] | None:
    """Return (sysid, msgid, magic) or None if not a MAVLink frame."""
    if not buf or len(buf) < 8:
        return None
    magic = buf[0]
    if magic == 0xFD and len(buf) >= 10:  # v2
        sysid = buf[5]
        msgid = buf[7] | (buf[8] << 8) | (buf[9] << 16)
        return sysid, msgid, magic
    if magic == 0xFE and len(buf) >= 6:  # v1
        sysid = buf[3]
        msgid = buf[5]
        return sysid, msgid, magic
    return None


def _command_long_id(buf: bytes, magic: int) -> int | None:
    """Extract COMMAND_LONG command id (float→int) when possible."""
    try:
        if magic == 0xFD and len(buf) >= 10 + 4 + 4 * 7:
            # payload starts at offset 10; COMMAND_LONG: 7 floats + target + cmd
            # Actually layout: param1..param7 (7*f32), command (u16), target_system, target_component
            # msgid at 7..9, payload at 10
            payload = buf[10:]
            if len(payload) < 33:
                return None
            cmd = struct.unpack_from("<H", payload, 28)[0]
            return int(cmd)
        if magic == 0xFE and len(buf) >= 6 + 33:
            payload = buf[6:]
            cmd = struct.unpack_from("<H", payload, 28)[0]
            return int(cmd)
    except Exception:
        return None
    return None


def _classify_packet(sysid: int, msgid: int, buf: bytes, magic: int) -> str:
    if msgid == MSG_COMMAND_LONG:
        cmd = _command_long_id(buf, magic)
        if cmd == MAV_CMD_COMPONENT_ARM_DISARM:
            # param1==0 → disarm (we don't always parse param1; treat as disarm risk)
            return "disarm_injection"
        if cmd == MAV_CMD_NAV_TAKEOFF:
            return "takeoff_injection"
        if cmd == MAV_CMD_NAV_LAND:
            return "mode_change_land"
        if cmd == MAV_CMD_NAV_RETURN_TO_LAUNCH:
            return "mode_change_rtl"
        return "command_flood_dos"
    return MSGID_TO_CLASS.get(msgid, "command_flood_dos")


class MavGateway:
    """UDP forwarder with proactive drop policy."""

    def __init__(self):
        self.listen_host = "127.0.0.1"
        self.listen_port = int(getattr(C, "MAV_GATEWAY_PORT", 19550))
        self.dest = (C.UAV_HOST, int(getattr(C, "GCS_TX_PORT", C.GCS_PORT)))
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._enabled = True  # process running
        self._defense_on = False
        self._mode = str(getattr(C, "DEFENSE_MODE", "hybrid")).lower()
        self._gt_attack = False
        self._gt_class: str | None = None
        self._drop_armed = False
        self._drop_class: str | None = None
        self._drop_reason: str | None = None
        self._trusted = {
            int(C.CONTROLLER_SYSID),
            int(getattr(C, "DEFENDER_SYSID", 249)),
            int(getattr(C, "RECORDER_SYSID", 254)),
            255,
        }
        self._attacker = int(C.ATTACKER_SYSID)
        # stats
        self.forwarded = 0
        self.dropped = 0
        self.proactive_blocks = 0
        self.blocks_by_class: Counter = Counter()
        self.block_latencies_ms: list[float] = []
        self.last_block: dict[str, Any] | None = None
        self._publish = None

    # ---------------------------------------------------------------- policy
    def set_publish(self, fn) -> None:
        self._publish = fn

    def set_defense_enabled(self, on: bool) -> None:
        with self._lock:
            self._defense_on = bool(on)
            if not on:
                self._drop_armed = False
                self._drop_class = None
                self._drop_reason = None

    def set_mode(self, mode: str) -> None:
        with self._lock:
            self._mode = (mode or "hybrid").strip().lower()

    def set_gt_attack(self, active: bool, attack_class: str | None = None) -> None:
        with self._lock:
            self._gt_attack = bool(active)
            self._gt_class = attack_class
            # Pure proactive/prevent: arm drops as soon as the attack window opens.
            # Hybrid waits for IDS detection so a brief physical effect is visible.
            if active and self._defense_on and self._mode in ("proactive", "prevent"):
                self._drop_armed = True
                self._drop_class = attack_class
                self._drop_reason = "gt_window_preemptive"

    def arm_drop_policy(self, attack_class: str | None, reason: str = "ids_alert") -> None:
        with self._lock:
            if not self._defense_on:
                return
            if self._mode not in ("proactive", "hybrid", "prevent"):
                return
            self._drop_armed = True
            self._drop_class = attack_class or self._drop_class
            self._drop_reason = reason

    def clear_drop_policy(self) -> None:
        with self._lock:
            # Keep drops during GT window in proactive/hybrid
            if self._gt_attack and self._defense_on and self._mode in (
                "proactive", "hybrid", "prevent"
            ):
                return
            self._drop_armed = False
            self._drop_reason = None

    def _should_drop(self, sysid: int, msgid: int) -> tuple[bool, str | None]:
        with self._lock:
            if not self._defense_on:
                return False, None
            if sysid in self._trusted:
                return False, None
            if sysid != self._attacker:
                # Unknown spoofed GCS — still drop dangerous msgs in proactive
                if self._mode in ("proactive", "hybrid", "prevent") and msgid in DANGEROUS_MSGIDS:
                    if self._drop_armed or self._gt_attack or self._mode == "proactive":
                        return True, "untrusted_sysid"
                return False, None
            if msgid not in DANGEROUS_MSGIDS:
                return False, None  # allow attacker heartbeats etc.
            mode = self._mode
            if mode == "reactive":
                return False, None
            if mode == "proactive":
                return True, "proactive_filter"
            # hybrid / prevent: drop once IDS arms the policy (or prevent always
            # after GT). Before arming, forward so the attack can produce a
            # brief observable effect, then mitigation engages.
            if mode == "prevent":
                if self._drop_armed or self._gt_attack:
                    return True, self._drop_reason or "prevent_filter"
                return False, None
            if mode == "hybrid":
                if self._drop_armed:
                    return True, self._drop_reason or "hybrid_ids_armed"
                return False, None
            if self._drop_armed or self._gt_attack:
                return True, self._drop_reason or "hybrid_filter"
            return False, None

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.listen_host, self.listen_port))
            sock.settimeout(0.5)
            self._sock = sock
        except OSError as exc:
            self._sock = None
            return False
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="mav-gateway")
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None

    def _loop(self) -> None:
        assert self._sock is not None
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            while not self._stop.is_set():
                try:
                    data, _addr = self._sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                t0 = time.perf_counter()
                parsed = _parse_mavlink(data)
                if parsed is None:
                    # forward opaque / non-mavlink
                    try:
                        out.sendto(data, self.dest)
                        self.forwarded += 1
                    except OSError:
                        pass
                    continue
                sysid, msgid, magic = parsed
                drop, reason = self._should_drop(sysid, msgid)
                if drop:
                    cls = _classify_packet(sysid, msgid, data, magic)
                    with self._lock:
                        if self._gt_class:
                            cls = self._gt_class
                        elif self._drop_class:
                            cls = self._drop_class
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    self.dropped += 1
                    self.proactive_blocks += 1
                    self.blocks_by_class[cls] += 1
                    self.block_latencies_ms.append(lat_ms)
                    if len(self.block_latencies_ms) > 500:
                        self.block_latencies_ms = self.block_latencies_ms[-250:]
                    self.last_block = {
                        "attack_class": cls,
                        "msgid": msgid,
                        "sysid": sysid,
                        "reason": reason,
                        "latency_ms": round(lat_ms, 3),
                        "ts": time.time(),
                    }
                    pub = self._publish
                    if pub is not None:
                        try:
                            pub({
                                "type": "ids",
                                "data": {
                                    "event": "proactive_block",
                                    "attack_class": cls,
                                    "msgid": msgid,
                                    "sysid": sysid,
                                    "reason": reason,
                                    "latency_ms": round(lat_ms, 3),
                                    "proactive_blocks": self.proactive_blocks,
                                    "message": (f"PROACTIVE BLOCK · {cls} "
                                                f"(msgid={msgid}, {reason})"),
                                },
                            })
                        except Exception:
                            pass
                    continue
                try:
                    out.sendto(data, self.dest)
                    self.forwarded += 1
                except OSError:
                    pass
        finally:
            try:
                out.close()
            except Exception:
                pass

    def status(self) -> dict:
        with self._lock:
            lats = list(self.block_latencies_ms)
        mean_lat = (sum(lats) / len(lats)) if lats else None
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "listen": f"{self.listen_host}:{self.listen_port}",
            "dest": f"{self.dest[0]}:{self.dest[1]}",
            "defense_on": self._defense_on,
            "mode": self._mode,
            "drop_armed": self._drop_armed,
            "gt_attack": self._gt_attack,
            "gt_class": self._gt_class,
            "forwarded": self.forwarded,
            "dropped": self.dropped,
            "proactive_blocks": self.proactive_blocks,
            "blocks_by_class": dict(self.blocks_by_class),
            "mean_block_latency_ms": round(mean_lat, 3) if mean_lat is not None else None,
            "last_block": dict(self.last_block) if self.last_block else None,
        }


_GATEWAY: MavGateway | None = None
_GATE_LOCK = threading.Lock()


def get_gateway() -> MavGateway:
    global _GATEWAY
    with _GATE_LOCK:
        if _GATEWAY is None:
            _GATEWAY = MavGateway()
        return _GATEWAY


def ensure_gateway_started(publish=None) -> MavGateway:
    g = get_gateway()
    if publish is not None:
        g.set_publish(publish)
    g.start()
    return g
