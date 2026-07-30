"""Live network-feature sniffer (dashboard only).

Runs `tcpdump -w -` to stdout and parses the pcap stream on the fly with scapy,
emitting one windowed feature dict per second via ``on_window``. This is purely
for live visualisation; the authoritative per-packet + per-window dataset is
still produced by ``NetworkRecorder`` from its own saved pcap.

Requires sudo (credentials are cached once by the orchestrator via `sudo -v`).
"""

from __future__ import annotations

import statistics
import subprocess
import threading
import time

import config as C

_MAV_PORTS = [C.GCS_API_PORT, C.GCS_PORT, C.RX_PORT, C.OFFBOARD_PORT]

_COUNT_KEYS = [
    ("heartbeat_count", "HEARTBEAT"),
    ("command_long_count", "COMMAND_LONG"),
    ("param_set_count", "PARAM_SET"),
    ("rc_override_count", "RC_CHANNELS_OVERRIDE"),
    ("manual_control_count", "MANUAL_CONTROL"),
    ("gps_input_count", "GPS_INPUT"),
    ("set_mode_count", "SET_MODE"),
]
_MISSION_NAMES = {"MISSION_ITEM_INT", "MISSION_ITEM", "MISSION_COUNT"}


class LiveNetworkSniffer:
    def __init__(self, on_window, iface: str | None = None):
        self.on_window = on_window
        self.iface = iface or C.NET_IFACE
        self.proc = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._acc: list[dict] = []
        self._t0 = None
        self._win = 0
        self._reader = None
        self._ticker = None

    def start(self):
        ports = " or ".join(f"port {p}" for p in _MAV_PORTS)
        expr = f"host {C.UAV_HOST} and udp and ({ports})"
        cmd = ["sudo", "-n", "tcpdump", "-i", self.iface, "-n", "-U", "-w", "-", expr]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, bufsize=0,
                                         start_new_session=True)
        except Exception:
            self.proc = None
            return
        self._t0 = time.time()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._ticker = threading.Thread(target=self._tick_loop, daemon=True)
        self._ticker.start()

    def stop(self):
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            try:
                import os
                import signal
                os.killpg(self.proc.pid, signal.SIGINT)
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    subprocess.run(["sudo", "-n", "pkill", "-INT", "-f",
                                    "tcpdump.*-w -"],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                    self.proc.wait(timeout=2)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass

    def _read_loop(self):
        try:
            from scapy.all import PcapReader, IP, UDP
        except Exception:
            return
        try:
            from pymavlink.dialects.v20 import common as mavlink2
            parser = mavlink2.MAVLink(None)
        except Exception:
            parser = None
        try:
            reader = PcapReader(self.proc.stdout)
        except Exception:
            return
        for p in reader:
            if self._stop.is_set():
                break
            try:
                if IP not in p or UDP not in p:
                    continue
                ip, udp = p[IP], p[UDP]
                payload = bytes(udp.payload)
                name = ""
                msgid = None
                sysid = None
                if parser is not None and payload and payload[0] in (0xFD, 0xFE):
                    try:
                        msgs = parser.parse_buffer(payload) or []
                        if msgs:
                            m0 = msgs[0]
                            name = m0.get_type()
                            msgid = getattr(m0, "id", None)
                            try:
                                sysid = m0.get_srcSystem()
                            except Exception:
                                sysid = getattr(m0, "_header", None)
                                sysid = getattr(sysid, "srcSystem", None) if sysid else None
                    except Exception:
                        pass
                rec = {
                    "len": len(payload),
                    "to_uav": ip.dst == C.UAV_HOST,
                    "name": name,
                    "msgid": msgid,
                    "sysid": sysid,
                    "t": time.time(),
                }
                with self._lock:
                    self._acc.append(rec)
            except Exception:
                continue

    def _tick_loop(self):
        while not self._stop.is_set():
            time.sleep(1.0)
            with self._lock:
                batch = self._acc
                self._acc = []
            self._emit(batch)

    def _emit(self, batch: list[dict]):
        win = self._win
        self._win += 1
        lens = [r["len"] for r in batch]
        ts = sorted(r["t"] for r in batch)
        iats = [b - a for a, b in zip(ts, ts[1:])]
        names = [r["name"] for r in batch]
        msgids = {r["msgid"] for r in batch if r.get("msgid") is not None}
        sysids = {r["sysid"] for r in batch if r.get("sysid") is not None}
        mission_n = sum(1 for n in names if n in _MISSION_NAMES)
        out = {
            "win": win,
            "t_rel": win,
            "pkt_count": len(batch),
            "byte_count": sum(lens),
            "pkt_rate": len(batch),
            "byte_rate": sum(lens),
            "mean_len": round(statistics.mean(lens), 1) if lens else 0.0,
            "std_len": round(statistics.pstdev(lens), 2) if len(lens) > 1 else 0.0,
            "mean_iat": round(statistics.mean(iats), 4) if iats else 0.0,
            "std_iat": round(statistics.pstdev(iats), 4) if len(iats) > 1 else 0.0,
            "to_uav_count": sum(1 for r in batch if r["to_uav"]),
            "from_uav_count": sum(1 for r in batch if not r["to_uav"]),
            "unique_msgids": len(msgids),
            "unique_sysids": len(sysids),
            "mission_count": mission_n,
            "mission_item_count": mission_n,
        }
        for key, nm in _COUNT_KEYS:
            out[key] = sum(1 for n in names if n == nm)
        try:
            self.on_window(out)
        except Exception:
            pass
