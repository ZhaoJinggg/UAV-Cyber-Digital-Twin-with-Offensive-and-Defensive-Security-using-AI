"""Network-layer recorder.

Captures the Mac<->UAV MAVLink traffic with tcpdump (needs sudo; the orchestrator
caches credentials once via `sudo -v`), then parses the pcap into:

  network_raw.csv        one row per captured packet (+ decoded MAVLink header)
  network_processed.csv  windowed traffic-flow features (rates, sizes, msg mix)

All MAVLink attack packets originate from the Mac, so this captures the full
adversary<->vehicle exchange.
"""

from __future__ import annotations

import csv
import statistics
import subprocess
import time
from pathlib import Path

import config as C

NET_WINDOW_S = 1.0

RAW_HEADER = ["t_wall", "t_rel", "src_ip", "dst_ip", "src_port", "dst_port",
              "ip_len", "udp_payload_len", "direction", "mav_version",
              "msgid", "msg_name", "mav_sysid", "mav_compid", "mav_seq"]

PROC_HEADER = ["t_rel", "win_s", "pkt_count", "byte_count", "pkt_rate", "byte_rate",
               "mean_len", "std_len", "mean_iat", "std_iat",
               "to_uav_count", "from_uav_count",
               "unique_msgids", "unique_sysids",
               "heartbeat_count", "command_long_count", "param_set_count",
               "mission_item_count", "rc_override_count", "manual_control_count",
               "gps_input_count", "set_mode_count"]

_MAV_PORTS = [C.GCS_API_PORT, C.GCS_PORT, C.RX_PORT, C.OFFBOARD_PORT]

# MAVLink message ids of interest
MSGID = {
    0: "HEARTBEAT", 76: "COMMAND_LONG", 11: "SET_MODE", 23: "PARAM_SET",
    73: "MISSION_ITEM_INT", 39: "MISSION_ITEM", 44: "MISSION_COUNT",
    70: "RC_CHANNELS_OVERRIDE", 69: "MANUAL_CONTROL", 232: "GPS_INPUT",
}


class NetworkRecorder:
    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.pcap = self.run_dir / "network_capture.pcap"
        self.proc = None
        self.t0 = None

    def start(self):
        ports = " or ".join(f"port {p}" for p in _MAV_PORTS)
        expr = f"host {C.UAV_HOST} and udp and ({ports})"
        cmd = ["sudo", "-n", "tcpdump", "-i", C.NET_IFACE, "-n", "-U",
               "-w", str(self.pcap), expr]
        self.t0 = time.time()
        # start_new_session: sudo/tcpdump get their own process group so we can
        # kill the whole tree (kill on the sudo PID alone often leaves tcpdump
        # orphaned and writing forever on macOS).
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL,
                                     start_new_session=True)
        time.sleep(0.5)

    def stop(self):
        self._kill_capture()
        time.sleep(0.3)
        self._parse()

    def _kill_capture(self):
        """Stop tcpdump reliably (sudo parent + real capturer + leftover orphans)."""
        if self.proc and self.proc.poll() is None:
            try:
                import os
                import signal
                os.killpg(self.proc.pid, signal.SIGINT)
            except Exception:
                subprocess.run(["sudo", "-n", "kill", "-INT", "-g",
                                str(self.proc.pid)],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            try:
                self.proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                try:
                    import os
                    import signal
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
        # Belt-and-suspenders: anything still writing THIS pcap
        subprocess.run(["sudo", "-n", "pkill", "-INT", "-f",
                        f"tcpdump.*{self.pcap.name}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "-n", "pkill", "-KILL", "-f",
                        f"tcpdump.*{self.pcap.name}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _parse(self):
        try:
            from scapy.all import rdpcap, IP, UDP
        except Exception as exc:  # noqa: BLE001
            (self.run_dir / "network_ERROR.txt").write_text(
                f"scapy not available: {exc}\n")
            return
        try:
            from pymavlink.dialects.v20 import common as mavlink2
        except Exception:
            mavlink2 = None

        try:
            pkts = rdpcap(str(self.pcap))
        except Exception as exc:  # noqa: BLE001
            (self.run_dir / "network_ERROR.txt").write_text(f"rdpcap failed: {exc}\n")
            return

        parser = mavlink2.MAVLink(None) if mavlink2 else None
        rows = []
        t0 = float(pkts[0].time) if len(pkts) else self.t0
        for p in pkts:
            if IP not in p or UDP not in p:
                continue
            ip = p[IP]
            udp = p[UDP]
            payload = bytes(udp.payload)
            direction = "to_uav" if ip.dst == C.UAV_HOST else "from_uav"
            mav_ver = msgid = sysid = compid = seq = ""
            msg_name = ""
            if payload:
                if payload[0] == 0xFD:
                    mav_ver = 2
                elif payload[0] == 0xFE:
                    mav_ver = 1
                if parser is not None and mav_ver:
                    try:
                        msgs = parser.parse_buffer(payload) or []
                        if msgs:
                            mm = msgs[0]
                            msgid = mm.get_msgId()
                            msg_name = mm.get_type()
                            sysid = mm.get_srcSystem()
                            compid = mm.get_srcComponent()
                            seq = mm.get_seq()
                    except Exception:
                        pass
            rows.append({
                "t_wall": float(p.time), "t_rel": float(p.time) - t0,
                "src_ip": ip.src, "dst_ip": ip.dst,
                "src_port": udp.sport, "dst_port": udp.dport,
                "ip_len": ip.len, "udp_payload_len": len(payload),
                "direction": direction, "mav_version": mav_ver,
                "msgid": msgid, "msg_name": msg_name,
                "mav_sysid": sysid, "mav_compid": compid, "mav_seq": seq,
            })

        with open(self.run_dir / "network_raw.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=RAW_HEADER)
            w.writeheader()
            for r in rows:
                w.writerow(r)

        self._windows(rows)

    def _windows(self, rows: list):
        with open(self.run_dir / "network_processed.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(PROC_HEADER)
            if not rows:
                return
            end = rows[-1]["t_rel"]
            win = 0.0
            i = 0
            n = len(rows)
            while win <= end:
                w_rows = [r for r in rows if win <= r["t_rel"] < win + NET_WINDOW_S]
                if w_rows:
                    lens = [r["udp_payload_len"] for r in w_rows]
                    ts = [r["t_rel"] for r in w_rows]
                    iats = [b - a for a, b in zip(ts, ts[1:])]
                    names = [r["msg_name"] for r in w_rows]

                    def cnt(nm):
                        return sum(1 for x in names if x == nm)

                    w.writerow([
                        round(win, 3), NET_WINDOW_S, len(w_rows), sum(lens),
                        len(w_rows) / NET_WINDOW_S, sum(lens) / NET_WINDOW_S,
                        round(statistics.mean(lens), 2),
                        round(statistics.pstdev(lens), 2) if len(lens) > 1 else 0.0,
                        round(statistics.mean(iats), 4) if iats else 0.0,
                        round(statistics.pstdev(iats), 4) if len(iats) > 1 else 0.0,
                        sum(1 for r in w_rows if r["direction"] == "to_uav"),
                        sum(1 for r in w_rows if r["direction"] == "from_uav"),
                        len({r["msgid"] for r in w_rows if r["msgid"] != ""}),
                        len({r["mav_sysid"] for r in w_rows if r["mav_sysid"] != ""}),
                        cnt("HEARTBEAT"), cnt("COMMAND_LONG"), cnt("PARAM_SET"),
                        cnt("MISSION_ITEM_INT") + cnt("MISSION_ITEM") + cnt("MISSION_COUNT"),
                        cnt("RC_CHANNELS_OVERRIDE"), cnt("MANUAL_CONTROL"),
                        cnt("GPS_INPUT"), cnt("SET_MODE"),
                    ])
                else:
                    w.writerow([round(win, 3), NET_WINDOW_S] + [0] * (len(PROC_HEADER) - 2))
                win += NET_WINDOW_S
