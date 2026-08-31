#!/usr/bin/env python3
"""Preflight check for the Digital Twin → Physical Twin network link.

The lab defaults in ``config.py`` (``192.168.123.130``, user ``danish``) are
specific to the authors' bench, where the UAV workstation holds a static
address. On a DHCP network the Physical Twin gets a different address — often
a new one after each reboot — so those defaults will not reach it.

Nothing here changes the project's configuration. It inspects the link, tells
you what is wrong, and prints the exact environment variables to export.

    python scripts/uav_link.py                      # check current settings
    python scripts/uav_link.py --host 192.168.1.42  # check a specific host
    python scripts/uav_link.py --scan               # find the PT on this LAN

Exit status is 0 when the link is usable, 1 otherwise, so it can gate a script.
"""

from __future__ import annotations

import argparse
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    GREEN = RED = YELLOW = DIM = RESET = ""

PASS, FAIL, WARN = f"{GREEN}PASS{RESET}", f"{RED}FAIL{RESET}", f"{YELLOW}WARN{RESET}"

SSH_PORT = 22
GCS_PORT = 14550          # PX4 telemetry the DT recorder binds
_results: list[tuple[str, bool]] = []


def report(status: str, title: str, detail: str = "", fix: str = "") -> None:
    print(f"  [{status}] {title}")
    if detail:
        print(f"         {DIM}{detail}{RESET}")
    if fix:
        print(f"         {YELLOW}→ {fix}{RESET}")
    _results.append((title, status == PASS))


def resolve(host: str) -> str | None:
    """Return a dotted IPv4 for host (already-an-IP passes straight through)."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def local_ip() -> str | None:
    """This machine's IP on the interface that reaches the outside world."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))       # no traffic is actually sent
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def ping(host: str, timeout_s: int = 2) -> bool:
    flag = "-W" if platform.system() == "Darwin" else "-w"
    val = str(timeout_s * 1000) if platform.system() == "Darwin" else str(timeout_s)
    try:
        return subprocess.run(["ping", "-c", "1", flag, val, host],
                              capture_output=True, timeout=timeout_s + 2).returncode == 0
    except Exception:
        return False


def tcp_open(host: str, port: int, timeout_s: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def udp_port_free(port: int) -> tuple[bool, str]:
    """True if we can bind the telemetry port (QGroundControl often holds it)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        return True, ""
    except OSError as e:
        return False, str(e)
    finally:
        s.close()


def detect_iface(host: str) -> str | None:
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(["route", "get", host], capture_output=True,
                                 text=True, timeout=3).stdout
            for line in out.splitlines():
                if line.strip().startswith("interface:"):
                    return line.split(":", 1)[1].strip()
        else:
            out = subprocess.run(["ip", "route", "get", host], capture_output=True,
                                 text=True, timeout=3).stdout.split()
            if "dev" in out:
                return out[out.index("dev") + 1]
    except Exception:
        pass
    return None


def ssh_ok(user: str, host: str) -> tuple[bool, str]:
    """Key-based, non-interactive SSH — same options ssh_control.py uses."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=5", f"{user}@{host}", "echo ok"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return p.returncode == 0 and "ok" in p.stdout, (p.stderr or "").strip().split("\n")[-1]
    except Exception as e:
        return False, str(e)


def scan(base_ip: str, workers: int = 64) -> list[tuple[str, str]]:
    """Find hosts on this /24 with SSH open — PT candidates."""
    from concurrent.futures import ThreadPoolExecutor
    prefix = ".".join(base_ip.split(".")[:3])
    targets = [f"{prefix}.{i}" for i in range(1, 255) if f"{prefix}.{i}" != base_ip]
    print(f"  {DIM}scanning {prefix}.1-254 for hosts with SSH open…{RESET}")

    def probe(ip: str) -> tuple[str, str] | None:
        if not tcp_open(ip, SSH_PORT, timeout_s=0.6):
            return None
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        return (ip, name)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return [r for r in ex.map(probe, targets) if r]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", help="PT address or hostname to test (default: $UAV_HOST)")
    ap.add_argument("--user", help="SSH user on the PT (default: $UAV_SSH_USER)")
    ap.add_argument("--scan", action="store_true", help="scan this LAN for the PT")
    args = ap.parse_args()

    host_in = args.host or os.environ.get("UAV_HOST", "192.168.123.130")
    user = args.user or os.environ.get("UAV_SSH_USER", "danish")

    print(f"\n{DIM}UAV Cyber Digital Twin — link preflight{RESET}")
    print(f"{DIM}{'=' * 58}{RESET}\n")

    mine = local_ip()
    print(f"  Digital Twin (this machine): {mine or 'unknown'}  [{platform.system()}]")
    print(f"  Physical Twin (target):      {host_in}  (user: {user})\n")

    if args.scan:
        if not mine:
            print(f"  {RED}Cannot determine this machine's IP — are you on a network?{RESET}")
            return 1
        found = scan(mine)
        if not found:
            print(f"\n  {YELLOW}No SSH hosts found on your subnet.{RESET}")
            print("  The PT may be on a different network, powered off, or without an SSH server.")
            return 1
        print(f"\n  Found {len(found)} host(s) with SSH open:\n")
        for ip, name in found:
            print(f"    {ip:<16} {DIM}{name}{RESET}")
        print(f"\n  {YELLOW}Identify your UAV workstation above, then re-run:{RESET}")
        print(f"    python scripts/uav_link.py --host <that-ip> --user <your-ssh-user>\n")
        return 0

    # ---- 1. resolve ----
    ip = resolve(host_in)
    if ip is None:
        report(FAIL, f"Resolve '{host_in}'", "hostname did not resolve",
               "Check spelling, or use --scan to find the PT's address")
        ip = host_in
    elif ip != host_in:
        report(PASS, f"Resolve '{host_in}'", f"→ {ip}")
    else:
        report(PASS, f"Address {ip}", "literal IP, no lookup needed")

    # ---- 2. reachable ----
    if ping(ip):
        report(PASS, f"Ping {ip}", "host is up")
    else:
        report(WARN, f"Ping {ip}", "no ICMP reply (some hosts block ping)",
               "If SSH below also fails, the address is wrong or the host is down")

    # ---- 3. SSH port ----
    if tcp_open(ip, SSH_PORT):
        report(PASS, f"TCP {ip}:22", "SSH server is listening")
    else:
        report(FAIL, f"TCP {ip}:22", "no SSH server reachable",
               "Wrong address, host down, firewall, or sshd not installed on the PT")

    # ---- 4. SSH auth ----
    ok, err = ssh_ok(user, ip)
    if ok:
        report(PASS, f"SSH {user}@{ip}", "key-based login works")
    else:
        report(FAIL, f"SSH {user}@{ip}", err or "authentication failed",
               f"Set up key auth:  ssh-copy-id {user}@{ip}   (the project uses BatchMode)")

    # ---- 5. telemetry port free on the DT ----
    free, err = udp_port_free(GCS_PORT)
    if free:
        report(PASS, f"UDP :{GCS_PORT} free", "the recorder can bind telemetry")
    else:
        report(FAIL, f"UDP :{GCS_PORT} busy", err,
               "Close QGroundControl (or rebind it) — it holds this port")

    # ---- 6. capture interface ----
    iface = os.environ.get("NET_IFACE") or detect_iface(ip)
    if iface:
        report(PASS, "Capture interface", f"tcpdump will use '{iface}'")
    else:
        report(WARN, "Capture interface", "could not auto-detect",
               "Set it explicitly, e.g. NET_IFACE=en0 (macOS) or NET_IFACE=eth0 (Linux)")

    # ---- summary ----
    failed = [t for t, ok_ in _results if not ok_]
    print(f"\n{DIM}{'-' * 58}{RESET}")
    if not failed:
        print(f"  {GREEN}Link looks good.{RESET} Export these before starting the dashboard:\n")
        print(f"    export UAV_HOST={host_in}")
        print(f"    export UAV_SSH_USER={user}")
        if iface:
            print(f"    export NET_IFACE={iface}")
        print(f"\n  Then:  ./run_dashboard.sh\n")
        return 0

    print(f"  {RED}{len(failed)} check(s) failed.{RESET} Fix the → items above, then re-run.")
    print(f"  {DIM}Find the PT's current address by running  hostname -I  on the UAV PC,{RESET}")
    print(f"  {DIM}or run:  python scripts/uav_link.py --scan{RESET}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
