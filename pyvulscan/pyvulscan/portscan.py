"""Stage 1 scanner: TCP connect scan + banner grabbing, stdlib only."""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Iterable

from .scope import assert_in_scope

# Quick triage set (top-ish ports). Stage 2 grows this into a profile file.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017,
]

# Port -> human label used for fingerprinting and later rule matching.
PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http", 8080: "http", 8443: "https", 27017: "mongodb",
}


@dataclass
class PortResult:
    port: int
    status: str = "filtered"      # open | closed | filtered
    service: str = ""
    banner: str = ""
    rtt_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def probe_port(host: str, port: int, timeout: float = 0.8) -> PortResult:
    """TCP connect probe + best-effort banner grab."""
    res = PortResult(port=port, service=PORT_HINTS.get(port, ""))
    t0 = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        res.status = "open"
    except (socket.timeout, TimeoutError):
        sock.close()
        return res
    except ConnectionRefusedError:
        res.status = "closed"
        sock.close()
        return res
    except OSError:
        sock.close()
        return res

    res.rtt_ms = round((time.perf_counter() - t0) * 1000, 1)

    try:
        sock.settimeout(0.4)
        try:
            data = sock.recv(1024)       # server-first: SSH, FTP, SMTP, telnet
        except (socket.timeout, TimeoutError):
            data = b""
        if not data:                     # client-first: HTTP and friends
            sock.sendall(
                b"HEAD / HTTP/1.0\r\nHost: %s\r\n"
                b"User-Agent: PyVulScan/0.1\r\n\r\n" % host.encode()
            )
            sock.settimeout(1.0)
            data = sock.recv(1024)
        res.banner = data.decode("latin-1", "replace").strip()
    except OSError:
        pass
    finally:
        sock.close()

    return res


def scan(
    host: str,
    ports: Iterable[int] | None = None,
    workers: int = 64,
    timeout: float = 0.8,
    show_closed: bool = False,
) -> list[PortResult]:
    host = assert_in_scope(host)
    ports = list(ports or DEFAULT_PORTS)

    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=min(workers, max(len(ports), 1))) as pool:
        futures = {pool.submit(probe_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r.port)
    if not show_closed:
        results = [r for r in results if r.status != "closed"]
    return results
