"""Stage 2: turn raw banners into structured fingerprints."""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass, field, asdict

from .portscan import PortResult

# Ports we actively talk HTTP to, even when the banner said nothing.
HTTP_PORTS = {80, 8000, 8080, 8088, 8099, 3000, 5000}
HTTPS_PORTS = {443, 8443}

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class Fingerprint:
    port: int
    service: str = "unknown"
    product: str = ""
    version: str = ""
    http_status: int | None = None
    http_title: str = ""
    headers: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    banner: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_server_header(value: str) -> tuple[str, str]:
    """'DemoWeb/1.4.2 Python/3.10.6' -> ('DemoWeb', '1.4.2')."""
    if not value:
        return "", ""
    token = value.split()[0]
    if "/" in token:
        product, _, ver = token.partition("/")
        m = _VERSION_RE.search(ver)
        return product.strip(), (m.group(1) if m else ver.strip())
    return token.strip(), ""


def _http_request(host: str, port: int, path: str = "/", use_tls: bool = False,
                  timeout: float = 2.0) -> tuple[int | None, dict, str, dict]:
    """Return (status_code, headers, body, tls_facts). Never raises."""
    sock = None
    raw = b""
    tls_info: dict = {}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
            der = sock.getpeercert(binary_form=True) or b""
            tls_info = {
                "version": sock.version() or "",
                "cipher": (sock.cipher() or ("",) * 3)[0],
                "cert_sha256": hashlib.sha256(der).hexdigest()[:32] if der else "",
                "cert_bytes": len(der),
                "trusted": False,
            }
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "User-Agent: PyVulScan/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        sock.settimeout(timeout)
        while len(raw) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    except (OSError, ssl.SSLError):
        return None, {}, "", tls_info
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if not raw:
        return None, {}, "", tls_info

    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = None
    m = re.match(r"HTTP/\d\.\d (\d{3})", lines[0] or "")
    if m:
        status = int(m.group(1))
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers, body.decode("latin-1", "replace"), tls_info


def classify_service(port: int, banner: str) -> str:
    b = banner.strip()
    if b.startswith("SSH-"):
        return "ssh"
    if b[:3].isdigit() and ("FTP" in b or "ftp" in b):
        return "ftp"
    if b.startswith("220") and ("SMTP" in b or "smtp" in b):
        return "smtp"
    if b.startswith("HTTP/"):
        return "https" if port in HTTPS_PORTS else "http"
    if "login:" in b.lower() or "telnet" in b.lower():
        return "telnet"
    if port in (3306,):
        return "mysql"
    if port in (5432,):
        return "postgresql"
    if port in (6379,):
        return "redis"
    if port in (22,):
        return "ssh"
    return "unknown"


def fingerprint_port(host: str, res: PortResult) -> Fingerprint:
    fp = Fingerprint(port=res.port, banner=res.banner)
    service = classify_service(res.port, res.banner)

    # Anything that looks HTTP-ish (or sits on a web port) gets a real request.
    if service in ("http", "https") or res.port in HTTP_PORTS | HTTPS_PORTS:
        use_tls = res.port in HTTPS_PORTS
        status, headers, body, tls_info = _http_request(host, res.port, "/", use_tls)
        if status is not None:
            fp.service = "https" if use_tls else "http"
            fp.http_status = status
            fp.headers = headers
            fp.tls = tls_info
            fp.product, fp.version = parse_server_header(headers.get("server", ""))
            m = _TITLE_RE.search(body)
            fp.http_title = (m.group(1).strip()[:80] if m else "")
            return fp

    fp.service = service
    if service == "ssh":
        fp.product = "OpenSSH" if "OpenSSH" in res.banner else "ssh"
        m = re.search(r"OpenSSH_(\S+)", res.banner)
        fp.version = m.group(1) if m else ""
    elif service in ("ftp", "smtp"):
        m = _VERSION_RE.search(res.banner)
        fp.version = m.group(1) if m else ""

    # Last resort: an HTTP probe on a port the banner did not identify.
    if service == "unknown" and res.banner:
        status, headers, _, tls_info = _http_request(host, res.port, "/")
        if status is not None:
            fp.service = "http"
            fp.http_status = status
            fp.headers = headers
            fp.product, fp.version = parse_server_header(headers.get("server", ""))
    return fp


def fingerprint_host(host: str, results: list[PortResult]) -> list[Fingerprint]:
    return [fingerprint_port(host, r) for r in results if r.status == "open"]
