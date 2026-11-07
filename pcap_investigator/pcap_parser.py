"""
Module 1 - PCAP Analysis Module
Reads a PCAP/PCAPNG file with PyShark (tshark backend) and returns every
HTTP request as a plain Python dict with the raw header block and body.
"""
import asyncio
import os
import shutil
from pathlib import Path

import pyshark

HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE")


def find_tshark():
    """Locate TShark installed on Windows or kept with the local project."""
    portable = Path(__file__).resolve().parent / "tools" / "wireshark" / "Wireshark" / "tshark.exe"
    candidates = (
        os.environ.get("TSHARK_PATH"),
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        portable,
    )
    return next((str(path) for path in candidates if path and Path(path).is_file()), None)


def _hex_to_bytes(colon_hex):
    """PyShark gives tcp.payload as 'aa:bb:cc'. Convert to bytes."""
    try:
        return bytes.fromhex(colon_hex.replace(":", ""))
    except (ValueError, AttributeError):
        return b""


def _field(layer, name, default=""):
    try:
        val = layer.get_field_value(name)
        return str(val) if val is not None else default
    except Exception:
        return default


def _rebuild_from_fields(http):
    """Fallback when the request spans several TCP segments: rebuild the
    header lines from the fields Wireshark already dissected."""
    method = _field(http, "request_method")
    uri = _field(http, "request_uri")
    version = _field(http, "request_version")
    lines = []
    try:
        for f in http.request_line.all_fields:
            lines.append(f.get_default_value().replace("\\r\\n", "").strip())
    except Exception:
        pass
    raw_body = b""
    fd = _field(http, "file_data")
    if fd:
        raw_body = _hex_to_bytes(fd) if ":" in fd else fd.encode("latin-1", "ignore")
    return f"{method} {uri} {version}", lines, raw_body


def parse_http_header_block(raw):
    """Split raw request bytes into (request_line, [header lines], body bytes)."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    return lines[0], [l for l in lines[1:] if l.strip()], body


def extract_http_requests(pcap_path):
    """Yield one dict per HTTP request found in the capture."""
    # Python 3.14+ no longer creates an event loop automatically, but PyShark
    # expects one to exist. Create it ourselves (on Windows this is a
    # ProactorEventLoop, which PyShark needs to start tshark).
    asyncio.set_event_loop(asyncio.new_event_loop())
    tshark_path = find_tshark()
    if tshark_path is None:
        raise FileNotFoundError("TShark was not found. Set TSHARK_PATH to tshark.exe.")
    cap = pyshark.FileCapture(pcap_path, display_filter="http.request", keep_packets=False,
                              tshark_path=tshark_path)
    try:
        for pkt in cap:
            http = pkt.http
            ip_layer = pkt.ip if hasattr(pkt, "ip") else getattr(pkt, "ipv6", None)
            if ip_layer is None:
                continue

            raw = _hex_to_bytes(_field(pkt.tcp, "payload")) if hasattr(pkt, "tcp") else b""
            if raw.startswith(tuple(m.encode() for m in HTTP_METHODS)) and b"\r\n\r\n" in raw:
                request_line, header_lines, body = parse_http_header_block(raw)
            else:
                request_line, header_lines, body = _rebuild_from_fields(http)

            yield {
                "frame": int(pkt.number),
                "timestamp": float(pkt.sniff_timestamp),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "src_port": int(pkt.tcp.srcport) if hasattr(pkt, "tcp") else 0,
                "dst_port": int(pkt.tcp.dstport) if hasattr(pkt, "tcp") else 0,
                "method": _field(http, "request_method"),
                "uri": _field(http, "request_uri"),
                "version": _field(http, "request_version"),
                "request_line": request_line,
                "header_lines": header_lines,
                "body": body,
            }
    finally:
        cap.close()
