"""
Module 2 - HTTP Feature Extraction Module
Turns a parsed HTTP request into the characteristics studied in
"Characterizing Anomalies in Malware-Generated HTTP Traffic":
HTTP version, header count / presence, User-Agent, Referer, Host,
payload size, non-ASCII content and payload entropy.
"""
import ipaddress
import math
from collections import Counter

# Headers a normal browser practically always sends
COMMON_BROWSER_HEADERS = ("accept", "accept-language", "accept-encoding")


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = constant, 8 = random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def non_ascii_ratio(data: bytes) -> float:
    """Share of bytes that are not printable ASCII (tab/CR/LF allowed)."""
    if not data:
        return 0.0
    bad = sum(1 for b in data if b > 126 or (b < 32 and b not in (9, 10, 13)))
    return bad / len(data)


def is_ip_address(host: str) -> bool:
    host = host.strip().strip("[]")
    if host.count(":") == 1:          # strip ":port"
        host = host.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_features(req: dict) -> dict:
    headers = {}
    for line in req["header_lines"]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

    body = req["body"] or b""
    host = headers.get("host", "")
    return {
        "http_version": req["version"] or req["request_line"].split(" ")[-1],
        "header_count": len(headers),
        "header_names": list(headers.keys()),
        "host": host,
        "host_is_ip": is_ip_address(host) if host else False,
        "has_host": bool(host),
        "user_agent": headers.get("user-agent", ""),
        "has_user_agent": "user-agent" in headers,
        "referer": headers.get("referer", ""),
        "has_referer": "referer" in headers,
        "missing_common_headers": [h for h in COMMON_BROWSER_HEADERS if h not in headers],
        "payload_len": len(body),
        "payload_entropy": round(shannon_entropy(body), 3),
        "non_ascii_ratio": round(non_ascii_ratio(body), 3),
    }
