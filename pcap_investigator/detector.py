"""
Module 3 - Paper-Based Anomaly Detection Module
Each anomaly indicator from the paper adds 1 point. A request whose
score reaches SCORE_THRESHOLD is flagged as anomalous.
This is the BASELINE (paper) approach - it judges each request alone.
"""
import math
import re

SCORE_THRESHOLD = 3
LOW_HEADER_COUNT = 3           # browsers send ~6-12 headers
HIGH_ENTROPY_BITS = 7.0        # bits/byte for payloads >= 256 bytes
MIN_PAYLOAD_FOR_ENTROPY = 32
NON_ASCII_LIMIT = 0.10         # >10% non-printable bytes

# User-Agents that are not a modern browser
SUSPICIOUS_UA = re.compile(
    r"(MSIE [1-7]\.|python|curl|wget|winhttp|go-http|java/|libwww|"
    r"powershell|bitsadmin|^mozilla/4\.0$|^-$|^test)", re.IGNORECASE)

INDICATOR_TEXT = {
    "http_1_0": "Uses outdated HTTP/1.0",
    "low_header_count": "Very few HTTP headers",
    "missing_user_agent": "No User-Agent header",
    "suspicious_user_agent": "Non-browser / outdated User-Agent",
    "missing_referer": "No Referer header",
    "host_is_ip": "Host is a raw IP address",
    "missing_host": "No Host header",
    "missing_browser_headers": "Missing Accept / Accept-Language / Accept-Encoding",
    "non_ascii_payload": "Binary (non-ASCII) payload",
    "high_entropy_payload": "High-entropy (encrypted/packed) payload",
}


def _high_entropy(f):
    n = f["payload_len"]
    if n < MIN_PAYLOAD_FOR_ENTROPY:
        return False
    if n >= 256:
        return f["payload_entropy"] >= HIGH_ENTROPY_BITS
    # short payloads can't reach 8 bits/byte, so compare to their maximum
    return f["payload_entropy"] >= 0.85 * math.log2(n)


def score_request(f: dict):
    """Return (score, [indicator names]) for one request's features."""
    hits = []
    if f["http_version"].upper() == "HTTP/1.0":
        hits.append("http_1_0")
    if f["header_count"] <= LOW_HEADER_COUNT:
        hits.append("low_header_count")
    if not f["has_user_agent"]:
        hits.append("missing_user_agent")
    elif SUSPICIOUS_UA.search(f["user_agent"]) or len(f["user_agent"]) < 12:
        hits.append("suspicious_user_agent")
    if not f["has_referer"]:
        hits.append("missing_referer")
    if not f["has_host"]:
        hits.append("missing_host")
    elif f["host_is_ip"]:
        hits.append("host_is_ip")
    if len(f["missing_common_headers"]) >= 2:
        hits.append("missing_browser_headers")
    if f["payload_len"] and f["non_ascii_ratio"] > NON_ASCII_LIMIT:
        hits.append("non_ascii_payload")
    if _high_entropy(f):
        hits.append("high_entropy_payload")
    return len(hits), hits


def is_anomalous(score: int) -> bool:
    return score >= SCORE_THRESHOLD
