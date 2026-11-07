"""Cautious case labels and response suggestions derived from observed HTTP traffic.

These are triage hints, not malware identification or automatic enforcement.
In particular, a single source/destination group cannot establish a DDoS attack.
"""
import base64
import binascii
import re
from urllib.parse import parse_qs, unquote_plus, urlsplit


def web_attack_signals(uri):
    """Recognize clear request payloads; these prove attempts, not outcomes."""
    decoded = unquote_plus(uri).lower()
    signals = set()
    if "../" in decoded.replace("\\", "/"):
        signals.add("path_traversal")
    if re.search(r"\bunion\s*\(?\s*select\b", decoded):
        signals.add("sql_injection")
    if re.search(r"<\s*script\b", decoded):
        signals.add("xss_payload")
    if "xss_payload" not in signals:
        for values in parse_qs(urlsplit(uri).query).values():
            for value in values:
                if not 8 <= len(value) <= 4096:
                    continue
                try:
                    payload = base64.b64decode(value.replace(" ", "+") + "===", validate=False).decode("utf-8", "ignore")
                except (ValueError, UnicodeError, binascii.Error):
                    continue
                if re.search(r"<\s*script\b", payload, re.IGNORECASE):
                    signals.add("xss_payload")
                    return signals
    return signals


def classify_case(requests, flagged_count, beaconing, checkin_pattern=False,
                  peer_destinations=0, transport_scheme="http"):
    """Return (possible attack/pattern, suggested mitigation) for one case."""
    duration = max(r["timestamp"] for r in requests) - min(r["timestamp"] for r in requests)
    rate = len(requests) / max(duration, 1)
    paths = {r["uri"].split("?", 1)[0] for r in requests}

    observed = set().union(*(web_attack_signals(r["uri"]) for r in requests))
    if "path_traversal" in observed:
        return (
            "Directory traversal attempt",
            "Restrict file access to the approved directory; check what the server returned.",
        )
    if "sql_injection" in observed:
        return (
            "SQL injection attempt",
            "Use parameterized queries; inspect the server response and database logs.",
        )
    if "xss_payload" in observed:
        return (
            "Cross-site scripting (XSS) attempt",
            "Encode untrusted output; check whether the payload appeared in the response.",
        )

    if checkin_pattern and peer_destinations >= 3:
        return (
            "Command-and-control check-in pattern",
            "Isolate the source; block confirmed C2 destinations.",
        )
    if checkin_pattern:
        return (
            "Repeated C2-style check-ins",
            "Inspect the POSTs; block a confirmed C2 destination.",
        )

    if len(requests) >= 100 and flagged_count >= 20 and duration <= 30 and rate >= 10:
        return (
            f"Attempted {transport_scheme.upper()} denial-of-service (DoS) flood",
            "Rate-limit the endpoint; verify normal requests still work.",
        )
    if beaconing and flagged_count >= 3:
        return (
            "Possible automated check-ins",
            "Investigate the host; block confirmed C2 traffic.",
        )
    if beaconing:
        return (
            "Periodic client polling",
            "Check whether this is an expected update before blocking.",
        )
    if flagged_count >= 5 and len(paths) >= 3:
        return (
            "Possible scripted probing",
            "Review server logs; fix exposed paths and rate-limit abuse.",
        )
    if flagged_count >= 3:
        if any(path.lower().endswith((".exe", ".dll", ".ps1")) for path in paths):
            return (
                "Executable retrieval for review",
                "Check the file hash safely; block only if confirmed harmful.",
            )
        return (
            "Scripted HTTP request pattern",
            "Review source and server logs; restrict if unwanted.",
        )
    return (
        "Unusual HTTP request",
        "Inspect the packet and context before acting.",
    )
