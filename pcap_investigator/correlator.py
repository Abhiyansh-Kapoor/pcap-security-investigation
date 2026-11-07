"""
Module 4 - Behaviour Correlation and Improvement Module  (our improvement)

The paper scores every request on its own. Malware, however, rarely sends
one request - it beacons to its C2 server again and again. We group requests
by (source IP, destination host) and look at behaviour over time:

  * repetition  - how many suspicious requests the same source sent there
  * beaconing   - are the gaps between requests unusually regular?
  * same URI    - is the same path hit repeatedly (check-in / gate URL)?

This lets us (a) catch stealthy requests whose single requests look almost normal
"""
import statistics
from collections import defaultdict

from case_guidance import classify_case, web_attack_signals

MIN_REQUESTS_FOR_BEACON = 4
BEACON_MAX_CV = 0.25           # coefficient of variation of gaps (std/mean)
REPEAT_SUSPICIOUS_MIN = 3

BONUS_REPEATED = 2
BONUS_BEACON = 3
BONUS_SAME_URI = 1

SEVERITY_HIGH = 7
SEVERITY_MEDIUM = 5


def _beacon_stats(timestamps):
    ts = sorted(timestamps)
    if len(ts) < MIN_REQUESTS_FOR_BEACON:
        return False, None, None
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]   # ignore bursts
    if len(gaps) < MIN_REQUESTS_FOR_BEACON - 1:
        return False, None, None
    mean = statistics.mean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean else 99
    return cv <= BEACON_MAX_CV, round(mean, 1), round(cv, 3)


def _checkin_pattern(reqs):
    """Repeated body-bearing POSTs plus a long-query GET to one endpoint.

    This combination can indicate a scripted check-in, but is not by itself
    proof that the remote host is malicious.
    """
    if len(reqs) < 6:
        return False
    paths = [r["uri"].split("?", 1)[0] for r in reqs]
    main_path = max(set(paths), key=paths.count)
    if paths.count(main_path) < 0.75 * len(reqs):
        return False
    posts = sum(r["method"] == "POST" and r["payload_len"] >= 100 for r in reqs)
    query_gets = sum(r["method"] == "GET" and len(r["uri"].split("?", 1)[-1]) >= 80
                     and "?" in r["uri"] for r in reqs)
    return posts >= 4 and query_gets >= 1


def correlate(requests, transport_scheme="http"):
    """requests: list of dicts with src_ip, host/dst_ip, timestamp, uri, score.
    Returns a list of incident dicts sorted by risk (highest first)."""
    groups = defaultdict(list)
    for r in requests:
        dest = r["host"] or r["dst_ip"]
        groups[(r["src_ip"], dest)].append(r)

    pattern_destinations = defaultdict(set)
    for (src, dest), reqs in groups.items():
        if _checkin_pattern(reqs):
            pattern_destinations[src].add(dest)

    incidents = []
    for (src, dest), reqs in groups.items():
        scores = [r["score"] for r in reqs]
        flagged = [r for r in reqs if r["paper_flag"]]
        beacon, interval, cv = _beacon_stats([r["timestamp"] for r in reqs])
        avg_score = sum(scores) / len(scores)
        checkin_pattern = _checkin_pattern(reqs)
        web_hits = {
            name: [r for r in reqs if name in web_attack_signals(r["uri"])]
            for name in ("path_traversal", "sql_injection", "xss_payload")
        }
        peer_destinations = len(pattern_destinations[src])

        uri_counts = defaultdict(int)
        for r in reqs:
            uri_counts[r["uri"].split("?")[0]] += 1
        top_uri, top_uri_n = max(uri_counts.items(), key=lambda kv: kv[1])
        same_uri = top_uri_n >= REPEAT_SUSPICIOUS_MIN and top_uri_n / len(reqs) >= 0.8

        reasons, risk = [], max(scores)
        if len(flagged) >= REPEAT_SUSPICIOUS_MIN:
            risk += BONUS_REPEATED
            reasons.append(f"{len(flagged)} anomalous requests from same source")
        if beacon and avg_score >= 1:
            risk += BONUS_BEACON
            reasons.append(f"Beaconing: every ~{interval}s (gap variation {cv})")
        if same_uri and avg_score >= 1:
            risk += BONUS_SAME_URI
            reasons.append(f"Same URI repeated {top_uri_n}x: {top_uri}")
        duration = max(r["timestamp"] for r in reqs) - min(r["timestamp"] for r in reqs)
        if len(reqs) >= 100 and len(flagged) >= 20 and duration <= 30 and len(reqs) / max(duration, 1) >= 10:
            risk += 2
            reasons.append(f"High-rate burst: {len(reqs)} requests in {duration:.2f}s")
        if checkin_pattern:
            risk += 3
            reasons.append("Repeated body-bearing POSTs and long-query GETs to one endpoint")
            if peer_destinations >= 3:
                risk += 3
                reasons.append(f"Matching request pattern across {peer_destinations} destinations")
        for name, label in (
            ("path_traversal", "Path traversal path targets a file outside the web directory"),
            ("sql_injection", "UNION SELECT payload in the URL query"),
            ("xss_payload", "Query value decodes to a script tag"),
        ):
            if web_hits[name]:
                risk += 7
                reasons.append(f"{label} in {len(web_hits[name])} request(s): frame {web_hits[name][0]['frame']}")

        # only keep groups that show at least some suspicion
        if not flagged and not (beacon and avg_score >= 1) and not checkin_pattern and not any(web_hits.values()):
            continue

        severity = "HIGH" if risk >= SEVERITY_HIGH else "MEDIUM" if risk >= SEVERITY_MEDIUM else "LOW"
        possible_attack, mitigation = classify_case(
            reqs, len(flagged), beacon, checkin_pattern, peer_destinations,
            transport_scheme=transport_scheme)
        incidents.append({
            "src_ip": src,
            "destination": dest,
            "request_count": len(reqs),
            "flagged_count": len(flagged),
            "max_score": max(scores),
            "avg_score": round(avg_score, 2),
            "beaconing": beacon,
            "beacon_interval": interval,
            "beacon_cv": cv,
            "checkin_pattern": checkin_pattern,
            "peer_destinations": peer_destinations,
            "top_uri": top_uri,
            "first_seen": min(r["timestamp"] for r in reqs),
            "last_seen": max(r["timestamp"] for r in reqs),
            "risk": risk,
            "severity": severity,
            "possible_attack": possible_attack,
            "mitigation": mitigation,
            "reasons": reasons or [f"{len(flagged)} anomalous request(s), no repeated/periodic behaviour"],
            "frames": [r["frame"] for r in reqs],
        })
    return sorted(incidents, key=lambda i: (-i["risk"], -i["flagged_count"]))
