"""Build a readable, evidence-first HTML report for one packet capture."""

import datetime as dt
import hashlib
import html
from collections import Counter
from pathlib import Path

from case_guidance import web_attack_signals
from detector import INDICATOR_TEXT, SCORE_THRESHOLD


FORMBOOK_PAGE = "https://malware-traffic-analysis.net/2026/08/09/index.html"
FORMBOOK_SHA256 = "0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170"
PUBLIC_SAMPLE_PAGE = "https://wiki.wireshark.org/SampleCaptures"
WEB_ATTACK_PAGE = "https://github.com/codepath/opencyber-snort-lab/blob/main/docker/files/pcaps/web-attack.pcap"
BENCHMARK_PAGE = "https://github.com/Trepverterless/IDS-Benchmark-pcaps"
SQL_PAGE = BENCHMARK_PAGE + "/blob/main/SQL_Injection/PbootCMS_entrance.php.pcap"
XSS_PAGE = BENCHMARK_PAGE + "/blob/main/XSS/EyouCms_Uploadimgnew%5BCVE-2024-22927%5D%5BCNNVD-202402-070%5D.pcap"

CSS = """
:root{--ink:#182934;--muted:#61717b;--line:#d3dce0;--soft:#f4f7f7;--accent:#13645f}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#fff;color:var(--ink);font:14px/1.48 Arial,Helvetica,sans-serif}
main{max-width:1390px;margin:auto;padding:30px 36px 65px;border-top:5px solid #183c48}
.eyebrow{color:#426675;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
h1{margin:8px 0 5px;font-size:32px;line-height:1.15;letter-spacing:-.025em}h2{margin:0;font-size:20px;line-height:1.2}
.subtitle{margin:0 0 18px;color:#526674;font-size:15px}.meta{display:flex;flex-wrap:wrap;gap:8px 24px;padding:11px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line);font-size:12px;color:#526674}
.meta b{color:var(--ink)}.meta a{color:var(--accent)}.mono,code{font-family:Consolas,"Courier New",monospace;font-size:.96em}.wrap{overflow-wrap:anywhere}
.report-nav{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:15px}.report-nav b{margin-right:8px;color:#58717a;font-size:10px;letter-spacing:.06em;text-transform:uppercase}.report-nav a{padding:6px 9px;border:1px solid #cbd8da;color:#315a60;font-size:11px;text-decoration:none}.report-nav a:hover,.report-nav a.active{border-color:#276b64;background:#eaf3ef;color:#164a45}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);margin:22px 0 32px;border-bottom:1px solid var(--line)}.metric{padding:0 15px 17px 0;margin-right:15px;border-right:1px solid #e4e9eb}.metric:last-child{border-right:0}.metric strong{display:block;font-size:27px;line-height:1.2;font-variant-numeric:tabular-nums}.metric span{display:block;margin-top:3px;color:#5c6f79;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
section{margin-top:32px}.section-head{display:flex;align-items:baseline;gap:12px;padding-bottom:9px;border-bottom:1px solid #9eafb7}.section-no{color:#6b8088;font:12px Consolas,monospace}.section-desc{margin:9px 0 14px;color:#5b6d77;font-size:12px}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12px}th{padding:9px 9px;border-bottom:1px solid #9dabb2;color:#50636d;font-size:10px;letter-spacing:.05em;text-align:left;text-transform:uppercase;white-space:nowrap}td{padding:11px 9px;border-bottom:1px solid #e1e7e9;vertical-align:top}tr:hover td{background:#f8faf9}
.case-table{min-width:1100px}.request-table{min-width:1000px}.case-table td:nth-child(2){min-width:180px}.case-table td:nth-child(4){min-width:220px}.case-table td:nth-child(5){min-width:150px}.case-table td:nth-child(6){min-width:175px}
.minor{color:var(--muted);font-size:11px}.block{display:block;margin-top:3px}.severity{font-size:11px;font-weight:700;letter-spacing:.04em}.severity.HIGH{color:#a43b32}.severity.MEDIUM{color:#8a5e1e}.severity.LOW{color:#536f7c}.risk{display:block;margin-top:3px;font-size:11px;color:var(--muted)}
.reason-list{margin:0;padding-left:16px}.reason-list li+li{margin-top:4px}.attack{font-weight:700}.address{overflow-wrap:anywhere}.signal{display:inline-block;margin:1px 4px 4px 0;padding:2px 5px;border:1px solid #d8e1e4;color:#405763;font-size:10px}.method{font-weight:700;color:#175a57}.frame{font-weight:700;color:var(--accent)}
.indicator-kind{color:#53747a;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}.fold{margin-top:12px;border:1px solid var(--line)}.fold summary{padding:11px 13px;color:var(--accent);font-weight:700;cursor:pointer}.fold[open] summary{border-bottom:1px solid var(--line)}.fold .table-wrap{padding:0 12px 12px}
.frame-list{display:block;margin:8px 0 0;max-height:190px;overflow:auto;line-height:1.75;word-break:break-word}.frame-details summary{color:var(--accent);cursor:pointer;font-weight:700}.frame-details[open]{min-width:170px}
.empty{padding:13px;border:1px solid var(--line);color:var(--muted)}.source{padding:12px 14px;border-left:3px solid #5a9185;background:var(--soft)}.source p{margin:4px 0}.source a{color:var(--accent)}.footer{margin-top:38px;padding-top:13px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}
@media(max-width:760px){main{padding:20px 16px 48px}h1{font-size:27px}.metrics{grid-template-columns:repeat(2,1fr);row-gap:14px}.metric:nth-child(2){border-right:0}}
@media print{main{max-width:none;padding:0}.table-wrap{overflow:visible}.case-table,.request-table{min-width:0}table{font-size:10px}tr{break-inside:avoid}}
"""


def _ts(value):
    return dt.datetime.fromtimestamp(value).strftime("%d %b %Y, %H:%M:%S")


def _source(pcap_file):
    name = Path(pcap_file).name
    if name == "real_formbook_2026.pcap" and Path(pcap_file).is_file():
        if hashlib.sha256(Path(pcap_file).read_bytes()).hexdigest() == FORMBOOK_SHA256:
            return "Published FormBook traffic capture", FORMBOOK_PAGE, (
                "Recorded by Malware-Traffic-Analysis.net. The publisher identifies FormBook C2 activity. "
                "The analysis below is based on the packets in this file."
            )
    if name == "published_web_attack.pcap":
        return "Published web-attack lab capture", WEB_ATTACK_PAGE, (
            "Captured HTTP requests from the CodePath security lab. One request uses ../ to reach "
            "/etc/passwd; its HTTP 200 response contains the file's contents."
        )
    if name == "published_sql_injection.pcap":
        return "Published SQL injection test capture", SQL_PAGE, (
            "A PbootCMS SQL injection test PCAP from the IDS-Benchmark-pcaps collection. "
            "The request carries a UNION SELECT payload; the capture alone does not establish a successful exploit."
        )
    if name == "published_xss.pcap":
        return "Published XSS test capture", XSS_PAGE, (
            "An EyouCMS XSS test PCAP from the IDS-Benchmark-pcaps collection. "
            "A query value decodes to a script payload; the capture alone does not show it executed."
        )
    if name.startswith("https_lab_") and name.endswith(".pcapng"):
        return "Local HTTPS capture", None, (
            "This laptop sent harmless flood, traversal, SQL injection, XSS, and check-in test requests "
            "to one server at 127.0.0.1:8443. The different .localhost Host labels separate the scenarios; "
            "Npcap captured them and embedded TLS session keys let Wireshark decode the requests."
        )
    if name == "public_http_browsing.pcap":
        return "Published normal browsing capture", PUBLIC_SAMPLE_PAGE, (
            "A historical browsing capture from Wireshark's sample collection."
        )
    if name in {"infected_host.pcap", "normal_browsing.pcap"}:
        return "Generated test capture", None, (
            "Created with Scapy by tools/make_test_pcaps.py. Expected labels are in pcaps/labels.json."
        )
    return "Imported capture", None, "Inspect the cited frames in Wireshark before making a conclusion."


def _url(request, https):
    uri = request["uri"] or "/"
    if uri.startswith(("http://", "https://")):
        return uri
    host = request["host"] or request["dst_ip"]
    if https and request["dst_port"] != 443 and ":" not in host:
        host += f":{request['dst_port']}"
    return ("https://" if https else "http://") + host + (uri if uri.startswith("/") else "/" + uri)


def _request_row(request, https):
    e = html.escape
    url = _url(request, https)
    attack_signal_text = {
        "path_traversal": "Path traversal path",
        "sql_injection": "UNION SELECT query",
        "xss_payload": "Encoded script payload",
    }
    observed = web_attack_signals(request["uri"])
    signals = "".join(
        f"<span class='signal'>{e(label)}</span>"
        for name, label in attack_signal_text.items() if name in observed
    )
    signals += "".join(f"<span class='signal'>{e(INDICATOR_TEXT[name])}</span>" for name in request["indicators"])
    if not signals:
        signals = "<span class='minor'>Matched repeated behavior</span>"
    return (
        "<tr>"
        f"<td class='mono frame'>{request['frame']}</td>"
        f"<td><span class='method'>{e(request['method'])}</span> "
        f"<span class='mono address'>{e(url)}</span>"
        f"<span class='block minor'>{e(request['user_agent'] or 'No User-Agent')} · "
        f"{request['payload_len']:,} body bytes</span></td>"
        f"<td class='mono'>{e(request['src_ip'])}</td>"
        f"<td>{request['score']}</td><td>{signals}</td>"
        "</tr>"
    )


def build_report(path, pcap_file, requests, incidents):
    e = html.escape
    https = Path(pcap_file).name.startswith("https_lab_")
    kind, source_url, source_note = _source(pcap_file)
    formbook = source_url == FORMBOOK_PAGE
    flagged = [request for request in requests if request["paper_flag"]]
    by_frame = {request["frame"]: request for request in requests}
    pattern_cases = [case for case in incidents if case.get("checkin_pattern")]
    pattern_frames = {frame for case in pattern_cases for frame in case["frames"]}
    pattern_requests = [request for request in requests if request["frame"] in pattern_frames]
    linked_frames = {frame for case in incidents for frame in case["frames"]}
    case_requests = [request for request in requests if request["frame"] in linked_frames]
    web_hits = {
        name: [request for request in requests if name in web_attack_signals(request["uri"])]
        for name in ("path_traversal", "sql_injection", "xss_payload")
    }
    high_count = sum(case["severity"] == "HIGH" for case in incidents)
    header_counts = Counter(name for request in requests for name in request["indicators"])
    source_count = len({request["src_ip"] for request in requests})

    navigation = [
        ("Real data", "report_real_data.html"),
        ("Local HTTPS", "report_https_lab_capture.html"),
    ]
    nav_html = "<nav class='report-nav' aria-label='Demo reports'><b>Demo reports</b>" + "".join(
        f"<a class='{'active' if Path(path).name == filename else ''}' href='{e(filename)}'>{e(label)}</a>"
        for label, filename in navigation
        if (Path(path).parent / filename).is_file() or Path(path).name == filename
    ) + "</nav>"

    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>{'HTTPS' if https else 'PCAP'} security investigation</title>",
        f"<style>{CSS}</style></head><body><main>",
        "<header><div class='eyebrow'>Group 9 / Information Security Lab</div>",
        f"<h1>{'HTTPS' if https else 'PCAP'} security investigation</h1>",
        nav_html,
        "</header>",
        "<div class='metrics'>",
        f"<div class='metric'><strong>{len(requests):,}</strong><span>{'HTTPS' if https else 'HTTP'} requests</span></div>",
        f"<div class='metric'><strong>{source_count:,}</strong><span>Source computers</span></div>",
        f"<div class='metric'><strong>{len(incidents):,}</strong><span>Cases · {high_count} high</span></div>",
        f"<div class='metric'><strong>{len(case_requests) if https else (len(pattern_requests) if pattern_requests else len(case_requests)):,}</strong><span>Requests linked to cases</span></div>",
        "</div>",
        "<section id='cases'><div class='section-head'><span class='section-no'>01</span><h2>Cases to review</h2></div>",
    ]

    if incidents:
        out.extend([
            "<div class='table-wrap'><table class='case-table'><thead><tr>",
            f"<th>Priority</th><th>{'Source / HTTP Host' if https else 'Source / destination'}</th><th>Requests and time</th>",
            "<th>Why this case was raised</th><th>Attack type</th><th>Mitigation technique</th><th>Wireshark frames</th>",
            "</tr></thead><tbody>",
        ])
        for case in incidents:
            linked = [by_frame[frame] for frame in case["frames"] if frame in by_frame]
            posts = sum(request["method"] == "POST" for request in linked)
            gets = sum(request["method"] == "GET" for request in linked)
            if formbook and case.get("checkin_pattern"):
                attack = "FormBook C2 communication"
            elif formbook:
                attack = "Update-like header anomaly"
            elif kind == "Published web-attack lab capture" and case["possible_attack"] == "Directory traversal attempt":
                attack = "Successful directory traversal"
            elif https and case.get("checkin_pattern"):
                attack = "Simulated C2-style HTTPS check-ins"
            else:
                attack = case["possible_attack"]
            mitigation = (
                "Review the source and destination; block only if similar activity is confirmed malicious."
                if https and case.get("checkin_pattern") else case["mitigation"]
            )
            evidence_frames = [frame for frame in case["frames"] if frame in by_frame]
            frame_preview = ", ".join(str(frame) for frame in evidence_frames[:5])
            frame_list = ", ".join(str(frame) for frame in evidence_frames)
            if https and len(evidence_frames) >= 100:
                flagged_times = [by_frame[frame]["timestamp"] for frame in evidence_frames]
                burst_seconds = max(flagged_times) - min(flagged_times)
                case_reasons = [
                    f"{len(evidence_frames)} POSTs to {case['top_uri']} in {burst_seconds:.2f} seconds",
                    "Burst sent from one source to the local HTTPS test server",
                ]
            else:
                case_reasons = case["reasons"]
            reasons = "".join(f"<li>{e(reason)}</li>" for reason in case_reasons)
            out.append(
                "<tr>"
                f"<td><span class='severity {e(case['severity'])}'>{e(case['severity'])}</span>"
                f"<span class='risk'>Risk {case['risk']}</span></td>"
                f"<td><span class='mono'>{e(case['src_ip'])}</span>"
                f"<span class='block mono wrap'>→ {e(case['destination'])}</span>"
                f"<span class='block minor mono wrap'>{e(case['top_uri'])}</span></td>"
                f"<td><b>{case['request_count']}</b> requests"
                + (f"<span class='block minor'>{posts} POST · {gets} GET</span>" if posts and gets else "")
                + f"<span class='block minor'>{_ts(case['first_seen'])}</span>"
                f"<span class='block minor'>to {_ts(case['last_seen'])}</span></td>"
                f"<td><ul class='reason-list'>{reasons}</ul></td>"
                f"<td><span class='attack'>{e(attack)}</span></td>"
                f"<td>{e(mitigation)}</td>"
                f"<td class='mono wrap'>{e(frame_preview)}"
                f"<details class='frame-details'><summary>Show all {len(evidence_frames)} frames</summary>"
                f"<code class='frame-list'>{e(frame_list)}</code></details></td>"
                "</tr>"
            )
        out.append("</tbody></table></div>")
    else:
        out.append("<p class='empty'>No cases were raised in this capture.</p>")
    out.append("</section>")

    behavior = []
    flood_cases = [case for case in incidents if "denial-of-service" in case["possible_attack"]] if https else []
    if flood_cases:
        flood_requests = [by_frame[frame] for frame in flood_cases[0]["frames"] if frame in by_frame]
        burst_seconds = max(request["timestamp"] for request in flood_requests) - min(request["timestamp"] for request in flood_requests)
        behavior.extend([
            (f"Rapid POST burst within {burst_seconds:.2f} seconds", sum(request["method"] == "POST" for request in flood_requests), "requests"),
            ("Repeated POSTs to /gate.php", sum(request["uri"].split("?", 1)[0] == "/gate.php" for request in flood_requests), "requests"),
        ])
    if pattern_requests:
        destinations = len({request["host"] or request["dst_ip"] for request in pattern_requests})
        body_posts = sum(request["method"] == "POST" and request["payload_len"] >= 100 for request in pattern_requests)
        long_gets = sum(request["method"] == "GET" and "?" in request["uri"] and len(request["uri"].split("?", 1)[1]) >= 80 for request in pattern_requests)
        body_sizes = len({request["payload_len"] for request in pattern_requests if request["method"] == "POST" and request["payload_len"] >= 100})
        if https:
            behavior.extend([
                ("Repeated check-in sequence", len(pattern_requests), "requests"),
                ("Check-in POSTs carrying a body", body_posts, "requests"),
                ("Long-query check-in GETs", long_gets, "requests"),
            ])
        else:
            behavior.extend([
                ("Same POST/GET pattern across destinations", destinations, "destinations"),
                ("POST requests carrying a body", body_posts, "requests"),
                ("GET requests with long query strings", long_gets, "requests"),
                ("Recurring POST body sizes", body_sizes, "sizes"),
            ])
    for name, label in (
        ("path_traversal", "Path traversal sequence in requested file path"),
        ("sql_injection", "UNION SELECT injection payload in query"),
        ("xss_payload", "Script payload in request parameter"),
    ):
        if web_hits[name]:
            behavior.append((label, len(web_hits[name]), "requests"))
    out.extend([
        "<section id='indicators'><div class='section-head'><span class='section-no'>02</span><h2>Indicators observed</h2></div>",
    ])
    if behavior or header_counts:
        out.append("<div class='table-wrap'><table><thead><tr><th>Type</th><th>Observed indicator</th><th>Count</th></tr></thead><tbody>")
        for label, count, unit in behavior:
            out.append(f"<tr><td class='indicator-kind'>Behavior</td><td>{e(label)}</td><td class='mono'>{count:,} {e(unit)}</td></tr>")
        for name, count in header_counts.most_common():
            out.append(f"<tr><td class='indicator-kind'>Header</td><td>{e(INDICATOR_TEXT[name])}</td><td class='mono'>{count:,} requests</td></tr>")
        out.append("</tbody></table></div>")
    else:
        out.append("<p class='empty'>No unusual request details were observed.</p>")
    out.append("</section>")

    signature_requests = [
        request for request in requests
        if any(request in matches for matches in web_hits.values())
    ]
    if https:
        first_frames = {case["frames"][0] for case in incidents if case["frames"]}
        leads = [request for request in case_requests if request["frame"] in first_frames]
        leads.extend(request for request in case_requests if request["frame"] not in first_frames)
    else:
        leads = pattern_requests if pattern_requests else (signature_requests if signature_requests else (flagged if flagged else case_requests))
    out.extend([
        f"<section id='requests'><div class='section-head'><span class='section-no'>03</span><h2>{'All ' + str(len(leads)) + ' case-linked HTTPS requests' if https else 'Suspicious requests to inspect'}</h2></div>",
    ])
    if leads:
        out.append("<div class='table-wrap'><table class='request-table'><thead><tr><th>Frame</th><th>Request</th><th>Source</th><th>Score</th><th>Signals</th></tr></thead><tbody>")
        for request in leads[:24]:
            out.append(_request_row(request, https))
        out.append("</tbody></table></div>")
        if len(leads) > 24:
            out.append(f"<details class='fold'><summary>Show remaining {len(leads) - 24} requests</summary><div class='table-wrap'><table class='request-table'><thead><tr><th>Frame</th><th>Request</th><th>Source</th><th>Score</th><th>Signals</th></tr></thead><tbody>")
            for request in leads[24:]:
                out.append(_request_row(request, https))
            out.append("</tbody></table></div></details>")
    else:
        out.append("<p class='empty'>No request reached the rule threshold.</p>")
    if flagged and pattern_requests and not https:
        out.append(
            f"<p class='section-desc'>{len(flagged)} request met the separate header-score threshold of {SCORE_THRESHOLD}; "
            "the repeated-behavior cases above come from correlation across packets.</p>"
        )
    out.append("</section>")

    out.extend([
        "<section id='source'><div class='section-head'><span class='section-no'>04</span><h2>Capture sources</h2></div>",
        "<div class='source'>",
        f"<p><b>{e(kind)}</b> — {e(source_note)}</p>",
        f"<p>Local packet file: <code class='wrap'>{e(str(pcap_file))}</code></p>",
        *([f"<p>Original publisher: <a href='{e(source_url, quote=True)}'>{e(source_url)}</a></p>"] if source_url else []),
        "</div></section>",
        "</main></body></html>",
    ])
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(out), encoding="utf-8")


def build_real_report(path, analyses):
    """One investigation page for published captures with distinct, sourced cases."""
    e = html.escape
    by_name = {Path(item["pcap"]).name: item for item in analyses}
    formbook = by_name["real_formbook_2026.pcap"]
    traversal = by_name["published_web_attack.pcap"]
    sql = by_name["published_sql_injection.pcap"]
    xss = by_name["published_xss.pcap"]

    patterns = [case for case in formbook["incidents"] if case.get("checkin_pattern")]
    pattern_frames = sorted({frame for case in patterns for frame in case["frames"]})
    formbook_requests = {r["frame"]: r for r in formbook["requests"]}
    pattern_requests = [formbook_requests[frame] for frame in pattern_frames if frame in formbook_requests]
    destinations = len({r["host"] or r["dst_ip"] for r in pattern_requests})
    posts = sum(r["method"] == "POST" and r["payload_len"] >= 100 for r in pattern_requests)
    long_gets = sum(r["method"] == "GET" and "?" in r["uri"] and len(r["uri"].split("?", 1)[1]) >= 80 for r in pattern_requests)

    traversal_req = next(r for r in traversal["requests"] if "path_traversal" in web_attack_signals(r["uri"]))
    sql_req = next(r for r in sql["requests"] if "sql_injection" in web_attack_signals(r["uri"]))
    xss_req = next(r for r in xss["requests"] if "xss_payload" in web_attack_signals(r["uri"]))
    sample_post = max((r for r in pattern_requests if r["method"] == "POST"), key=lambda r: r["payload_len"])
    sample_get = next(r for r in pattern_requests if r["method"] == "GET" and "?" in r["uri"])

    cases = [
        {
            "file": "real_formbook_2026.pcap", "source": "Published malware capture",
            "scope": f"{destinations} destinations · {len(pattern_frames)} requests",
            "attack": "FormBook command-and-control (C2) activity",
            "reasons": [f"{posts} body-bearing POSTs and {long_gets} long-query GETs",
                        f"Same sequence from 172.16.8.49 across {destinations} hosts"],
            "mitigation": "Investigate and isolate the source; block verified C2 destinations.",
            "frames": pattern_frames,
        },
        {
            "file": "published_web_attack.pcap", "source": "Published lab capture",
            "scope": "1 attack request · response frame 76",
            "attack": "Successful directory traversal",
            "reasons": ["Frame 74 requests /../../../etc/passwd",
                        "Frame 76 returns HTTP 200 and the file contents"],
            "mitigation": "Restrict file paths to the approved directory; review access logs.",
            "frames": [traversal_req["frame"], 76],
        },
        {
            "file": "published_sql_injection.pcap", "source": "Published IDS test capture",
            "scope": "1 crafted request",
            "attack": "SQL injection attempt",
            "reasons": ["URL query contains a UNION SELECT payload", "The packet shows an attempt; success is not established"],
            "mitigation": "Use parameterized queries; inspect the response and database logs.",
            "frames": [sql_req["frame"]],
        },
        {
            "file": "published_xss.pcap", "source": "Published IDS test capture",
            "scope": "1 crafted request",
            "attack": "Cross-site scripting (XSS) attempt",
            "reasons": ["A query value decodes to a script tag", "The packet does not show script execution"],
            "mitigation": "Encode untrusted output; check whether the script appeared in a response.",
            "frames": [xss_req["frame"]],
        },
    ]
    total_requests = sum(len(item["requests"]) for item in analyses)
    evidence_frames = sum(len(case["frames"]) for case in cases)

    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Real-data security investigation</title>",
        f"<style>{CSS}</style></head><body><main>",
        "<header><div class='eyebrow'>Group 9 / Information Security Lab</div>",
        "<h1>Real-data security investigation</h1>",
        "<nav class='report-nav' aria-label='Demo reports'><b>Demo reports</b>"
        "<a class='active' href='report_real_data.html'>Real data</a>"
        "<a href='report_https_lab_capture.html'>Local HTTPS</a></nav></header>",
        "<div class='metrics'>",
        f"<div class='metric'><strong>{len(analyses)}</strong><span>Published captures</span></div>",
        f"<div class='metric'><strong>{total_requests}</strong><span>HTTP requests examined</span></div>",
        f"<div class='metric'><strong>{len(cases)}</strong><span>Evidence-backed attack types</span></div>",
        f"<div class='metric'><strong>{evidence_frames}</strong><span>Frames listed in cases</span></div>",
        "</div>",
        "<section id='cases'><div class='section-head'><span class='section-no'>01</span><h2>Cases to review</h2></div>",
        "<div class='table-wrap'><table class='case-table'><thead><tr><th>Priority</th><th>Capture and scope</th>"
        "<th>Evidence</th><th>Attack type</th><th>Mitigation technique</th><th>Wireshark frames</th>"
        "</tr></thead><tbody>",
    ]
    for case in cases:
        reasons = "".join(f"<li>{e(reason)}</li>" for reason in case["reasons"])
        preview = ", ".join(str(frame) for frame in case["frames"][:5])
        full = ", ".join(str(frame) for frame in case["frames"])
        frame_details = (
            f"<details class='frame-details'><summary>Show all {len(case['frames'])} frames</summary>"
            f"<code class='frame-list'>{e(full)}</code></details>"
            if len(case["frames"]) > 5 else ""
        )
        out.append(
            "<tr><td><span class='severity HIGH'>HIGH</span></td>"
            f"<td><b class='mono wrap'>{e(case['file'])}</b>"
            f"<span class='block minor'>{e(case['source'])}</span>"
            f"<span class='block minor'>{e(case['scope'])}</span></td>"
            f"<td><ul class='reason-list'>{reasons}</ul></td>"
            f"<td><span class='attack'>{e(case['attack'])}</span></td>"
            f"<td>{e(case['mitigation'])}</td>"
            f"<td class='mono wrap'>{e(preview)}{frame_details}</td></tr>"
        )
    out.extend([
        "</tbody></table></div></section>",
        "<section id='indicators'><div class='section-head'><span class='section-no'>02</span><h2>Indicators observed</h2></div>",
        "<div class='table-wrap'><table><thead><tr><th>Capture</th><th>Observed indicator</th><th>Count</th></tr></thead><tbody>",
    ])
    indicators = [
        ("FormBook", "Matching C2 destinations", destinations, "hosts"),
        ("FormBook", "POST requests carrying a body", posts, "requests"),
        ("FormBook", "Long-query GET requests", long_gets, "requests"),
        ("Directory traversal", "../ path escaping the web directory", 1, "request"),
        ("SQL injection", "UNION SELECT query payload", 1, "request"),
        ("XSS", "Base64 query value containing a script tag", 1, "request"),
    ]
    for capture, indicator, count, unit in indicators:
        out.append(f"<tr><td class='indicator-kind'>{e(capture)}</td><td>{e(indicator)}</td><td class='mono'>{count} {e(unit)}</td></tr>")
    out.extend([
        "</tbody></table></div></section>",
        f"<section id='requests'><div class='section-head'><span class='section-no'>03</span><h2>All {evidence_frames} case evidence frames</h2></div>",
        "<div class='table-wrap'><table class='request-table'><thead><tr><th>Capture</th><th>Frame</th><th>Packet / request</th><th>Why inspect it</th></tr></thead><tbody>",
    ])
    examples = [
        ("real_formbook_2026.pcap", sample_post, "Large POST in the repeated C2 sequence"),
        ("real_formbook_2026.pcap", sample_get, "Long-query GET in the same sequence"),
        ("published_web_attack.pcap", traversal_req, "Traversal request; response is frame 76"),
        ("published_sql_injection.pcap", sql_req, "UNION SELECT in the URL"),
        ("published_xss.pcap", xss_req, "Encoded script payload in the query"),
    ]
    for filename, request, reason in examples:
        out.append(
            f"<tr><td class='mono'>{e(filename)}</td><td class='mono frame'>{request['frame']}</td>"
            f"<td class='mono address'>{e(request['method'])} {e(_url(request, False))}</td>"
            f"<td>{e(reason)}</td></tr>"
        )
    out.append(
        "<tr><td class='mono'>published_web_attack.pcap</td><td class='mono frame'>76</td>"
        "<td class='mono address'>HTTP 200 response with /etc/passwd contents</td>"
        "<td>Confirms the traversal returned the requested file</td></tr>"
    )
    example_frames = {sample_post["frame"], sample_get["frame"]}
    remaining = [request for request in pattern_requests if request["frame"] not in example_frames]
    out.extend([
        "</tbody></table></div>",
        f"<details class='fold'><summary>Show remaining {len(remaining)} case frames — all {evidence_frames} are included</summary>",
        "<div class='table-wrap'><table class='request-table'><thead><tr><th>Capture</th><th>Frame</th><th>Packet / request</th><th>Why inspect it</th></tr></thead><tbody>",
    ])
    for request in remaining:
        reason = "POST body in the repeated C2 sequence" if request["method"] == "POST" else "Long-query GET in the repeated C2 sequence"
        out.append(
            f"<tr><td class='mono'>real_formbook_2026.pcap</td><td class='mono frame'>{request['frame']}</td>"
            f"<td class='mono address'>{e(request['method'])} {e(_url(request, False))}</td>"
            f"<td>{e(reason)}</td></tr>"
        )
    out.extend([
        "</tbody></table></div></details></section>",
        "<section id='source'><div class='section-head'><span class='section-no'>04</span><h2>Capture sources</h2></div>",
        "<div class='source'>",
    ])
    for item in analyses:
        kind, source_url, note = _source(item["pcap"])
        out.append(
            f"<p><b>{e(Path(item['pcap']).name)}</b> — {e(kind)}. {e(note)} "
            + (f"<a href='{e(source_url, quote=True)}'>Publisher ↗</a>" if source_url else "")
            + "</p>"
        )
    out.extend([
        "</div></section>",
        "</main></body></html>",
    ])
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(out), encoding="utf-8")
