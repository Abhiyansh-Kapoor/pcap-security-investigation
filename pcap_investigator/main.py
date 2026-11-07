"""
Python-Based PCAP Security Investigation and Threat Detection System
Information Security Lab - Group 9

Usage:
    python main.py <capture.pcap> [--db output/results.db] [--report output/report.html]
"""
import argparse
import os
import time
from pathlib import Path

from pcap_parser import extract_http_requests
from features import extract_features
from detector import score_request, is_anomalous, INDICATOR_TEXT
from correlator import correlate
from storage import save_results
from report import build_report


def analyse(pcap_path):
    """Run modules 1-4 and return (requests, incidents)."""
    requests = []
    for req in extract_http_requests(pcap_path):                 # Module 1
        f = extract_features(req)                                 # Module 2
        score, hits = score_request(f)                            # Module 3
        requests.append({
            **{k: req[k] for k in ("frame", "timestamp", "src_ip", "dst_ip", "dst_port", "method", "uri")},
            "http_version": f["http_version"], "host": f["host"], "user_agent": f["user_agent"],
            "referer": f["referer"], "header_count": f["header_count"], "payload_len": f["payload_len"],
            "payload_entropy": f["payload_entropy"], "non_ascii_ratio": f["non_ascii_ratio"],
            "score": score, "indicators": hits, "paper_flag": is_anomalous(score),
        })
    scheme = "https" if Path(pcap_path).name.startswith("https_lab_") else "http"
    incidents = correlate(requests, transport_scheme=scheme)      # Module 4
    return requests, incidents


def main():
    ap = argparse.ArgumentParser(description="PCAP HTTP threat detection")
    ap.add_argument("pcap")
    ap.add_argument("--db", default="output/results.db")
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    name = os.path.splitext(os.path.basename(args.pcap))[0]
    report_path = args.report or f"output/report_{name}.html"
    os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.db) or ".", exist_ok=True)

    t0 = time.time()
    print(f"[*] Analysing {args.pcap} ...")
    requests, incidents = analyse(args.pcap)
    flagged = [r for r in requests if r["paper_flag"]]
    transport_label = "HTTPS requests decoded" if name.startswith("https_lab_") else "HTTP requests extracted"
    print(f"[+] {transport_label:24}: {len(requests)}")
    print(f"[+] Feature-rule alerts     : {len(flagged)}")
    print(f"[+] Correlated incidents    : {len(incidents)}")

    for i in incidents:
        print(f"    [{i['severity']:6}] risk={i['risk']:2}  {i['src_ip']} -> {i['destination']}"
              f"  ({i['request_count']} reqs, {i['flagged_count']} flagged)")
        for reason in i["reasons"]:
            print(f"             - {reason}")

    run_id = save_results(args.db, args.pcap, requests, incidents)      # Module 5
    build_report(report_path, args.pcap, requests, incidents)
    print(f"[+] Saved to SQLite         : {args.db} (run_id={run_id})")
    print(f"[+] HTML report             : {report_path}")
    print(f"[+] Done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
