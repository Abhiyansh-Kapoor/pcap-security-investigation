"""Build one sourced investigation report from four published packet captures."""
import argparse
import hashlib
import webbrowser
from pathlib import Path

from main import analyse
from report import build_real_report
from storage import save_results

HERE = Path(__file__).resolve().parent
CAPTURE = HERE / "pcaps" / "real_formbook_2026.pcap"
REPORT = HERE / "output" / "report_real_data.html"
EXPECTED_SHA256 = "0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170"
SOURCE_URL = "https://malware-traffic-analysis.net/2026/08/09/index.html"
WEB_CAPTURE = HERE / "pcaps" / "published_web_attack.pcap"
WEB_SHA256 = "dcfb4d00f3f0d92dde816e8c7cdf3590a09cdc5cb026a1ac518d8e0dbe2aa8bc"
WEB_SOURCE_URL = "https://github.com/codepath/opencyber-snort-lab/blob/main/docker/files/pcaps/web-attack.pcap"
SQL_CAPTURE = HERE / "pcaps" / "published_sql_injection.pcap"
SQL_SHA256 = "40b6bf93a8906ab570a7e0872302e7e7df3f194de8717f4478d72ea3943e5bcc"
SQL_SOURCE_URL = "https://github.com/Trepverterless/IDS-Benchmark-pcaps/blob/main/SQL_Injection/PbootCMS_entrance.php.pcap"
XSS_CAPTURE = HERE / "pcaps" / "published_xss.pcap"
XSS_SHA256 = "321d641e8d550b015f15658187b366573b3122a6fdf707664384a92173c53b91"
XSS_SOURCE_URL = "https://github.com/Trepverterless/IDS-Benchmark-pcaps/blob/main/XSS/EyouCms_Uploadimgnew%5BCVE-2024-22927%5D%5BCNNVD-202402-070%5D.pcap"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    sources = [
        (CAPTURE, EXPECTED_SHA256, SOURCE_URL),
        (WEB_CAPTURE, WEB_SHA256, WEB_SOURCE_URL),
        (SQL_CAPTURE, SQL_SHA256, SQL_SOURCE_URL),
        (XSS_CAPTURE, XSS_SHA256, XSS_SOURCE_URL),
    ]
    analyses = []
    for capture, expected_hash, source_url in sources:
        if not capture.is_file() or hashlib.sha256(capture.read_bytes()).hexdigest() != expected_hash:
            raise SystemExit(f"Published capture missing or changed: {capture.name}")
        print(f"Published source: {source_url}", flush=True)
        requests, incidents = analyse(capture)
        save_results(HERE / "output" / "results.db", str(capture), requests, incidents)
        analyses.append({"pcap": capture, "requests": requests, "incidents": incidents})
        print(f"  {len(requests)} requests, {len(incidents)} correlated cases", flush=True)
    build_real_report(REPORT, analyses)
    print(f"Real-data report: {REPORT}")
    if not args.no_browser:
        webbrowser.open(REPORT.as_uri())


if __name__ == "__main__":
    main()
