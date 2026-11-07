"""Analyse the independent browsing PCAP published by Wireshark SampleCaptures."""
import argparse
import hashlib
import subprocess
import sys
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAPTURE = HERE / "pcaps" / "public_http_browsing.pcap"
REPORT = HERE / "output" / "report_public_http_browsing.html"
EXPECTED_SHA256 = "b562d12dbd1b5b5fc0e7af67a0185d0c537dcbc7d5d82c7a3f30f7ec60ab0d0d"
SOURCE_URL = "https://wiki.wireshark.org/SampleCaptures"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if not CAPTURE.is_file() or hashlib.sha256(CAPTURE.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise SystemExit("The published sample capture is missing or changed. Do not label it as verified source data.")
    print(f"Published source: {SOURCE_URL}", flush=True)
    print("Original file: http_with_jpegs.cap.gz (decompressed to the PCAP in this folder)", flush=True)
    subprocess.run(
        [sys.executable, "main.py", str(CAPTURE), "--report", str(REPORT)],
        cwd=HERE, check=True,
    )
    if not args.no_browser:
        webbrowser.open(REPORT.as_uri())


if __name__ == "__main__":
    main()
