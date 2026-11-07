"""
ONE-CLICK DEMO (for PyCharm: right-click this file -> Run 'run_demo')

Does everything in order:
  1. checks that Wireshark/tshark is installed
  2. creates the test PCAPs (if not already there)
  3. analyses both captures (modules 1-5)
  4. runs the paper-vs-improved comparison
  5. opens the HTML report in your browser
"""
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

from pcap_parser import find_tshark

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)                      # so relative paths work however PyCharm runs it
sys.path.insert(0, HERE)


def check_packages():
    missing = []
    for mod in ("pyshark", "scapy", "matplotlib"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        print(f"[!] Missing packages: {', '.join(missing)} - installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])


def check_tshark():
    path = find_tshark()
    if path:
        print(f"[+] tshark found: {path}")
        return
    print("\n[X] tshark NOT found. Install Wireshark from https://www.wireshark.org/download.html")
    print("    (on Windows keep the 'TShark' option ticked), then run this file again.")
    sys.exit(1)


def run(script, *args):
    print(f"\n{'=' * 70}\n>>> python {script} {' '.join(args)}\n{'=' * 70}")
    subprocess.check_call([sys.executable, script, *args])


if __name__ == "__main__":
    check_packages()
    check_tshark()
    if not os.path.exists(os.path.join("pcaps", "infected_host.pcap")):
        run(os.path.join("tools", "make_test_pcaps.py"))
    run("main.py", os.path.join("pcaps", "normal_browsing.pcap"))
    run("main.py", os.path.join("pcaps", "infected_host.pcap"))
    run("compare.py")
    report = os.path.join(HERE, "output", "report_infected_host.html")
    print(f"\n[+] Opening report: {report}")
    if "--no-browser" not in sys.argv:
        webbrowser.open(Path(report).as_uri())
