"""Capture real local HTTP requests with Npcap and analyse the new PCAPNGs.

Only a local test server is contacted. The script-like requests are harmless
examples for showing the detector; no malware is run.
"""
import argparse
import datetime
import os
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pcap_parser import find_tshark

HERE = Path(__file__).resolve().parent
PORT = 80  # Wireshark decodes this as HTTP without extra configuration.


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.respond()

    def respond(self):
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def loopback_interface(tshark):
    result = subprocess.run([tshark, "-D"], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        match = re.match(r"^\d+\. (\S*NPF_Loopback)\b", line)
        if match:
            return match.group(1)
    raise RuntimeError("Npcap loopback capture is unavailable. Check the Npcap installation.")


def send_request(request):
    with socket.create_connection(("127.0.0.1", PORT), timeout=5) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        while connection.recv(4096):
            pass


def capture(tshark, interface, filename, requests):
    target = HERE / "pcaps" / filename
    target.parent.mkdir(exist_ok=True)
    if target.exists():
        try:
            target.unlink()
        except PermissionError:
            # Wireshark can hold an earlier capture open on Windows.
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target = target.with_name(f"{target.stem}_{stamp}_{os.getpid()}{target.suffix}")
            print(f"  Previous {filename} is open; saving this capture as {target.name}", flush=True)
    command = [tshark, "-i", interface, "-f", f"tcp port {PORT}",
               "-a", "duration:7", "-w", str(target)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    time.sleep(1.5)  # Give the capture driver time to begin before sending packets.
    if process.poll() is not None:
        _stdout, stderr = process.communicate()
        raise RuntimeError(f"TShark could not start: {stderr.decode(errors='replace')}")
    for number, request in enumerate(requests, 1):
        print(f"  Sending request {number}/{len(requests)}: "
              f"{request.split(b'\r\n', 1)[0].decode()}", flush=True)
        send_request(request)
        if number < len(requests):
            time.sleep(0.8)
    _stdout, stderr = process.communicate(timeout=20)
    if process.returncode != 0 or not target.is_file():
        raise RuntimeError(f"TShark capture failed: {stderr.decode(errors='replace')}")
    print(f"  Captured packets in {target.name}", flush=True)
    return target


def analyse(pcap, report):
    subprocess.run([sys.executable, "main.py", str(pcap), "--report", str(report)],
                   cwd=HERE, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--auto", action="store_true", help="Skip Enter prompts for testing")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("TShark was not found.")
    interface = loopback_interface(tshark)
    try:
        server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    except OSError as error:
        raise RuntimeError(f"Cannot start local HTTP server on port {PORT}: {error}") from error
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    browser_headers = (
        b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36\r\n"
        b"Accept: text/html\r\nAccept-Language: en-US,en;q=0.9\r\n"
        b"Accept-Encoding: gzip, deflate\r\nReferer: http://127.0.0.1/\r\n"
        b"Connection: close\r\n\r\n"
    )
    script_headers = (
        b"POST /gate.php HTTP/1.0\r\nHost: 127.0.0.1\r\n"
        b"User-Agent: curl/8.5.0\r\nContent-Length: 4\r\n\r\nDEMO"
    )

    try:
        print("LIVE LOCAL REQUEST DEMO. No malware or external site is involved.", flush=True)
        if not args.auto:
            input("\nPress Enter to send and capture ONE normal-looking request...")
        normal = capture(tshark, interface, "live_normal.pcapng", [browser_headers])
        analyse(normal, HERE / "output" / "report_live_normal.html")

        if not args.auto:
            input("\nPress Enter to send and capture THREE unusual requests...")
        unusual = capture(tshark, interface, "live_unusual.pcapng", [script_headers] * 3)
        report = HERE / "output" / "report_live_unusual.html"
        analyse(unusual, report)
        print(f"\nOpen the new report, then inspect {unusual} in Wireshark.", flush=True)
        if not args.no_browser:
            webbrowser.open(report.as_uri())
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
