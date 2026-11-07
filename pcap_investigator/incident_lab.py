"""Capture five harmless local HTTPS attack-pattern scenarios in one run."""

import argparse
import datetime as dt
import ipaddress
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from live_demo import loopback_interface
from main import analyse
from pcap_parser import find_tshark


HERE = Path(__file__).resolve().parent
PORT = 8443
ATTEMPTS = 120
LOCAL_HOSTS = ("flood", "traversal", "sql", "xss", "checkin", "normal")
CAPTURE = HERE / "pcaps" / "https_lab_capture.pcapng"
REPORT = HERE / "output" / "report_https_lab_capture.html"


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.respond()

    def respond(self):
        body = b"LOCAL HTTPS TEST"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def certificate(folder):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            *(x509.DNSName(f"{name}.localhost") for name in LOCAL_HOSTS),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = folder / "lab.crt", folder / "lab.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return cert_path, key_path


def capture_https(tshark, interface, folder):
    keylog = folder / "session.keys"
    raw = folder / "capture_raw.pcapng"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # self-signed certificate for localhost only
    context.keylog_filename = str(keylog)

    CAPTURE.parent.mkdir(exist_ok=True)
    target = CAPTURE
    if target.exists():
        try:
            target.unlink()
        except PermissionError:
            suffix = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            target = CAPTURE.with_name(f"https_lab_capture_{suffix}_{os.getpid()}.pcapng")

    process = subprocess.Popen(
        [tshark, "-i", interface, "-f", f"tcp port {PORT}", "-a", "duration:12", "-w", str(raw)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    time.sleep(1.5)
    if process.poll() is not None:
        _, error = process.communicate()
        raise RuntimeError(f"TShark could not start: {error.decode(errors='replace')}")

    def scripted_request(method, path, host, body=b""):
        return (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}.localhost:{PORT}\r\n"
            "User-Agent: curl/8.5.0\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body

    flood_post = scripted_request("POST", "/gate.php", "flood", b"DEMO")
    traversal_requests = [scripted_request("GET", path, "traversal") for path in (
        "/files/../../../../etc/passwd",
        "/download/../../../windows/win.ini",
        "/view?file=../../../../etc/hosts",
    )]
    sql_requests = [scripted_request("GET", path, "sql") for path in (
        "/search?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "/items?sort=0%20UNION%20SELECT%20NULL,NULL",
        "/account?user=1%20UNION%20SELECT%20email,password%20FROM%20users",
    )]
    xss_requests = [scripted_request("GET", path, "xss") for path in (
        "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/profile?name=%3Cscript%3Ealert(2)%3C%2Fscript%3E",
        "/comment?text=%3Cscript%3Ealert(3)%3C%2Fscript%3E",
    )]
    checkin_body = b"id=demo-client&status=" + b"A" * 120
    checkin_requests = [scripted_request("POST", "/checkin", "checkin", checkin_body) for _ in range(6)]
    checkin_requests.append(scripted_request("GET", "/checkin?token=" + "B" * 96, "checkin"))
    normal_get = (
        f"GET /index.html HTTP/1.1\r\nHost: normal.localhost:{PORT}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36\r\n"
        "Accept: text/html\r\nAccept-Language: en-US,en;q=0.9\r\n"
        "Accept-Encoding: gzip, deflate\r\nReferer: https://normal.localhost:8443/\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    def send(request):
        with socket.create_connection(("127.0.0.1", PORT), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as secure:
                secure.settimeout(8)
                secure.sendall(request)
                response = secure.recv(256)
        return int(response.split(b" ", 2)[1])

    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(send, [flood_post] * ATTEMPTS))
        scenarios = {
            "traversal": traversal_requests,
            "SQL injection": sql_requests,
            "XSS": xss_requests,
            "check-in": checkin_requests,
        }
        scenario_statuses = {name: [send(request) for request in scenario] for name, scenario in scenarios.items()}
        normal_status = send(normal_get)
    finally:
        try:
            _, error = process.communicate(timeout=20)
        finally:
            context.keylog_filename = None  # close the temporary file before Windows removes its folder
        if process.returncode != 0:
            raise RuntimeError(f"TShark capture failed: {error.decode(errors='replace')}")

    if not keylog.is_file() or keylog.stat().st_size == 0:
        raise RuntimeError("TLS keys were not recorded; the HTTPS contents cannot be inspected.")
    editcap = str(Path(tshark).with_name("editcap.exe"))
    subprocess.run(
        [editcap, "--inject-secrets", f"tls,{keylog}", str(raw), str(target)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        [sys.executable, "main.py", str(target), "--report", str(REPORT)],
        cwd=HERE, check=True,
    )
    frame_result = subprocess.run(
        [tshark, "-r", str(target), "-Y", "http.request", "-T", "fields", "-e", "frame.number"],
        check=True, capture_output=True, text=True,
    )
    request_count = len([line for line in frame_result.stdout.splitlines() if line.strip()])
    expected_requests = ATTEMPTS + sum(len(scenario) for scenario in scenarios.values()) + 1
    if request_count != expected_requests:
        raise RuntimeError(f"HTTPS capture decoded {request_count} of {expected_requests} expected requests; rerun the demo.")
    parsed_requests, cases = analyse(target)
    expected_cases = {
        "flood.localhost:8443": (120, "Attempted HTTPS denial-of-service (DoS) flood"),
        "traversal.localhost:8443": (3, "Directory traversal attempt"),
        "sql.localhost:8443": (3, "SQL injection attempt"),
        "xss.localhost:8443": (3, "Cross-site scripting (XSS) attempt"),
        "checkin.localhost:8443": (7, "Repeated C2-style check-ins"),
    }
    observed_cases = {case["destination"]: (case["request_count"], case["possible_attack"]) for case in cases}
    if len(parsed_requests) != expected_requests or observed_cases != expected_cases:
        raise RuntimeError(f"HTTPS case verification failed: {observed_cases}")
    print(f"Captured {request_count} HTTPS requests; flood responses {dict(Counter(statuses))}; "
          f"other scenarios { {name: dict(Counter(values)) for name, values in scenario_statuses.items()} }; "
          f"normal GET {normal_status}; {len(cases)} verified cases", flush=True)
    print(f"Packet capture: {target}", flush=True)
    print(f"Case report: {REPORT}", flush=True)
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    tshark = find_tshark()
    if not tshark:
        raise SystemExit("TShark was not found. Run SETUP.cmd first.")
    if not Path(tshark).with_name("editcap.exe").is_file():
        raise SystemExit("Wireshark editcap.exe is required for the HTTPS capture.")
    interface = loopback_interface(tshark)
    with tempfile.TemporaryDirectory(prefix="isl_https_lab_") as folder_name:
        folder = Path(folder_name)
        cert, key = certificate(folder)
        server = ThreadingHTTPServer(("127.0.0.1", PORT), TargetHandler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            capture_https(tshark, interface, folder)
        finally:
            server.shutdown()
            server.server_close()
    if not args.no_browser:
        webbrowser.open(REPORT.as_uri())


if __name__ == "__main__":
    main()
