"""
Builds CONTROLLED test captures with known ground truth (Scapy).
Each HTTP request is a full TCP conversation (handshake, request, response,
FIN) so Wireshark and tshark dissect it exactly like real traffic.

  pcaps/normal_browsing.pcap  - 3 users browsing, an AJAX poller, one curl call
  pcaps/infected_host.pcap    - same office + one infected PC (4 malware behaviours)

Ground truth (which destinations are malicious) is written to pcaps/labels.json.
Usage:  python tools/make_test_pcaps.py
"""
import json
import os
import random

from scapy.all import Ether, IP, TCP, Raw, wrpcap

random.seed(9)
OUT = os.path.join(os.path.dirname(__file__), "..", "pcaps")
START = 1760000000.0  # fixed epoch so runs are reproducible

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
SERVER_IPS = {}


def server_ip(host):
    if host.replace(".", "").isdigit():
        return host
    if host not in SERVER_IPS:
        SERVER_IPS[host] = f"93.{random.randint(10, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
    return SERVER_IPS[host]


def conversation(t, src, host, request: bytes):
    """Return packets for one HTTP request/response over a fresh TCP connection."""
    dst = server_ip(host)
    sport, seq, ack = random.randint(49152, 65000), random.randint(1, 2**31), random.randint(1, 2**31)
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nOK"
    e = Ether(src="00:0c:29:aa:bb:cc", dst="00:50:56:11:22:33")
    pk = [
        e / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="S", seq=seq),
        e / IP(src=dst, dst=src) / TCP(sport=80, dport=sport, flags="SA", seq=ack, ack=seq + 1),
        e / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="A", seq=seq + 1, ack=ack + 1),
        e / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA", seq=seq + 1, ack=ack + 1) / Raw(request),
        e / IP(src=dst, dst=src) / TCP(sport=80, dport=sport, flags="PA", seq=ack + 1,
                                     ack=seq + 1 + len(request)) / Raw(resp),
        e / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="FA", seq=seq + 1 + len(request),
                                     ack=ack + 1 + len(resp)),
    ]
    for i, p in enumerate(pk):
        p.time = t + i * 0.01
    return pk


def http(method, uri, version, headers, body=b""):
    lines = [f"{method} {uri} {version}"] + [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


# ---------------- benign behaviour ----------------
SITES = {
    "www.wikipedia.org": ["/", "/wiki/Network_security", "/static/style.css", "/static/logo.png"],
    "news.example.com": ["/", "/world/article-2241", "/assets/app.js", "/img/hero.jpg"],
    "docs.python.org": ["/3/", "/3/library/sqlite3.html", "/_static/pydoctheme.css"],
    "www.manipal.edu": ["/", "/mit.html", "/content/dam/logo.svg"],
    "stackoverflow.example.org": ["/questions/1234", "/questions/9876", "/cdn/stack.js"],
}


def browser_request(host, uri, ua, first_page):
    h = [("Host", host), ("User-Agent", ua),
         ("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
         ("Accept-Language", "en-IN,en;q=0.9"), ("Accept-Encoding", "gzip, deflate"),
         ("Connection", "keep-alive")]
    if not first_page:
        h.append(("Referer", f"http://{host}/"))
    if random.random() < 0.5:
        h.append(("Cookie", f"session={random.getrandbits(64):x}"))
    return http("GET", uri, "HTTP/1.1", h)


def benign_user(src, ua, t0, duration):
    pkts, t = [], t0
    while t < t0 + duration:
        host = random.choice(list(SITES))
        for n, uri in enumerate(SITES[host]):
            pkts += conversation(t, src, host, browser_request(host, uri, ua, n == 0))
            t += random.uniform(0.05, 0.8)
        t += random.expovariate(1 / 45)       # human think time
    return pkts


def ajax_poller(src, t0, duration):
    """Benign but periodic: a web mail tab polling every 30 s (full browser headers)."""
    pkts, t = [], t0
    while t < t0 + duration:
        req = http("GET", "/mail/api/poll?unread=1", "HTTP/1.1", [
            ("Host", "mail.example.com"), ("User-Agent", CHROME), ("Accept", "application/json"),
            ("Accept-Language", "en-IN,en;q=0.9"), ("Accept-Encoding", "gzip, deflate"),
            ("Referer", "http://mail.example.com/inbox"), ("X-Requested-With", "XMLHttpRequest")])
        pkts += conversation(t, src, "mail.example.com", req)
        t += random.uniform(29.5, 30.5)
    return pkts


def admin_curl(src, t):
    """Benign one-off: an admin checking an internal API with curl."""
    req = http("GET", "/health", "HTTP/1.1",
               [("Host", "10.0.0.20"), ("User-Agent", "curl/8.5.0"), ("Accept", "*/*")])
    return conversation(t, src, "10.0.0.20", req)


# ---------------- malicious behaviour ----------------
def c2_beacon(src, t0, n=20, interval=60.0):
    """Classic RAT beacon: HTTP/1.0 POST to raw IP, old MSIE UA, encrypted body."""
    pkts, t = [], t0
    for _ in range(n):
        body = os.urandom(512)
        req = http("POST", "/gate.php", "HTTP/1.0", [
            ("Host", "185.234.72.19"),
            ("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"),
            ("Content-Length", str(len(body)))], body)
        pkts += conversation(t, src, "185.234.72.19", req)
        t += interval * random.uniform(0.97, 1.03)
    return pkts


def stealthy_beacon(src, t0, n=15, interval=120.0):
    """Stealthy C2 that copies browser headers - only the missing Referer gives it away
    per request, so the paper's per-request rules miss it."""
    pkts, t = [], t0
    for _ in range(n):
        req = http("GET", f"/api/v2/update?id={random.getrandbits(32):08x}", "HTTP/1.1", [
            ("Host", "cdn-update-check.net"), ("User-Agent", CHROME),
            ("Accept", "text/html,*/*"), ("Accept-Language", "en-US,en;q=0.9"),
            ("Accept-Encoding", "gzip, deflate"), ("Connection", "keep-alive")])
        pkts += conversation(t, src, "cdn-update-check.net", req)
        t += interval * random.uniform(0.95, 1.05)
    return pkts


def downloader(src, t0):
    """Dropper fetching a second-stage payload, retrying 3 times."""
    pkts = []
    for k in range(3):
        req = http("GET", "/files/invoice_2026.exe", "HTTP/1.1",
                   [("Host", "91.215.85.40"), ("User-Agent", "WinHTTP"), ("Connection", "close")])
        pkts += conversation(t0 + k * 5, src, "91.215.85.40", req)
    return pkts


def exfiltration(src, t0):
    """Data theft: binary, high-entropy upload via a Python script."""
    pkts = []
    for k in range(2):
        body = os.urandom(2048)
        req = http("POST", "/upload", "HTTP/1.1", [
            ("Host", "45.137.21.9"), ("User-Agent", "python-requests/2.31.0"),
            ("Content-Type", "application/octet-stream"), ("Content-Length", str(len(body)))], body)
        pkts += conversation(t0 + k * 240, src, "45.137.21.9", req)
    return pkts


def office_traffic(duration):
    return (benign_user("192.168.1.11", CHROME, START, duration)
            + benign_user("192.168.1.12", FIREFOX, START + 7, duration)
            + benign_user("192.168.1.13", CHROME, START + 15, duration)
            + ajax_poller("192.168.1.12", START + 3, duration)
            + admin_curl("192.168.1.13", START + 400))


def write(name, pkts):
    pkts.sort(key=lambda p: p.time)
    wrpcap(os.path.join(OUT, name), pkts)
    print(f"wrote pcaps/{name}: {len(pkts)} packets")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    DUR = 1800  # 30 minutes
    write("normal_browsing.pcap", office_traffic(DUR))

    infected = "192.168.1.50"
    write("infected_host.pcap", office_traffic(DUR)
          + benign_user(infected, CHROME, START + 20, DUR)
          + downloader(infected, START + 60)
          + c2_beacon(infected, START + 90)
          + stealthy_beacon(infected, START + 130)
          + exfiltration(infected, START + 900))

    labels = {
        "malicious_destinations": ["185.234.72.19", "cdn-update-check.net", "91.215.85.40", "45.137.21.9"],
        "description": {
            "185.234.72.19": "C2 beacon (HTTP/1.0 POST, encrypted body, every 60s)",
            "cdn-update-check.net": "Stealthy C2 beacon with browser-like headers (every 120s)",
            "91.215.85.40": "Second-stage .exe downloader (3 retries)",
            "45.137.21.9": "High-entropy data exfiltration",
        },
    }
    with open(os.path.join(OUT, "labels.json"), "w") as fh:
        json.dump(labels, fh, indent=2)
    print("wrote pcaps/labels.json")
