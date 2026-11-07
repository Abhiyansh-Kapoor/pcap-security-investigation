"""Check Windows capture prerequisites after the Python packages are installed."""
import sys

from pcap_parser import find_tshark
from live_demo import loopback_interface

tshark = find_tshark()
if not tshark:
    print("TShark not found. Install Wireshark with its TShark component:")
    print("https://www.wireshark.org/download.html")
    sys.exit(1)
print(f"TShark: {tshark}")

try:
    loopback = loopback_interface(tshark)
except Exception as error:
    print(f"Npcap loopback capture not ready: {error}")
    print("Install Npcap from https://npcap.com/ and enable loopback support.")
    sys.exit(1)
print(f"Npcap loopback: {loopback}")
print("Capture setup is ready.")
