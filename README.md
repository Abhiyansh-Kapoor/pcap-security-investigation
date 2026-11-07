# PCAP Security Investigation

Information Security Lab mini project, Group 9. The Python program reads saved network captures, scores HTTP requests, groups related requests into review cases, stores the results in SQLite, and produces HTML reports with Wireshark frame numbers.

- [Published capture investigation](https://abhiyansh-kapoor.github.io/pcap-security-investigation/report_real_data.html)
- [Local HTTPS capture report](https://abhiyansh-kapoor.github.io/pcap-security-investigation/report_https_lab_capture.html)
- [Final paper](https://abhiyansh-kapoor.github.io/pcap-security-investigation/final-report.pdf)

The website contains saved reports. GitHub Pages cannot run the Python capture or analysis. To generate a fresh local HTTPS capture on Windows, install Python 3, Wireshark/TShark, and Npcap with loopback support; run `SETUP.cmd`, then `HTTPS_RESPONSE_LAB.cmd`. The local demo creates 137 test requests and verifies five cases. `REAL_DATA.cmd` needs the four separately published captures listed in `pcap_investigator/pcaps/SOURCES.md`.

The two generated Scapy fixtures, `normal_browsing.pcap` and `infected_host.pcap`, and their labels are included for controlled tests. Run `python -m unittest discover -s tests` from `pcap_investigator` to run the case guidance tests. The generated captures are for testing; their performance numbers are not a field accuracy estimate.

The mitigation column provides investigation advice. The program does not block traffic. The local HTTPS capture is a controlled test; its TLS secrets are saved in the local PCAPNG so Wireshark can decode it. The flood is one-source DoS test traffic, not DDoS or a demonstrated outage.

## Contributors

- Abhiyansh Kapoor: case report and local HTTPS capture.
- Saniya Taneja: published traffic analysis, request checks, and repeated-pattern analysis.
- Tanvi Kavi: report UI, SQLite storage, generated test traffic, and tests.