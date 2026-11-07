# Published captures used for the real-data report

These third-party packet captures are not redistributed in this repository. Put the files below in this folder before running `REAL_DATA.cmd`. The program checks each file's SHA-256 and stops if it differs.

| Local filename | Publisher | Source | SHA-256 |
|---|---|---|---|
| `real_formbook_2026.pcap` | Malware-Traffic-Analysis.net | https://malware-traffic-analysis.net/2026/08/09/index.html | `0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170` |
| `published_web_attack.pcap` | CodePath | https://github.com/codepath/opencyber-snort-lab/blob/main/docker/files/pcaps/web-attack.pcap | `dcfb4d00f3f0d92dde816e8c7cdf3590a09cdc5cb026a1ac518d8e0dbe2aa8bc` |
| `published_sql_injection.pcap` | IDS-Benchmark-pcaps | https://github.com/Trepverterless/IDS-Benchmark-pcaps/blob/main/SQL_Injection/PbootCMS_entrance.php.pcap | `40b6bf93a8906ab570a7e0872302e7e7df3f194de8717f4478d72ea3943e5bcc` |
| `published_xss.pcap` | IDS-Benchmark-pcaps | https://github.com/Trepverterless/IDS-Benchmark-pcaps/blob/main/XSS/EyouCms_Uploadimgnew%5BCVE-2024-22927%5D%5BCNNVD-202402-070%5D.pcap | `321d641e8d550b015f15658187b366573b3122a6fdf707664384a92173c53b91` |

The published-capture HTML page is a saved investigation snapshot. It combines four selected cases from these files. To inspect its frame numbers in Wireshark, obtain the matching PCAP and open the named file; frame numbers restart in every PCAP.