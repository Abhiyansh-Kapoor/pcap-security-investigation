import sqlite3
import tempfile
import unittest
import base64
from contextlib import closing
from pathlib import Path

from case_guidance import classify_case, web_attack_signals
from correlator import correlate
from storage import SCHEMA, save_results


def requests(count, uri="/gate.php", spacing=1):
    return [{"timestamp": i * spacing, "uri": uri} for i in range(count)]


class CaseGuidanceTests(unittest.TestCase):
    def test_three_requests_are_not_called_ddos(self):
        label, advice = classify_case(requests(3), flagged_count=3, beaconing=False)
        self.assertEqual(label, "Scripted HTTP request pattern")
        self.assertIn("restrict if unwanted", advice)

    def test_unflagged_beacon_is_not_called_attack(self):
        label, advice = classify_case(requests(15, spacing=120), flagged_count=0, beaconing=True)
        self.assertEqual(label, "Periodic client polling")
        self.assertIn("expected update", advice)

    def test_flood_requires_volume_and_rate(self):
        label, _ = classify_case(requests(120, spacing=0.1), flagged_count=50, beaconing=False)
        self.assertEqual(label, "Attempted HTTP denial-of-service (DoS) flood")
        label, _ = classify_case(requests(120, spacing=10), flagged_count=50, beaconing=False)
        self.assertNotIn("flood", label.lower())

    def test_cross_destination_checkins_create_behavior_cases(self):
        traffic = []
        for host_index in range(3):
            host = f"test{host_index}.example"
            for index in range(6):
                is_get = index == 5
                traffic.append({
                    "src_ip": "192.0.2.10", "dst_ip": "198.51.100.1", "host": host,
                    "timestamp": host_index * 20 + index * 0.1,
                    "method": "GET" if is_get else "POST",
                    "uri": "/abcd/?token=" + "x" * 90 if is_get else "/abcd/",
                    "payload_len": 0 if is_get else 500,
                    "score": 1 if is_get else 0, "paper_flag": False,
                    "frame": len(traffic) + 1,
                })
        cases = correlate(traffic)
        self.assertEqual(len(cases), 3)
        self.assertTrue(all(case["possible_attack"] == "Command-and-control check-in pattern" for case in cases))
        self.assertTrue(all(case["peer_destinations"] == 3 for case in cases))

    def test_many_plain_gets_do_not_create_checkin_cases(self):
        traffic = [{"src_ip": "192.0.2.10", "dst_ip": "198.51.100.1", "host": "updates.example",
                    "timestamp": index * 0.1, "method": "GET", "uri": f"/file{index}", "payload_len": 0,
                    "score": 0, "paper_flag": False, "frame": index + 1} for index in range(50)]
        self.assertEqual(correlate(traffic), [])

    def test_path_traversal_creates_case_from_captured_request(self):
        traffic = [{"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "host": "localhost:8888",
                    "timestamp": 1.0, "method": "GET", "uri": "/../../../etc/passwd",
                    "payload_len": 0, "score": 0, "paper_flag": False, "frame": 74}]
        cases = correlate(traffic)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["possible_attack"], "Directory traversal attempt")
        self.assertEqual(cases[0]["severity"], "HIGH")
        self.assertEqual(cases[0]["frames"], [74])

    def test_sql_and_encoded_xss_payloads_are_identified_as_attempts(self):
        sql_uri = "/?tag=%7Dsql%3A%7Bfilter%3D1%29UNION%28SELECT%2F%2A%2A%2Fversion%28%29%29"
        xss_uri = "/?info=" + base64.b64encode(b'<ScRiPt >alert(document.domain)</ScRiPt>').decode()
        self.assertIn("sql_injection", web_attack_signals(sql_uri))
        self.assertIn("xss_payload", web_attack_signals(xss_uri))
        for uri, label in ((sql_uri, "SQL injection attempt"), (xss_uri, "Cross-site scripting (XSS) attempt")):
            traffic = [{"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "host": "lab.example",
                        "timestamp": 1.0, "method": "GET", "uri": uri, "payload_len": 0,
                        "score": 0, "paper_flag": False, "frame": 4}]
            cases = correlate(traffic)
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["possible_attack"], label)
            self.assertEqual(cases[0]["severity"], "HIGH")

    def test_existing_database_gets_new_columns(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "old.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(SCHEMA.replace("    possible_attack TEXT, mitigation TEXT,\n", ""))
            save_results(database, "sample.pcap", [], [])
            with closing(sqlite3.connect(database)) as connection:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(incidents)")}
            self.assertTrue({"possible_attack", "mitigation"} <= columns)


if __name__ == "__main__":
    unittest.main()
