"""
Module 5a - Database Module
Stores every analysed request and every correlated incident in SQLite so
results can be queried later (e.g. with DB Browser for SQLite).
"""
import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file     TEXT,
    analysed_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    total_requests INTEGER,
    paper_alerts  INTEGER,
    incidents     INTEGER
);
CREATE TABLE IF NOT EXISTS http_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER REFERENCES analysis_runs(run_id),
    frame         INTEGER,
    timestamp     REAL,
    src_ip        TEXT, dst_ip TEXT, dst_port INTEGER,
    method        TEXT, uri TEXT, http_version TEXT,
    host          TEXT, user_agent TEXT, referer TEXT,
    header_count  INTEGER,
    payload_len   INTEGER, payload_entropy REAL, non_ascii_ratio REAL,
    score         INTEGER,
    indicators    TEXT,          -- JSON list
    paper_flag    INTEGER        -- 1 = anomalous by paper rules
);
CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER REFERENCES analysis_runs(run_id),
    src_ip        TEXT, destination TEXT,
    request_count INTEGER, flagged_count INTEGER,
    max_score     INTEGER, avg_score REAL,
    beaconing     INTEGER, beacon_interval REAL,
    first_seen    REAL, last_seen REAL,
    risk          INTEGER, severity TEXT,
    possible_attack TEXT, mitigation TEXT,
    reasons       TEXT,          -- JSON list
    frames        TEXT           -- JSON list of Wireshark frame numbers
);
"""


def save_results(db_path, pcap_file, requests, incidents):
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    # Existing demo databases predate the two review columns.
    existing = {row[1] for row in con.execute("PRAGMA table_info(incidents)")}
    for column in ("possible_attack", "mitigation"):
        if column not in existing:
            con.execute(f"ALTER TABLE incidents ADD COLUMN {column} TEXT")
    cur = con.execute(
        "INSERT INTO analysis_runs (pcap_file, total_requests, paper_alerts, incidents) VALUES (?,?,?,?)",
        (pcap_file, len(requests), sum(r["paper_flag"] for r in requests), len(incidents)))
    run_id = cur.lastrowid
    con.executemany(
        """INSERT INTO http_requests (run_id, frame, timestamp, src_ip, dst_ip, dst_port, method, uri,
           http_version, host, user_agent, referer, header_count, payload_len, payload_entropy,
           non_ascii_ratio, score, indicators, paper_flag) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [(run_id, r["frame"], r["timestamp"], r["src_ip"], r["dst_ip"], r["dst_port"], r["method"],
          r["uri"], r["http_version"], r["host"], r["user_agent"], r["referer"], r["header_count"],
          r["payload_len"], r["payload_entropy"], r["non_ascii_ratio"], r["score"],
          json.dumps(r["indicators"]), int(r["paper_flag"])) for r in requests])
    con.executemany(
        """INSERT INTO incidents (run_id, src_ip, destination, request_count, flagged_count, max_score,
           avg_score, beaconing, beacon_interval, first_seen, last_seen, risk, severity,
           possible_attack, mitigation, reasons, frames)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [(run_id, i["src_ip"], i["destination"], i["request_count"], i["flagged_count"], i["max_score"],
          i["avg_score"], int(i["beaconing"]), i["beacon_interval"], i["first_seen"], i["last_seen"],
          i["risk"], i["severity"], i["possible_attack"], i["mitigation"],
          json.dumps(i["reasons"]), json.dumps(i["frames"])) for i in incidents])
    con.commit()
    con.close()
    return run_id
