"""Show the newest stored analysis without needing a SQLite application."""
import sqlite3
from pathlib import Path

database = Path(__file__).resolve().parent / "output" / "results.db"
with sqlite3.connect(database) as connection:
    run = connection.execute(
        "SELECT run_id, pcap_file, total_requests, paper_alerts, incidents "
        "FROM analysis_runs ORDER BY run_id DESC LIMIT 1"
    ).fetchone()
    if run is None:
        raise SystemExit("No analyses are stored yet. Run the demo first.")
    print(f"Latest run: {run[1]} (run ID {run[0]})")
    print(f"Stored: {run[2]} requests, {run[3]} feature-rule alerts, {run[4]} incidents")
    print("\nSeverity  Source         Destination              Requests  Risk  Possible pattern")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(incidents)")}
    pattern_column = "possible_attack" if "possible_attack" in columns else "NULL AS possible_attack"
    for severity, source, destination, count, risk, possible_attack in connection.execute(
        f"SELECT severity, src_ip, destination, request_count, risk, {pattern_column} "
        "FROM incidents WHERE run_id = ? ORDER BY risk DESC", (run[0],)
    ):
        print(f"{severity:<9} {source:<14} {destination:<24} {count:>8} {risk:>5}  {possible_attack or 'Earlier result'}")
