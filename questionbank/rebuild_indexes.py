"""Rebuild the metadata-only CSV/SQLite locally; Python standard library only."""
import csv
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"


def main():
    rows = [json.loads(line) for line in (DATA / "challenges.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    if len({row["id"] for row in rows}) != len(rows): raise ValueError("duplicate record id")
    columns = ["id", "name", "category", "difficulty", "source_id", "year", "content_type", "split", "practice_readiness", "full_prompt_available", "alias_of", "family_key", "source_url"]
    with (DATA / "challenges.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns); writer.writeheader()
        for row in rows:
            values = {key: row.get(key, "") for key in columns}
            for key, value in values.items():
                if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"): values[key] = "'" + value
            writer.writerow(values)
    temporary = DATA / "questionbank.build.sqlite"
    if temporary.exists(): temporary.unlink()
    try:
        with sqlite3.connect(temporary) as connection:
            connection.execute("CREATE TABLE challenges (id TEXT PRIMARY KEY,name TEXT,category TEXT,difficulty TEXT,source_id TEXT,split TEXT,content_type TEXT,family_key TEXT,alias_of TEXT,payload_json TEXT)")
            connection.executemany("INSERT INTO challenges VALUES (?,?,?,?,?,?,?,?,?,?)", [(row["id"], row["name"], row["category"], row["difficulty"], row["source_id"], row["split"], row["content_type"], row["family_key"], row.get("alias_of"), json.dumps(row, ensure_ascii=False)) for row in rows])
            connection.execute("CREATE INDEX idx_selection ON challenges(category,split,content_type)")
            connection.execute("CREATE VIRTUAL TABLE search USING fts5(id UNINDEXED,name,description,tags)")
            connection.executemany("INSERT INTO search VALUES (?,?,?,?)", [(row["id"], row["name"], row["description"], " ".join(row["tags"])) for row in rows])
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok": raise ValueError("SQLite integrity check failed")
        temporary.replace(DATA / "questionbank.sqlite")
    finally:
        if temporary.exists(): temporary.unlink()
    print(json.dumps({"records": len(rows), "csv": "data/challenges.csv", "sqlite": "data/questionbank.sqlite", "integrity": "ok"}))


if __name__ == "__main__": main()
