"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from datetime import datetime, timezone
from urllib.parse import quote

BASE = Path(__file__).resolve().parents[1]
SOURCES = {
    "awesome-ctf": {"directory": "awesome-ctf", "url": "https://github.com/apsdehal/awesome-ctf",
                    "role": "tool_directory", "license": "CC0-1.0", "reference_only": False},
    "crypto-cat": {"directory": "crypto-cat-ctf", "url": "https://github.com/Crypto-Cat/CTF",
                   "role": "reference_cases", "license": None, "reference_only": True},
}
TEXT_SUFFIXES = {".md", ".py", ".sage", ".txt", ".c", ".cpp", ".h", ".js", ".sh"}


def locations(source):
    if source not in SOURCES:
        raise ValueError("source 必须为 hacktricks、awesome-ctf 或 crypto-cat")
    spec = SOURCES[source]
    return spec, BASE / "references" / spec["directory"], BASE / "references/indexes" / (source + ".sqlite3")


def _git(repo, *args):
    result = subprocess.run(["git", "-c", "core.quotePath=false", "-C", str(repo), *args],
                            capture_output=True, encoding="utf-8", errors="strict", timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Git metadata unavailable")
    return result.stdout.strip()


def _open(index):
    if not index.is_file():
        raise ValueError("参考索引未建立；运行 tools/ctf_reference_sources.py --build --source <source>")
    connection = sqlite3.connect(index.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def _metadata(connection):
    return json.loads(connection.execute("SELECT value FROM metadata WHERE key='build'").fetchone()[0])


def status(source):
    spec, repo, index = locations(source)
    result = {"source": source, "ready": False, "repo_path": str(repo), "index_path": str(index),
              "reference_only": spec["reference_only"], "role": spec["role"], "license": spec["license"]}
    if not index.is_file():
        return result
    try:
        connection = _open(index)
        try:
            result.update(_metadata(connection))
            result["ready"] = connection.execute("SELECT count(*) FROM sections").fetchone()[0] > 0
        finally:
            connection.close()
    except (OSError, ValueError, sqlite3.Error) as exc:
        result["detail"] = str(exc)
    return result


def build(source):
    from ctf_knowledge import _sections
    spec, repo, index = locations(source)
    if not (repo / ".git").exists():
        raise ValueError("参考 Git 仓库尚未拉取：" + str(repo))
    if _git(repo, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("参考仓库有本地修改，不能标注为上游固定提交")
    commit = _git(repo, "rev-parse", "HEAD")
    tracked = _git(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines()
    selected = [p for p in tracked if p == "README.md"] if source == "awesome-ctf" else [
        p for p in tracked if Path(p).suffix.lower() in TEXT_SUFFIXES]
    index.parent.mkdir(parents=True, exist_ok=True)
    temporary = index.with_name(index.name + ".%d.tmp" % os.getpid())
    files, chunks, excluded = 0, 0, []
    connection = None
    try:
        connection = sqlite3.connect(temporary)
        with connection:
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            connection.execute("CREATE TABLE sections(id INTEGER PRIMARY KEY,path TEXT,title TEXT,heading TEXT,start_line INTEGER,end_line INTEGER,file_sha256 TEXT,body TEXT)")
            connection.execute("CREATE VIRTUAL TABLE search USING fts5(path,title,heading,body,content='sections',content_rowid='id',tokenize='unicode61')")
            for relative in sorted(selected):
                path = (repo / relative).resolve()
                try:
                    if not path.is_relative_to(repo.resolve()) or path.stat().st_size > 524288:
                        raise ValueError("outside source or larger than 512 KiB")
                    raw = path.read_bytes()
                    if b"\0" in raw:
                        raise ValueError("binary content")
                    lines = raw.decode("utf-8-sig").splitlines()
                except (OSError, ValueError, UnicodeError) as exc:
                    excluded.append({"path": relative, "reason": str(exc)})
                    continue
                title = next((line.lstrip("# ") for line in lines if line.startswith("# ")), relative)
                digest = hashlib.sha256(raw).hexdigest()
                files += 1
                for first, last, heading, body in _sections(lines):
                    if body.strip():
                        connection.execute("INSERT INTO sections(path,title,heading,start_line,end_line,file_sha256,body) VALUES(?,?,?,?,?,?,?)",
                                           (relative, title, heading, first, last, digest, body))
                        chunks += 1
            if _git(repo, "status", "--porcelain", "--untracked-files=no") or _git(repo, "rev-parse", "HEAD") != commit:
                raise ValueError("参考仓库在建立索引时发生改变")
            meta = {"source": source, "repo_url": spec["url"], "commit": commit,
                    "built_at": datetime.now(timezone.utc).isoformat(), "tracked_files": len(tracked),
                    "selected_files": len(selected), "indexed_files": files, "sections": chunks,
                    "excluded_files": excluded, "role": spec["role"], "license": spec["license"],
                    "reference_only": spec["reference_only"], "trusted_instructions": False,
                    "retrieval": "local_keyword_fts5", "executes_source": False}
            connection.execute("INSERT INTO metadata VALUES('build',?)", (json.dumps(meta, ensure_ascii=False),))
            connection.execute("INSERT INTO search(search) VALUES('rebuild')")
            connection.execute("INSERT INTO search(search) VALUES('integrity-check')")
        connection.close()
        connection = None
        temporary.replace(index)
    finally:
        if connection is not None:
            connection.close()
        temporary.unlink(missing_ok=True)
    return status(source)


def _authorize(args):
    source = args.get("source")
    spec, repo, index = locations(source)
    if spec["reference_only"] and args.get("allow_reference") is not True:
        raise ValueError("Crypto-Cat 含题解/solver，独立解题和测评输入默认隔离；仅查阅参考案例时显式设置 allow_reference=true")
    return source, spec, repo, index


def _citation(row, source, spec, repo, meta):
    return {"source": source, "path": row["path"], "title": row["title"], "heading": row["heading"],
            "start_line": row["start_line"], "end_line": row["end_line"],
            "local_path": str(repo / row["path"]), "file_sha256": row["file_sha256"],
            "commit": meta["commit"], "reference_only": spec["reference_only"],
            "url": spec["url"] + "/blob/" + meta["commit"] + "/" + quote(row["path"], safe="/")
                   + "#L%d-L%d" % (row["start_line"], row["end_line"])}


def search(args):
    from ctf_knowledge import _terms
    source, spec, repo, index = _authorize(args)
    terms, limit = _terms(args["query"]), int(args.get("limit", 5))
    if not 1 <= limit <= 10:
        raise ValueError("limit 必须在 1–10 之间")
    connection = _open(index)
    try:
        meta, mode, rows = _metadata(connection), "all_terms", []
        for operator in (" AND ", " OR "):
            expression = operator.join('"' + term + '"' for term in terms)
            rows = connection.execute("SELECT s.*,snippet(search,3,'[',']',' … ',48) AS excerpt,bm25(search,4,12,8,1) AS rank FROM search JOIN sections s ON s.id=search.rowid WHERE search MATCH ? ORDER BY rank LIMIT ?",
                                      (expression, limit * 10)).fetchall()
            if rows:
                break
            mode = "any_term"
    finally:
        connection.close()
    matches, per_path = [], {}
    for row in rows:
        if per_path.get(row["path"], 0) >= 2:
            continue
        matches.append(dict(_citation(row, source, spec, repo, meta), excerpt=row["excerpt"][:1400], rank=round(row["rank"], 5)))
        per_path[row["path"]] = per_path.get(row["path"], 0) + 1
        if len(matches) >= limit:
            break
    return {"query": args["query"], "source": source, "normalized_terms": terms, "match_mode": mode,
            "count": len(matches), "matches": matches, "trusted_instructions": False,
            "usage": "kb_read 需携带同一 source/path；Crypto-Cat 还需 allow_reference=true。检索命中不代表工具已安装、脚本已运行或答案已验证。"}


def read(args):
    source, spec, repo, index = _authorize(args)
    relative = args["path"]
    if not isinstance(relative, str):
        raise ValueError("path 必须为检索返回的相对路径")
    path = (repo / relative).resolve()
    if not path.is_relative_to(repo.resolve()) or not path.is_file():
        raise ValueError("只允许读取本 source 已收录的文本")
    relative = path.relative_to(repo.resolve()).as_posix()
    first, count = int(args.get("start_line", 1)), int(args.get("lines", 80))
    if first < 1 or not 1 <= count <= 150:
        raise ValueError("start_line ≥1，lines 必须为 1–150")
    connection = _open(index)
    try:
        meta = _metadata(connection)
        row = connection.execute("SELECT * FROM sections WHERE path=? LIMIT 1", (relative,)).fetchone()
        if not row:
            raise ValueError("该文件未收录到文本索引")
    finally:
        connection.close()
    if path.stat().st_size > 524288:
        raise ValueError("原文已改变或超过读取大小限制")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != row["file_sha256"]:
        raise ValueError("原文已改变，请重建对应 source 索引")
    lines = raw.decode("utf-8-sig").splitlines()
    if first > len(lines):
        raise ValueError("start_line 超过页面总行数")
    chosen, size, truncated = [], 0, False
    for number in range(first, min(first + count, len(lines) + 1)):
        line = "%d: %s" % (number, lines[number - 1])
        if chosen and size + len(line) > 16000:
            truncated = True
            break
        truncated = truncated or len(line) > 16000
        chosen.append(line[:16000])
        size += len(chosen[-1]) + 1
    result = _citation(row, source, spec, repo, meta)
    result.update(start_line=first, end_line=first + len(chosen) - 1, total_lines=len(lines), text="\n".join(chosen),
                  more=first + len(chosen) <= len(lines), output_truncated=truncated, trusted_instructions=False)
    result["url"] = spec["url"] + "/blob/" + meta["commit"] + "/" + quote(relative, safe="/") + "#L%d-L%d" % (result["start_line"], result["end_line"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=tuple(SOURCES) + ("all",), default="all")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    sources = tuple(SOURCES) if args.source == "all" else (args.source,)
    result = {source: (build(source) if args.build else status(source)) for source in sources}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if all(item["ready"] for item in result.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
