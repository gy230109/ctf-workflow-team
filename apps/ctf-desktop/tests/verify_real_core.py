"""Check the real installed source in a separate writable runtime, without an AI API."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app_server import Core, Application, installation

home = Path(__file__).resolve().parents[1]
root, python = installation()
checks = []

def check(name, value):
    checks.append({"name": name, "passed": bool(value)})
    if not value:
        raise AssertionError(name)

def must(result):
    if not result.get("ok"):
        raise AssertionError(json.dumps(result, ensure_ascii=False))
    return result

live = Core(root, python)
catalog = must(live.call("ctf_system_status"))
listing = must(live.call("ctf_progress"))
check("installed_core_read_only_status", catalog["contract"]["version"] == "ctf-system/1.1")
check("installed_tasks_read_from_core", len(listing["tasks"]) > 0)
baseline = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in (root/"tools").glob("*.py")}

with tempfile.TemporaryDirectory(prefix="ctf-app-verification-", dir=home) as temporary:
    sandbox = Path(temporary)
    # Keep all execution outputs in the writable test runtime. No account/config files are copied.
    shutil.copytree(root/"tools", sandbox/"tools", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.bak*"))
    core = Core(sandbox, python)
    app = Application(core, sandbox/"app-data")
    created = must(app.create({"title": "独立应用自建验收", "description": "离线计算 48 与 60 的最大公约数。非比赛题，不调用真实模型。", "category": "crypto"}))
    identifier = created["task"]["task_id"]
    check("application_intake_saved_by_real_core", created["workflow"]["phase"] == "needs_triage")
    triage = must(core.call("ctf_analyze", {"task_id": identifier, "tool": "ctf_profile", "arguments": {
        "category": "crypto", "wp_purpose": "对离线自建验收题分流"}}))
    result = must(core.call("ctf_analyze", {"task_id": identifier, "tool": "math_gcd", "request_id": "app-verification-gcd",
        "arguments": {"values": [48, 60], "wp_purpose": "实际计算两个整数的最大公约数"}}))
    check("actual_math_execution", result["execution"]["result"]["result"] == 12)
    step = result["execution"]["wp_record"]["step"]
    for section, text in [("analysis", "题面给定 48 与 60，使用最大公约数计算工具。"), ("solution", "系统实际计算返回 12。此为离线自建验收，不代表比赛题已经解决。")]:
        must(core.call("ctf_call", {"task_id": identifier, "tool": "wp_section", "arguments": {
            "section": section, "text": text, "source_steps": [step], "wp_purpose": "记录有实际计算依据的自建验收正文"}}))
    handoff = must(app.handoff(identifier))
    check("handoff_preserves_shared_task_id", identifier in handoff["text"])
    receipt = must(core.call("ctf_finish", {"task_id": identifier, "include_images": False,
        "summary": "自建算术与应用入口验收，不调用真实模型，不涉及比赛答案。"}))
    check("export_does_not_claim_answer_verified", not receipt["answer_verified"])
    reports = must(app.artifacts(identifier))
    check("actual_wp_files_exist", any(x["name"].endswith(".md") for x in reports["files"]))
    check("actual_wp_zip_exists", any(x["name"].endswith(".zip") for x in reports["files"]))
    check("restart_uses_same_saved_task", must(Core(sandbox, python).call("ctf_progress", {"task_id": identifier}))["task"]["task_id"] == identifier)

after = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/"tools").glob("*.py")}
check("installed_source_not_overwritten", baseline == after)
report = {"passed": all(c["passed"] for c in checks), "checks": checks,
    "installed_core": str(root), "installed_task_count": len(listing["tasks"]),
    "core_release": catalog["runtime"]["release"], "scope": "真实核心只读；完整建题/算术/WP链路在隔离副本中验证。模型循环另用模拟响应验证，无真实模型API或比赛答案验收。"}
(home/"verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(report, ensure_ascii=False))
