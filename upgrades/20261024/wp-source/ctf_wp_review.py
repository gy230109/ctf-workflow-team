"""Read-only WP completeness checks over already-verified, case-local evidence.

This module checks structure and receipts. It does not judge whether an Agent's
reasoning is correct and never converts prose into an accepted answer.
"""
import json


SECTION_NAMES = ("overview", "analysis", "solution", "validation", "reproduction")


def analyze(folder, rows):
    """Evaluate the caller's verified snapshot; caller owns locking/integrity."""
    calls = [event for event in rows if event["kind"] == "call"]
    context = {"description": "", "source": "", "artifacts": []}
    sections, observed, errors, issues, receipts = {}, set(), [], [], []
    attachments = {}
    for event in rows:
        data = event["data"]
        if event["kind"] == "intake":
            for key in ("description", "source"):
                if data.get(key):
                    context[key] = data[key]
            for item in data.get("artifacts", []):
                attachments[(item.get("name"), item.get("sha256"))] = item
        elif event["kind"] == "writeup_section":
            sections[data["section"]] = dict(data, step=event["seq"])
        elif event["kind"] == "note" and data.get("status") == "observed":
            observed.add(data.get("source_step"))
        elif event["kind"] == "capture_failed":
            errors.append(dict(data, step=event["seq"], kind="capture_failed"))
        elif event["kind"] == "call":
            errors.extend(dict(item, step=event["seq"]) for item in data.get("capture_errors", []))
            # Read only the protected raw result, never a summary or section.
            if data.get("tool") == "ctfd_submit":
                raw_file = next((x for x in event.get("files", []) if x.get("kind") == "tool_output"), None)
                if raw_file:
                    raw = json.loads((folder / raw_file["path"]).read_text(encoding="utf-8"))
                    response = raw.get("response") or {}
                    result = response.get("result") or {}
                    if (response.get("ok") is True and isinstance(result, dict)
                            and result.get("candidate_verified") is True
                            and result.get("judge_status") == "correct"):
                        receipts.append({"step": event["seq"], "platform": "CTFd",
                                         "challenge_id": result.get("challenge_id")})
    context["artifacts"] = list(attachments.values())
    completed = {e["data"].get("operation_id") for e in calls if e["data"].get("operation_id")}
    pending = [dict(e["data"], step=e["seq"]) for e in rows
               if e["kind"] == "operation_started" and e["data"].get("operation_id") not in completed]

    def issue(code, message, steps=None):
        issues.append({"code": code, "severity": "needs_attention", "message": message,
                       "steps": steps or []})

    if not context["description"]:
        issue("missing_description", "缺少原始题面；用 wp_intake 追加原文及来源。")
    if not calls:
        issue("missing_calls", "尚无实际工具调用记录。")
    no_purpose = [e["seq"] for e in calls if not str(e["data"].get("purpose") or "").strip()]
    if no_purpose:
        issue("missing_purpose", "这些调用未记录行动目的；勿用事后猜测冒充执行前记录。", no_purpose)
    no_observed = [e["seq"] for e in calls if e["seq"] not in observed]
    if no_observed:
        issue("missing_observation", "这些调用缺少引用原输出的观察结论。", no_observed)
    missing_sections = [name for name in SECTION_NAMES if not str(sections.get(name, {}).get("text") or "").strip()]
    if missing_sections:
        issue("missing_sections", "缺少章节：" + ", ".join(missing_sections))
    if pending:
        issue("pending_operations", "有执行开始但未收回结果的操作；不为补证据自动重跑。",
              [e["step"] for e in pending])
    if errors:
        issue("capture_failed", "存在截图、输入快照或导出文件采集缺项；原错误已保留。",
              sorted({e["step"] for e in errors}))
    if not receipts:
        issue("answer_not_verified", "尚无结构化的真实平台正确回执；章节文字不认证答案。")
    return {"ok": True, "status": "ready" if not issues else "draft",
            "quality": {"document_complete": not any(x["code"] != "answer_not_verified" for x in issues),
                        "missing_sections": missing_sections,
                        "calls_without_purpose": no_purpose,
                        "calls_without_observation": no_observed,
                        "review_scope": "结构与证据引用检查；未审判 Agent 文字的语义正确性"},
            "issues": issues, "submission_ready": not issues,
            "integrity_verified": True, "recording_complete": not errors and not pending,
            "platform_answer_verified": bool(receipts), "verification_receipts": receipts,
            "solved_verified": False, "capture_errors": errors,
            "pending_operations": pending, "context": context, "sections": sections,
            "review_required": "提交或公开前仍需审阅正文、原件及图片像素。"}
