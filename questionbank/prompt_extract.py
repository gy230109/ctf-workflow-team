"""Conservative Markdown question extraction with fenced-code awareness."""
import re

START = re.compile(r"^(#{1,6})\s*(?:题目描述|题目介绍|题目|Description|Challenge Description)\s*$", re.I)
HEADING = re.compile(r"^(#{1,6})\s+(.+)$")
SOLUTION = re.compile(r"题解|解题|解法|解答|出题思路|solution|write.?up|walkthrough|expected.?solution", re.I)
FLAG = re.compile(r"\b(?:flag|ctf|crypto|DUCTF|CSAW|HTB|SEKAI|SUCTF|picoCTF)\{[^{}\r\n]{1,300}\}", re.I)


def extract_question(text):
    output = []; active = False; level = 0; fence = None; complete = False; reason = "question heading absent"
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None: fence = token
            elif token[0] == fence[0] and len(token) >= len(fence): fence = None
            if active: output.append(line)
            continue
        if fence is None:
            start = START.match(line.rstrip("\r\n"))
            if not active and start:
                active = True; level = len(start.group(1)); reason = "end of file"; continue
            heading = HEADING.match(line.rstrip("\r\n"))
            if active and heading:
                if SOLUTION.search(heading.group(2)):
                    complete = True; reason = "stopped before solution heading"; break
                if len(heading.group(1)) <= level:
                    reason = "stopped before sibling heading; completeness needs review"; break
        if active: output.append(line)
    else:
        complete = active and fence is None
    description = FLAG.sub("[literal reference withheld]", "".join(output))
    description = re.sub(r"(?i)\b(?:nc|ncat)\s+[A-Za-z0-9.-]+\s+[0-9]{2,5}", "[original remote endpoint; deploy a local instance]", description)
    if len(description) > 12000:
        description = description[:12000]; complete = False; reason = "question exceeds 12000-character catalog bound"
    return {"description": description, "full_prompt_available": complete, "description_scope": reason}
