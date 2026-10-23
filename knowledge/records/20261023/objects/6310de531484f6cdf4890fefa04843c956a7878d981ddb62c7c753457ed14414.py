"""Build local English n-gram statistics; do not send the image to a service."""
from pathlib import Path
from collections import Counter
import json, math, re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
corpus = ROOT / "references" / "hacktricks" / "src"
counts = Counter()
used = 0
for p in sorted(corpus.rglob("*.md")):
    text = p.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"```[\s\S]*?```", " ", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub("[^A-Z]", "", text.upper())
    counts.update(text[i:i+4] for i in range(len(text)-3))
    used += 1
    if sum(counts.values()) > 8_000_000:
        break
with (HERE/"grams.txt").open("w", encoding="ascii") as f:
    for gram, n in counts.items():
        f.write(f"{gram} {n}\n")
s = (HERE/"cipher.txt").read_text().replace("\n", "")
stats = {"symbols": dict(Counter(s)), "length":len(s), "distinct":len(set(s)),
         "training_files":used,"quadgrams":sum(counts.values()),
         "transcription_is_provisional":True}
(HERE/"preparation.json").write_text(json.dumps(stats,indent=2),encoding="utf-8")
print(json.dumps(stats))
