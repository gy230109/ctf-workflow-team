"""破甲（Purge 1.6.60）红队语义层 —— 并入原始 CTF 系统。

只读、不联网、不写 CTF 任务库。四个工具：
  ctf_redteam_skills       23 篇红队 playbook 的技能清单 + 依赖探针（probe 级证据）
  ctf_redteam_preset       红队预设（persona / 规则段）原文与行范围
  ctf_redteam_score_rules  评分维度与权重（优先 node 直接 import，失败回退结构提取）
  ctf_redteam_roles        红队角色清单（role-section）

证据等级约定：probe = 本机存在性探测；declared = 上游源码声明；verified = 实跑验证。
本模块不产出 verified。
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
INTEG = BASE / 'integrations' / 'purge-redteam'
UPSTREAM = INTEG / 'upstream'
FALLBACK = None  # 分发版不带本机解包副本；上游已在 integrations/purge-redteam/upstream
SOURCE_COMMIT = '27919a326b6615b1968661a3e749760cec3a2e07'
NODE = shutil.which('node') or ''

# playbook 名 -> 依赖的常见可执行文件（只做存在性探针，不代表可用）
DEPS = {
    'fscan-intranet': ['fscan'],
    'gogo-intranet': ['gogo'],
    'chisel-tunnel': ['chisel'],
    'frp-tunnel': ['frpc', 'frps'],
    'suo5-tunnel': ['suo5'],
    'nuclei-scan': ['nuclei'],
    'dir-bruteforce': ['ffuf'],
    'credential-attack': ['hashcat', 'john'],
    'active-scan': ['nmap'],
    'webshell-toolkit': ['curl'],
    'shell-handler': ['nc', 'ncat'],
    'cn-proxy-pool': ['proxychains', 'proxychains4'],
    'browser-automation': ['chrome', 'msedge'],
    'kimi-webbridge': [],
    'web-fingerprint': ['curl'],
    'recon-pipeline': ['subfinder', 'httpx'],
    'fofa-recon': ['curl'],
    'passive-recon': [],
    'asset-correlation': [],
    'lateral-movement': ['impacket', 'crackmapexec'],
    'unauth-exploit': ['curl'],
    'vps-reverse-shell': ['ssh'],
    'redteam-setup': [],
}


def _first(rel):
    for root in ([UPSTREAM] + ([FALLBACK] if FALLBACK else [])):
        candidate = root / rel
        if candidate.exists():
            return candidate, ('upstream' if root is UPSTREAM else 'fallback')
    return None, None


def _text(path):
    return path.read_text(encoding='utf-8')


def _skills_index():
    path = BASE / 'skills' / 'redteam-index.json'
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def skills(args):
    index = _skills_index()
    if not index:
        return {'ok': False, 'error': 'SKILL_INDEX_MISSING',
                'detail': 'skills/redteam-index.json 不存在，先运行技能落位步骤'}
    name = args.get('name')
    if name:
        index = [row for row in index if row.get('name') == name or row.get('source_name') == name]
        if not index:
            raise ValueError('未知技能名；先不带 name 调用取得清单')
    rows = []
    for row in index:
        deps = DEPS.get(row.get('source_name', ''), [])
        found = [d for d in deps if shutil.which(d)]
        missing = [d for d in deps if d not in found]
        rows.append({
            'name': row.get('name'),
            'source_name': row.get('source_name'),
            'description': row.get('description'),
            'path': row.get('path'),
            'sha256': row.get('sha256'),
            'bytes': row.get('bytes'),
            'dependencies': {'level': 'probe', 'required': deps, 'found': found, 'missing': missing},
        })
    return {
        'ok': True, 'count': len(rows), 'skills': rows,
        'source': f'purge@{SOURCE_COMMIT} skills/redteam/*.md',
        'evidence_level': 'probe',
        'note': 'found 只代表 PATH 上存在该可执行文件；是否可打、是否被策略允许仍需实跑确认。',
    }


def preset(args):
    path, origin = _first('presets/redteam/agent.cordis.yml')
    if not path:
        return {'ok': False, 'error': 'PRESET_MISSING', 'detail': '未找到 presets/redteam/agent.cordis.yml'}
    text = _text(path)
    lines = text.splitlines()
    match = re.search(r'(?ms)^- id: persona\s*$.*?(?=^- id: |\Z)', text)
    block = match.group(0).rstrip() if match else ''
    if not block:
        return {'ok': False, 'error': 'PERSONA_BLOCK_NOT_FOUND', 'detail': '预设文件结构变化，未匹配到 persona 段'}
    start = text[:text.index(block)].count('\n') + 1
    return {
        'ok': True, 'source': str(path), 'origin': origin, 'commit': SOURCE_COMMIT,
        'start_line': start, 'total_lines': len(lines),
        'persona_block': block,
        'evidence_level': 'declared',
        'note': '预设是宿主侧组合文件，CTF 系统只读取其身份/规则段作为参考，不据此改写任何宿主配置。',
    }


def _node_dump(rel, expr):
    path, origin = _first(rel)
    if not path:
        return None, None
    if not NODE:
        return None, origin
    script = (
        "import('file:///%s').then(m=>{const pick=%s;"
        "process.stdout.write(JSON.stringify(pick(m)))}).catch(e=>{"
        "process.stdout.write(JSON.stringify({__error:String(e&&e.message||e)}))})"
    ) % (str(path).replace('\\', '/'), expr)
    try:
        out = subprocess.run([NODE, '--input-type=module', '-e', script],
                             capture_output=True, text=True, encoding='utf-8', timeout=60)
        data = json.loads(out.stdout or '{}')
        if isinstance(data, dict) and data.get('__error'):
            return None, origin
        return data, origin
    except Exception:
        return None, origin


def score_rules(args):
    data, origin = _node_dump('lib/redteam/score-rules.js',
                              '(m)=>({exports:Object.keys(m),dims:(m.SCORE_DIMENSIONS||m.DIMENSIONS||m.scoreDimensions||null)})')
    if data:
        return {'ok': True, 'extraction': 'node-import', 'origin': origin, **data,
                'evidence_level': 'declared', 'source': 'lib/redteam/score-rules.js'}
    path, origin = _first('lib/redteam/score-rules.js')
    if not path:
        return {'ok': False, 'error': 'SCORE_RULES_MISSING'}
    text = _text(path)
    ids = sorted(set(re.findall(r'id:\s*"([a-z0-9_\-]{3,40})"', text)))[:80]
    weights = re.findall(r'weight:\s*([0-9.]+)', text)[:80]
    return {'ok': True, 'extraction': 'regex-fallback', 'origin': origin,
            'dimension_ids': ids, 'weights': weights, 'evidence_level': 'declared',
            'note': 'node 直接 import 失败，退回结构提取；仅供阅读，不参与实际计分。'}


def roles(args):
    data, origin = _node_dump('lib/redteam/role-section.js',
                              '(m)=>({exports:Object.keys(m),roles:(m.ROLES||m.roleSections||null)})')
    if data:
        return {'ok': True, 'extraction': 'node-import', 'origin': origin, **data,
                'evidence_level': 'declared', 'source': 'lib/redteam/role-section.js'}
    path, origin = _first('lib/redteam/role-section.js')
    if not path:
        return {'ok': False, 'error': 'ROLE_SECTION_MISSING'}
    text = _text(path)
    names = sorted(set(re.findall(r'(?:id|role):\s*"([a-z][a-z0-9_\-]{2,30})"', text)))
    return {'ok': True, 'extraction': 'regex-fallback', 'origin': origin, 'roles': names,
            'evidence_level': 'declared'}


def _schema(extra=None, required=()):
    props = {'case': {'type': 'string'}}
    props.update(extra or {})
    return {'type': 'object', 'properties': props, 'required': list(required), 'additionalProperties': False}


TOOLS = {
    'ctf_redteam_skills': (
        skills,
        '列出已并入 CTF 系统的破甲红队技能（23 篇 playbook）及其依赖探针结果；probe 级证据，不代表可用。',
        _schema({'name': {'type': 'string'}}),
    ),
    'ctf_redteam_preset': (
        preset,
        '读取破甲红队预设（persona/规则段）原文与行范围；只读参考，不改宿主配置。',
        _schema(),
    ),
    'ctf_redteam_score_rules': (
        score_rules,
        '读取破甲评分维度与权重定义（node import 优先，失败回退结构提取）；仅供对照，不参与实际计分。',
        _schema(),
    ),
    'ctf_redteam_roles': (
        roles,
        '读取破甲红队角色段清单，供 ctf_suite 派单参考。',
        _schema(),
    ),
}

DANGEROUS = set()


if __name__ == '__main__':
    import sys
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    name = sys.argv[1] if len(sys.argv) > 1 else ''
    if name in TOOLS:
        print(json.dumps(TOOLS[name][0]({}), ensure_ascii=False, indent=2))
    else:
        print(json.dumps({'tools': list(TOOLS)}, ensure_ascii=False, indent=2))
