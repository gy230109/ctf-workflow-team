"""Purge redteam × CTF fusion bridge.

把破甲（Purge）全量 56 个工具注册进 ``ctf_os.ALL_TOOLS``，并保持
``task_id ⇄ engagement`` 绑定与证据链（WP step ↔ 资产/漏洞/POC）。

契约：``integrations/purge-redteam/FUSION-CONTRACT.md``

对外接口
--------
``TOOLS``              ``{name: (handler, description, parameters)}``，可直接并入 ALL_TOOLS
``DANGEROUS``          需要 ``confirm=true`` 的工具名
``load_catalogue()``   三级兜底加载工具目录（runtime 缓存 → runtime 现取 → 静态解析）
``CatalogueInfo``      最近一次加载的来源与降级标记，用于不假装完整
``runtime_available()``运行时就绪探测
``call_tool(name, args)`` 直接调用（handler 内部同路径）
``store_call(...)``    兼容 8 个 ``ctf_redteam_*`` 工具的 store 兼容路径

设计纪律：任何异常都转 ``ValueError`` / ``RuntimeError``；超过 600 秒一律拒绝；
写操作可带 ``source_step``，但只能引用真实执行步骤，不引用红队元数据自身。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
INTEGRATION = BASE / 'integrations/purge-redteam'
RUNTIME_DIR = INTEGRATION / 'runtime'
RUNTIME_MCP = RUNTIME_DIR / 'redteam-mcp.mjs'
CATALOGUE_FILE = RUNTIME_DIR / 'catalogue.json'
MANIFEST_FILE = INTEGRATION / 'manifest.json'
SCHEMA_DIR = INTEGRATION / 'schemas'
UPSTREAM_SCHEMA = INTEGRATION / 'upstream/lib/redteam/schema.js'
DATA_DIR = BASE / '.local/purge-redteam'
TASKS_DIR = BASE / '.local/ctf-system/tasks'

#: 目录缓存写在数据区，不写队友的 ``runtime/``（scope 纪律）。
CACHE_FILE = DATA_DIR / 'catalogue-cache.json'

CASE_RE = re.compile(r'ctf-[a-f0-9]{16}')
MAX_TIMEOUT = 600
DEFAULT_TIMEOUT = 120

#: 这些 key 是 CTF 侧调度参数，不进红队工具 payload。
INTERNAL_KEYS = frozenset({
    'case', 'wp_case', 'timeout', 'source_step', 'confirm',
    'wp_purpose', 'wp_expectation', 'wp_repeat_expected',
})

#: 主动连接探测类工具沿用 CTF 的 confirm=true 约定。
DANGEROUS = {'redteam_session_check'}

#: 证据链：红队元数据记录不能当作执行证据。
EVIDENCE_DENY_PREFIXES = ('ctf_redteam_',)


class CatalogueInfo(dict):
    """目录加载结果（dict 子类，方便直接 json 序列化）。"""

    @property
    def degraded(self) -> bool:
        return bool(self.get('degraded'))

    @property
    def source(self) -> str:
        return str(self.get('source') or 'unknown')


# --------------------------------------------------------------------------- util


def node_executable():
    """node 可执行文件：PATH 优先，其次 D:\\noje\\node.exe。"""
    found = shutil.which('node')
    if found:
        return found
    for candidate in ('', r'C:\Program Files\nodejs\node.exe'):
        path = Path(candidate)
        if path.is_file():
            return str(path)
    return None


def runtime_available() -> bool:
    """运行时脚本在不在（不探测它能否跑通，避免额外起进程）。"""
    return RUNTIME_MCP.is_file()


def store_supported() -> bool:
    """runtime 是否实现 ``{"op":"store"}`` 兼容路径（静态探测，不起进程）。

    8 个兼容工具靠这个判断能否改走 fusion；不支持就保持原 bridge 路径。
    """
    if not RUNTIME_MCP.is_file():
        return False
    try:
        text = RUNTIME_MCP.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return False
    return any(mark in text for mark in ('"store"', "'store'", 'store:'))


#: runtime 完全不可用时才允许回退原 bridge（避免重复执行写操作）。
RUNTIME_DOWN_MARKS = ('not provisioned', 'could not start', 'no JSON',
                      'Node.js 22.13+', 'timed out after')


def _runtime_argv(node: str):
    """runtime 是否接受 ``--data-dir``；不接受就不多传参数。"""
    argv = [node, str(RUNTIME_MCP)]
    try:
        text = RUNTIME_MCP.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return argv
    if '--data-dir' in text:
        argv.extend(['--data-dir', str(DATA_DIR)])
    return argv


def _read_json(path: Path):
    """读 JSON；``utf-8-sig`` 兼顾带 BOM 的文件。

    ``runtime/catalogue.json`` 是 Node 侧用 ``writeFileSync`` 落盘的，Windows 上常带 BOM。
    早先这里按 ``utf-8`` 解码会抛 ``Unexpected UTF-8 BOM``，被 ``except ValueError`` 吞成
    ``None``，于是这份「一级目录源」被静默跳过 —— 排查时会误以为它没被写过。
    """
    try:
        data = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


#: JSON Schema 里允许出现在 ``type`` 上的标量名。
_TYPE_NAMES = frozenset({
    'object', 'array', 'string', 'number', 'integer', 'boolean', 'null',
})

#: 只在本层是 schema 时有意义的保留字。出现在 ``properties`` 的键位上、**且值不是 schema**
#: 时，说明这一整层被当成一个「属性」包了起来。
_SCHEMA_KEYWORDS = frozenset({
    'type', 'properties', 'items', 'required', 'additionalProperties',
    'enum', 'pattern', 'format', 'minimum', 'maximum', 'anyOf', 'oneOf',
    'allOf', 'not', '$ref', 'default', 'title',
})


def _looks_wrapped(props: dict) -> bool:
    """判断 ``properties`` 是否被整层包了一层。

    关键点：**不能只看键名**。``title`` / ``format`` / ``default`` 这些都是合法的字段名，
    真正的判别依据是「键是 schema 保留字，而值不像 schema」——``properties`` 的值必须
    是 schema（dict）或 boolean，所以 ``"type": "object"`` 这种字符串值一定是包壳。
    """
    for key, value in props.items():
        if not isinstance(key, str) or key not in _SCHEMA_KEYWORDS:
            continue
        if isinstance(value, dict):
            continue                       # 字段名恰好叫 title，值是 schema —— 正常
        if key == 'additionalProperties' and isinstance(value, bool):
            return True
        if isinstance(value, (str, list, int, float, bool)):
            return True
    return False


def repair_schema(node, _depth=0):
    """就地修复一份 JSON Schema，返回 ``(schema, problems)``。

    规则（只做结构性修复，不猜参数名、不删参数）：
      1. ``properties`` 只能是 ``{name: schema}``，禁止出现 ``type``/``properties`` 等保留字键位；
      2. ``additionalProperties`` 只能是 bool 或 schema，绝不能是字符串；
      3. ``type`` 只能是类型名，不能是对象；
      4. ``items`` 只能是 schema 或 schema 数组。
    """
    problems = []
    if not isinstance(node, dict):
        return node, problems
    if _depth > 32:                       # 防御自引用/病态嵌套
        return node, problems

    props = node.get('properties')
    if isinstance(props, dict) and props and _looks_wrapped(props):
        problems.append('properties carries schema keywords instead of field names')
        wrapped = dict(props)
        inner = wrapped.get('properties')
        if isinstance(inner, dict) and inner:
            node['properties'] = {}
            node['properties'].update(inner)
        else:
            node['properties'] = {}
        if 'required' not in node and isinstance(wrapped.get('required'), list):
            node['required'] = [r for r in wrapped['required'] if isinstance(r, str)]
        if 'additionalProperties' not in node and isinstance(
                wrapped.get('additionalProperties'), bool):
            node['additionalProperties'] = wrapped['additionalProperties']
        props = node.get('properties')

    if isinstance(props, dict):
        node['properties'] = {}
        for key, value in props.items():
            if not isinstance(key, str):
                problems.append('non-string property name dropped')
                continue
            if not isinstance(value, dict):
                value = {}
            fixed, sub = repair_schema(value, _depth + 1)
            problems.extend(sub)
            node['properties'][key] = fixed

    ap = node.get('additionalProperties')
    if isinstance(ap, str):
        problems.append('additionalProperties was a string')
        lowered = ap.strip().lower()
        node['additionalProperties'] = lowered in ('true', '1', 'yes')
    elif ap is not None and not isinstance(ap, (bool, dict)):
        problems.append('additionalProperties was not bool/object')
        node.pop('additionalProperties', None)
    elif isinstance(ap, dict):
        fixed, sub = repair_schema(ap, _depth + 1)
        problems.extend(sub)
        node['additionalProperties'] = fixed

    declared = node.get('type')
    if isinstance(declared, dict):
        problems.append('type was an object')
        node['type'] = 'object' if isinstance(declared.get('properties'), dict) else 'string'
    elif isinstance(declared, list):
        cleaned = [t for t in declared if isinstance(t, str) and t in _TYPE_NAMES]
        if not cleaned:
            problems.append('type list had no valid member')
            node.pop('type', None)
        elif len(cleaned) != len(declared):
            problems.append('type list had invalid members')
            node['type'] = cleaned

    items = node.get('items')
    if isinstance(items, dict):
        fixed, sub = repair_schema(items, _depth + 1)
        problems.extend(sub)
        node['items'] = fixed
    elif isinstance(items, list):
        fixed_items = []
        for entry in items:
            fixed, sub = repair_schema(entry if isinstance(entry, dict) else {}, _depth + 1)
            problems.extend(sub)
            fixed_items.append(fixed)
        node['items'] = fixed_items
    elif items is not None:
        problems.append('items was not object/array')
        node.pop('items', None)

    req = node.get('required')
    if req is not None and not (isinstance(req, list) and all(isinstance(r, str) for r in req)):
        problems.append('required was not a string array')
        if isinstance(props, dict):
            node['required'] = [r for r in (req if isinstance(req, list) else []) if isinstance(r, str)]
        else:
            node.pop('required', None)
    return node, problems


def _norm_tools(raw) -> list:
    """把任意来源的 tools 列表规范成 ``[{name, description, parameters}]``。

    任何来源（runtime 现取、磁盘缓存、静态解析）的 schema 都过一遍 ``repair_schema``，
    保证下发给模型网关的 ``properties`` 永远是「字段名 → schema」，不会把类型名当成字段名。
    """
    out = []
    seen = set()
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get('name')
        if not isinstance(name, str) or not name.startswith('redteam_'):
            continue
        if name in seen:
            continue
        seen.add(name)
        params = item.get('parameters')
        if not isinstance(params, dict) or params.get('type') != 'object':
            params = {'type': 'object', 'properties': {}}
        params, _problems = repair_schema(deepcopy(params))
        if not isinstance(params.get('properties'), dict):
            params['properties'] = {}
        out.append({
            'name': name,
            'description': str(item.get('description') or ''),
            'parameters': params,
        })
    return out


# --------------------------------------------------------------- catalogue 三级


def _from_file(path: Path, source: str):
    data = _read_json(path)
    if not data:
        return None
    tools = _norm_tools(data.get('tools'))
    if not tools:
        return None
    info = CatalogueInfo(source=source, degraded=bool(data.get('degraded')),
                         tools=tools, path=str(path), count=len(tools))
    return info


def _from_runtime():
    """当场问 runtime 要目录；成功则写入数据区缓存。"""
    node = node_executable()
    if not node or not RUNTIME_MCP.is_file():
        return None
    try:
        proc = subprocess.run(
            _runtime_argv(node),
            input=json.dumps({'op': 'list'}, ensure_ascii=False),
            capture_output=True, text=True, encoding='utf-8',
            timeout=DEFAULT_TIMEOUT, cwd=str(BASE),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode:
        return None
    payload = None
    for line in reversed((proc.stdout or '').splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            break
        except ValueError:
            continue
    if not isinstance(payload, dict) or payload.get('ok') is not True:
        return None
    tools = _norm_tools(payload.get('tools'))
    if not tools:
        return None
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(
            {'tools': tools, 'source': 'runtime:list',
             'degraded': False, 'written_by': 'ctf_redteam_fusion'},
            ensure_ascii=False, indent=1), encoding='utf-8')
    except OSError:
        pass
    return CatalogueInfo(source='runtime:list', degraded=False, tools=tools,
                         path=str(RUNTIME_MCP), count=len(tools))


def _parse_upstream_schema():
    """从 ``upstream/lib/redteam/schema.js`` 抠工具名+参数骨架（契约要求的降级源）。

    该文件主要承载 DDL 与迁移，未必含工具表；能抠到多少算多少。
    """
    try:
        text = UPSTREAM_SCHEMA.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    names = []
    for match in re.finditer(r"['\"](redteam_[a-z][a-z0-9_]*)['\"]", text):
        name = match.group(1)
        if name not in names:
            names.append(name)
    # 参数骨架同样只能给到空 object（该文件不含工具参数定义）。
    return [{'name': n, 'description': 'redteam tool (parsed from upstream schema.js)',
             'parameters': {'type': 'object', 'properties': {}}} for n in names]


def _shallow(text: str) -> str:
    """去掉嵌套对象内容，只留本层标量与顶层数组（``required`` 只在本层有效）。"""
    out = []
    depth = 0
    quote = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == '\\':
                if depth == 0:
                    out.append(text[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
            if depth == 0:
                out.append(ch)
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            if depth == 0:
                out.append(ch)
            i += 1
            continue
        if ch == '{':
            depth += 1
            i += 1
            continue
        if ch == '}':
            depth = max(0, depth - 1)
            i += 1
            continue
        if ch == '[':
            if depth == 0:
                out.append(ch)
            depth += 1
            i += 1
            continue
        if ch == ']':
            depth = max(0, depth - 1)
            if depth == 0:
                out.append(ch)
            i += 1
            continue
        if depth == 0:
            out.append(ch)
        i += 1
    return ''.join(out)


def _parse_parameters_js(text: str):
    """把 schemas/*.json 里的 ``parameters_js`` 字面量解析成 JSON Schema 骨架。

    只取顶层参数名与 type/required/enum/description，嵌套项按类型留空 —— 这是
    降级目录的“参数骨架”，足够让 agent 知道该传哪些 key，不假装是完整 schema。
    """
    if not isinstance(text, str) or not text.strip():
        return None
    src = text.strip()
    depth = 0
    properties = {}
    required = []
    i = 0
    n = len(src)
    quote = None
    key_buf = None
    while i < n:
        ch = src[i]
        if quote:
            if ch == '\\':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            i += 1
            continue
        if ch in '{[(':
            depth += 1
            i += 1
            continue
        if ch in '}])':
            depth -= 1
            i += 1
            continue
        if depth == 1 and (ch.isalpha() or ch == '_'):
            match = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*:', src[i:])
            if match:
                key = match.group(1)
                i += match.end()
                # 取该 key 的 value 片段（到同层 , 或 } 为止）
                start = i
                level = 0
                quote2 = None
                while i < n:
                    c = src[i]
                    if quote2:
                        if c == '\\':
                            i += 2
                            continue
                        if c == quote2:
                            quote2 = None
                        i += 1
                        continue
                    if c in ('"', "'", '`'):
                        quote2 = c
                        i += 1
                        continue
                    if c in '{[(':
                        level += 1
                    elif c in '}])':
                        if level == 0:
                            break
                        level -= 1
                    elif c == ',' and level == 0:
                        break
                    i += 1
                chunk = src[start:i].strip()
                if len(chunk) >= 2 and chunk[0] == '{' and chunk[-1] == '}':
                    chunk = chunk[1:-1]
                flat = _shallow(chunk)
                prop = {}
                tmatch = re.search(r"type\s*:\s*['\"]([a-zA-Z]+)['\"]", flat)
                if tmatch:
                    prop['type'] = tmatch.group(1).lower()
                dmatch = re.search(r"description\s*:\s*['\"]([^'\"]*)", flat)
                if dmatch:
                    prop['description'] = dmatch.group(1)[:300]
                ematch = re.search(r"enum\s*:\s*\[([^\]]*)\]", flat)
                if ematch:
                    values = re.findall(r"['\"]([^'\"]+)['\"]", ematch.group(1))
                    if values:
                        prop['enum'] = values
                if re.search(r'required\s*:\s*true', flat):
                    required.append(key)
                if prop:
                    properties[key] = prop
                continue
        i += 1
    if not properties:
        return None
    schema = {'type': 'object', 'properties': properties}
    if required:
        schema['required'] = required
    return schema


def _manifest_schema(name: str, rel=None) -> dict:
    """按 manifest 条目取参数定义：优先解析 parameters_js，其次整份 schema 文件。"""
    candidates = []
    if isinstance(rel, str):
        candidates.append(INTEGRATION / rel)
    candidates.append(SCHEMA_DIR / (name + '.json'))
    for path in candidates:
        data = _read_json(path)
        if not data:
            continue
        parsed = _parse_parameters_js(data.get('parameters_js'))
        if parsed:
            return parsed
        if data.get('type') == 'object' and isinstance(data.get('properties'), dict):
            return data
    return {'type': 'object', 'properties': {}}


def _manifest_operation(name: str, rel=None) -> str | None:
    """schemas/*.json 里的 ``operation`` = bridge/store 操作名，用于兜底派发。"""
    candidates = []
    if isinstance(rel, str):
        candidates.append(INTEGRATION / rel)
    candidates.append(SCHEMA_DIR / (name + '.json'))
    for path in candidates:
        data = _read_json(path)
        if not data:
            continue
        op = data.get('operation')
        if isinstance(op, str) and op:
            return op
    return None


def _from_manifest():
    """静态兜底：manifest.tool_mapping（56 条）+ schemas/*.json 参数定义。"""
    manifest = _read_json(MANIFEST_FILE)
    if not manifest:
        return None
    rows = manifest.get('tool_mapping')
    tools = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get('source_tool')
            if not isinstance(name, str) or not name.startswith('redteam_'):
                continue
            rel = row.get('parameter_definition')
            item = {'name': name,
                    'description': str(row.get('integration') or ''),
                    'parameters': _manifest_schema(name, rel)}
            op = _manifest_operation(name, rel)
            if op:
                item['operation'] = op
            if not item['description']:
                item['description'] = 'Purge redteam tool %s (degraded catalogue)' % name
            tools.append(item)
    # manifest 不全时补 schema 目录里剩下的
    if SCHEMA_DIR.is_dir():
        known = {t['name'] for t in tools}
        for path in sorted(SCHEMA_DIR.glob('redteam_*.json')):
            name = path.stem
            if name in known:
                continue
            data = _read_json(path) or {}
            item = {'name': name,
                    'description': str(data.get('trust') or
                                       'Purge redteam tool %s (degraded catalogue)' % name),
                    'parameters': _manifest_schema(name)}
            op = data.get('operation')
            if isinstance(op, str) and op:
                item['operation'] = op
            tools.append(item)
            known.add(name)
    if not tools:
        return None
    tools = _norm_tools(tools)
    if not tools:
        return None
    return CatalogueInfo(source='manifest+schemas (degraded)', degraded=True,
                         tools=tools, path=str(MANIFEST_FILE), count=len(tools))


def load_catalogue() -> CatalogueInfo:
    """加载 56 工具目录，永不抛异常。

    顺序：``runtime/catalogue.json`` → runtime ``{"op":"list"}``（数据区缓存）
    → ``upstream/lib/redteam/schema.js`` 解析 → ``manifest.json``+``schemas``。
    后两级一律 ``degraded=True``，不假装完整。
    """
    for loader in (
        lambda: _from_file(CATALOGUE_FILE, 'runtime:catalogue.json'),
        lambda: _from_file(CACHE_FILE, 'runtime:list (cached)'),
        _from_runtime,
    ):
        try:
            info = loader()
        except Exception:                                     # noqa: BLE001 - 加载期绝不炸宿主
            info = None
        if info:
            return info

    parsed = []
    try:
        parsed = _parse_upstream_schema()
    except Exception:                                         # noqa: BLE001
        parsed = []
    if parsed:
        return CatalogueInfo(source='upstream/schema.js (degraded)', degraded=True,
                             tools=_norm_tools(parsed), path=str(UPSTREAM_SCHEMA),
                             count=len(parsed))

    info = None
    try:
        info = _from_manifest()
    except Exception:                                         # noqa: BLE001
        info = None
    if info:
        return info

    return CatalogueInfo(source='none', degraded=True, tools=[], count=0,
                         error='redteam runtime 与 manifest 均不可用')


# ------------------------------------------------------------------ case / 证据


def _case(args) -> str:
    """沿用 ``ctf_redteam._case`` 的校验语义（case ↔ wp_case 不得冲突）。"""
    if not isinstance(args, dict):
        raise ValueError('arguments must be an object')
    case = args.get('case')
    wp_case = args.get('wp_case')
    if case and wp_case and case != wp_case:
        raise ValueError('A redteam operation cannot use evidence from a different task.')
    case = case or wp_case
    if not isinstance(case, str) or not CASE_RE.fullmatch(case):
        raise ValueError('Use the task_id returned by ctf_start.')
    if not (TASKS_DIR / case / 'task.json').is_file():
        raise ValueError('The CTF task does not exist in this installation.')
    return case


def _evidence(case: str, step):
    """``source_step`` 必须指向真实执行步骤（不能引用红队元数据自身）。"""
    if step is None:
        return None
    if type(step) is not int or step < 1:
        raise ValueError('source_step must refer to a completed real CTF tool call.')
    if 'ctf_wp' not in sys.modules:
        sys.path.insert(0, str(BASE / 'tools'))
    import ctf_wp                                            # noqa: PLC0415 - 延迟导入
    rows = ctf_wp.verify(ctf_wp.case_dir(case))
    row = next((r for r in rows if r.get('seq') == step and r.get('kind') == 'call'), None)
    if row is None:
        raise ValueError('Use an actual execution step; that step has no tool call record.')
    tool = str(row.get('data', {}).get('tool', ''))
    if tool.startswith(EVIDENCE_DENY_PREFIXES):
        raise ValueError('Use an actual execution step; a redteam metadata record is not execution evidence.')
    return {'wp_case': case, 'source_step': step, 'source_tool': tool}


def _timeout(args) -> int:
    value = args.get('timeout', DEFAULT_TIMEOUT)
    if type(value) is not int or not 1 <= value <= MAX_TIMEOUT:
        raise ValueError('timeout must fit the existing CTF 600-second execution budget')
    return value


def _payload(args) -> dict:
    return {k: v for k, v in args.items() if k not in INTERNAL_KEYS}


# ---------------------------------------------------------------------- runtime


def _invoke(request: dict, timeout: int) -> dict:
    """单次 stdin/stdout 调 runtime。"""
    node = node_executable()
    if not node:
        raise RuntimeError('Node.js 22.13+ with node:sqlite is required; no dependency was installed automatically.')
    if not RUNTIME_MCP.is_file():
        raise RuntimeError('Purge redteam runtime is not provisioned: %s' % RUNTIME_MCP)
    try:
        proc = subprocess.run(
            _runtime_argv(node),
            input=json.dumps(request, ensure_ascii=False),
            capture_output=True, text=True, encoding='utf-8',
            timeout=timeout, cwd=str(BASE),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Redteam runtime timed out after %ds' % timeout) from exc
    except OSError as exc:
        raise RuntimeError('Redteam runtime could not start: %r' % (exc,)) from exc
    if proc.returncode:
        detail = (proc.stderr or '').strip()[-1000:]
        raise RuntimeError('Redteam runtime failed (exit %s): %s' % (proc.returncode, detail))
    payload = None
    for line in reversed((proc.stdout or '').splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            break
        except ValueError:
            continue
    if not isinstance(payload, dict):
        raise RuntimeError('Redteam runtime returned no JSON: %s' % (proc.stdout or '')[-500:])
    if payload.get('ok') is not True:
        code = payload.get('error') or 'operation_failed'
        detail = payload.get('detail')
        raise RuntimeError(str(code) + (': %s' % detail if detail else ''))
    return payload


def call_tool(name: str, args) -> dict:
    """以 CTF 工具约定调用单个 redteam 工具。"""
    if not isinstance(name, str) or not name.startswith('redteam_'):
        raise ValueError('Unknown redteam tool.')
    args = dict(args or {})
    case = _case(args)
    if name in DANGEROUS and args.get('confirm') is not True:
        raise ValueError('Active connectivity checks retain the existing CTF confirm=true requirement.')
    timeout = _timeout(args)
    request = {'op': 'call', 'tool': name, 'args': _payload(args), 'case': case}
    provenance = _evidence(case, args.get('source_step'))
    if provenance:
        request['provenance'] = provenance
    payload = _invoke(request, timeout)
    result = payload.get('result')
    out = result if isinstance(result, dict) else {'result': result}
    out = dict(out)
    out.update({
        'tool': name,
        'case': case,
        'catalogue_source': _CATALOGUE_SOURCE,
        'provenance': provenance or {'wp_case': case, 'source_step': None,
                                     'status': 'metadata-only; no execution evidence supplied'},
        'answer_verified': False,
    })
    return out


def store_call(case, op, data=None, provenance=None, timeout=DEFAULT_TIMEOUT) -> dict:
    """兼容 8 个 ``ctf_redteam_*`` 工具的 store 路径（``{"op":"store"}``）。"""
    if not RUNTIME_MCP.is_file():
        raise RuntimeError('Purge redteam runtime is not provisioned: %s' % RUNTIME_MCP)
    if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT:
        raise ValueError('timeout must fit the existing CTF 600-second execution budget')
    request = {'op': 'store', 'name': op, 'data': data or {}, 'case': case}
    if provenance:
        request['provenance'] = provenance
    payload = _invoke(request, timeout)
    result = payload.get('result')
    return result if isinstance(result, dict) else {'result': result}


# ------------------------------------------------------------------------ TOOLS


def _make_handler(name: str, description: str):
    def handler(args):
        return call_tool(name, args)

    handler.__name__ = 'redteam_tool_' + name[len('redteam_'):]
    handler.__doc__ = description or ('Purge redteam tool %s' % name)
    return handler


def _tool_schema(parameters: dict) -> dict:
    """在原 schema 上补齐 CTF 调度字段（case / timeout / source_step）。"""
    schema = deepcopy(parameters) if isinstance(parameters, dict) else {}
    if schema.get('type') != 'object':
        schema = {'type': 'object', 'properties': {}}
    props = schema.setdefault('properties', {})
    if not isinstance(props, dict):
        props = {}
        schema['properties'] = props
    props.setdefault('case', {'type': 'string',
                              'description': 'ctf_start 返回的 task_id；同题共用 engagement'})
    props.setdefault('timeout', {'type': 'integer', 'minimum': 1, 'maximum': MAX_TIMEOUT})
    props.setdefault('source_step', {'type': 'integer', 'minimum': 1,
                                     'description': '仅写操作：引用已完成的真实 CTF 执行步骤'})
    return schema


def _build(registry):
    tools = {}
    for spec in registry:
        name = spec['name']
        tools[name] = (_make_handler(name, spec['description']),
                       spec['description'] or ('Purge redteam tool %s' % name),
                       _tool_schema(spec['parameters']))
    return tools


#: 最近一次目录加载结果（import 时求值一次）
CATALOGUE = load_catalogue()
_CATALOGUE_SOURCE = CATALOGUE.source
_CATALOGUE_DEGRADED = CATALOGUE.degraded

#: 56 项（runtime 真目录或降级目录），可直接并入 ALL_TOOLS
TOOLS = _build(CATALOGUE.get('tools') or [])


def describe_catalogue() -> dict:
    """给自测/报告用的目录元信息（不声称执行可用）。"""
    return {
        'count': len(TOOLS),
        'registered': sorted(TOOLS),
        'source': _CATALOGUE_SOURCE,
        'degraded': _CATALOGUE_DEGRADED,
        'runtime_present': runtime_available(),
        'runtime_path': str(RUNTIME_MCP),
        'catalogue_path': str(CATALOGUE_FILE),
        'node': node_executable(),
        'synthesized_handlers': sum(1 for n in TOOLS if n.startswith('redteam_')),
    }


def write_registered_list(path=None) -> Path:
    """导出注册工具名清单（默认 runtime/registered-tools.txt）。"""
    target = Path(path) if path else (RUNTIME_DIR / 'registered-tools.txt')
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        '# purge redteam tools registered into ctf_os.ALL_TOOLS',
        '# source: %s   degraded: %s' % (_CATALOGUE_SOURCE, _CATALOGUE_DEGRADED),
        '# generated_by: tools/ctf_redteam_fusion.py',
        '',
    ]
    lines.extend(sorted(TOOLS))
    target.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return target


__all__ = ['TOOLS', 'DANGEROUS', 'CATALOGUE', 'load_catalogue', 'describe_catalogue',
           'call_tool', 'store_call', 'runtime_available', 'node_executable',
           'write_registered_list', 'CatalogueInfo']
