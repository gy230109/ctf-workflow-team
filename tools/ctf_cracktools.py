"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib
import json
from pathlib import Path
import subprocess

BASE = Path(__file__).resolve().parents[1]
CONFIG = BASE / 'config/ctf_cracktools.local.json'


def settings():
    if not CONFIG.is_file():
        raise ValueError('CTFCrackTools 尚未部署')
    cfg = json.loads(CONFIG.read_text(encoding='utf-8-sig'))
    if cfg.get('enabled') is not True:
        raise ValueError('CTFCrackTools 未启用')
    return cfg


def verified_file(cfg, field):
    path = Path(cfg[field]).resolve(strict=True)
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != cfg[field + '_sha256']:
        raise ValueError(field + ' SHA256 不匹配，未执行')
    return path


def catalog(cfg):
    return json.loads(verified_file(cfg, 'catalog_file').read_text(encoding='utf-8'))


def status(args):
    if not CONFIG.is_file():
        return {'installed': False, 'detail': 'CTFCrackTools 尚未部署'}
    cfg = settings()
    state = {'installed': False, 'tag': cfg['tag'], 'upstream_commit': cfg['upstream_commit'],
             'scope': '本机文本编解码、哈希、古典密码与多步转换；不是 flag 判定器',
             'gui_path': cfg['gui_executable'], 'probe_performed': False}
    try:
        verified_file(cfg, 'gui_executable')
        verified_file(cfg, 'bridge_executable')
        algorithms = catalog(cfg)
        query = str(args.get('query') or '').casefold()
        state.update(installed=True, file_integrity_verified=True, algorithms_count=len(algorithms),
                     algorithms=[item for item in algorithms if query in item['algorithm'].casefold()],
                     limits={'input_bytes': 32768, 'steps': 16, 'output_per_step_bytes': 131072,
                             'total_step_output_bytes': 524288, 'timeout_seconds': 30},
                     usage='cracktools_run(input, steps=[{algorithm,mode}])。固定默认参数操作需 use_upstream_defaults=true；自定义密钥用现有密码工具。')
    except (OSError, ValueError) as exc:
        state['detail'] = str(exc)
    return state


def run(args):
    unknown = set(args) - {'input', 'steps', 'timeout', 'use_upstream_defaults', 'wp_case'}
    if unknown:
        raise ValueError('未知参数：' + ', '.join(sorted(unknown)))
    cfg = settings()
    executable = verified_file(cfg, 'bridge_executable')
    algorithms = {item['algorithm']: item for item in catalog(cfg)}
    text, steps = args.get('input'), args.get('steps')
    if not isinstance(text, str) or len(text.encode('utf-8')) > 32768:
        raise ValueError('input 必须为 UTF-8 文本且不超过 32 KiB；不适合任意二进制数据')
    if not isinstance(steps, list) or not 1 <= len(steps) <= 16:
        raise ValueError('steps 必须包含 1–16 个操作')
    warnings = []
    for step in steps:
        if not isinstance(step, dict) or set(step) != {'algorithm', 'mode'}:
            raise ValueError('每步只接受 algorithm 和 mode；自定义密钥/位移不受上游工作流支持')
        algorithm, mode = step['algorithm'], step['mode']
        if not isinstance(algorithm, str) or algorithm not in algorithms or mode not in algorithms[algorithm]['modes']:
            raise ValueError('算法或模式不受支持，请先 cracktools_status 查真实目录')
        item = algorithms[algorithm]
        if item['requires_upstream_defaults']:
            if args.get('use_upstream_defaults') is not True:
                raise ValueError(algorithm + ' 使用上游固定默认参数：' + item['parameter_limit'] + '；明确接受时设置 use_upstream_defaults=true')
            warnings.append(algorithm + ': ' + item['parameter_limit'])
    timeout = args.get('timeout', 15)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
        raise ValueError('timeout 必须为 1–30 秒')
    raw = json.dumps({'input': text, 'steps': steps}, ensure_ascii=False)
    if len(raw.encode('utf-8')) > 65536:
        raise ValueError('序列化请求超过 64 KiB')
    try:
        result = subprocess.run([str(executable)], input=raw, capture_output=True, text=True,
                                encoding='utf-8', timeout=timeout,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error_code': 'workflow_timeout', 'error': 'CTFCrackTools 工作流超时，已终止本次子进程'}
    if len(result.stdout.encode('utf-8')) > 4194304:
        raise ValueError('CTFCrackTools 输出超过预算')
    try:
        output = json.loads(result.stdout)
    except ValueError:
        return {'ok': False, 'error_code': 'bridge_invalid_output', 'error': 'CTFCrackTools 未返回有效 JSON',
                'exit_code': result.returncode, 'stderr': result.stderr[-2000:]}
    output['ok'] = output.get('ok') is True and result.returncode == 0
    if not output['ok']:
        output['error_code'] = 'workflow_failed'
    output.update(exit_code=result.returncode, upstream_commit=cfg['upstream_commit'],
                  engine='CTFCrackTools upstream Rust workflow engine + local bounded JSON wrapper',
                  parameter_warnings=list(dict.fromkeys(warnings)), answer_verified=False)
    return output


def open_gui(args):
    if args.get('confirm') is not True:
        raise ValueError('启动桌面工具需要布尔 confirm=true')
    cfg = settings()
    path = verified_file(cfg, 'gui_executable')
    process = subprocess.Popen([str(path)], cwd=path.parent,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return {'started': True, 'pid': process.pid, 'path': str(path), 'ui_ready_verified': False}


TOOLS = {
    'cracktools_status': (status, '查看 CTFCrackTools 本机安装、摘要与真实算法目录；不启动 GUI 或调用模型。部分算法使用固定默认参数。', {
        'type': 'object', 'properties': {'query': {'type': 'string'}}}),
    'cracktools_run': (run, '用 CTFCrackTools 原生 Rust 引擎执行文本转换链，失败即停止并自动留证。固定参数算法需 use_upstream_defaults=true；不验证 flag，不接收脚本。', {
        'type': 'object', 'properties': {'input': {'type': 'string'},
        'steps': {'type': 'array', 'minItems': 1, 'maxItems': 16, 'items': {'type': 'object',
            'properties': {'algorithm': {'type': 'string'}, 'mode': {'type': 'string', 'enum': ['encode', 'decode']}},
            'required': ['algorithm', 'mode'], 'additionalProperties': False}},
        'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 30, 'default': 15},
        'use_upstream_defaults': {'type': 'boolean', 'default': False}}, 'required': ['input', 'steps']}),
    'cracktools_open': (open_gui, '用户需要操作画布时启动 CTFCrackTools 桌面版；需要 confirm=true。自动转换使用 cracktools_run。', {
        'type': 'object', 'properties': {'confirm': {'type': 'boolean'}}, 'required': ['confirm']})
}
DANGEROUS = {'cracktools_open'}
