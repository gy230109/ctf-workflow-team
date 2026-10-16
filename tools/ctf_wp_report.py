"""One evidence-backed report model shared by readable WP formats.

Previews are mechanical excerpts. Observations and narrative remain attributed
to their author; this module never invents a solution or reruns an operation.
"""
import html
import json
import os
import re
from pathlib import Path
import subprocess
import sys


def redact(value):
    """Redact values without running text substitutions across JSON syntax."""
    import ctf_wp as wp
    if isinstance(value, dict):
        return {key: '[已遮盖]' if re.fullmatch(r'(?i)(password|passwd|token|api[_-]?key|authorization|cookie|secret|submission_flag)', str(key))
                else redact(item) for key, item in value.items()}
    if isinstance(value, list): return [redact(item) for item in value]
    if isinstance(value, str): return wp.scrub(value)
    return value


def ensure_task_context(case):
    """Upgrade an old Product session from saved inputs without replaying tools.

    Old long-lived clients do not pass the newly added intake fields. Import
    their actual saved task on export, with a new event timestamp, never by
    changing a protected historical session or inventing missing original data.
    """
    import ctf_wp as wp
    from ctf_wp_review import analyze
    folder = wp.case_dir(case)
    task_root = (wp.BASE / '.local/ctf-system/tasks').resolve()
    task_folder = (task_root / case).resolve()
    task_path = task_folder / 'task.json'
    if not task_folder.is_relative_to(task_root) or not task_path.is_file():
        return
    task = json.loads(task_path.read_text(encoding='utf-8'))
    if task.get('task_id') != case: raise ValueError('Task context case mismatch')
    with wp.locked(folder):
        context = analyze(folder, wp.verify(folder))['context']
    saved = {(x['name'], x['sha256']) for x in context['artifacts']}
    desired = {(x['name'], x['sha256']) for x in task.get('artifacts', [])}
    if context['description'] == task.get('description', '') and context.get('source') == (task.get('source') or '') and desired <= saved:
        return
    attachments = []
    for item in task.get('artifacts', []):
        path = (task_folder / item['relative_path']).resolve(strict=True)
        if not path.is_relative_to(task_folder) or wp.digest(path) != item['sha256']:
            raise ValueError('Original task input changed; cannot import WP context')
        attachments.append(dict(path=str(path), name=item['name'], sha256=item['sha256']))
    wp.intake(dict(case=case, description=task.get('description', ''), source=task.get('source') or '', attachments=attachments))


def excerpt(value, limit=3600, lines=48):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
    shown = '\n'.join(text.splitlines()[:lines])[:limit]
    return shown, len(shown) < len(text), len(text)


def output_view(response):
    """Avoid repeating JSON embedded in execution.stdout and data."""
    detail = response.get('result', response)
    if not isinstance(detail, dict):
        return detail
    view = {}
    for key in ('error', 'error_code', 'stderr', 'exit', 'returncode', 'exit_code', 'timed_out', 'truncated'):
        if key in detail:
            view[key] = detail[key]
    execution = detail.get('execution')
    if isinstance(execution, dict):
        execution = dict(execution)
        if 'data' in detail and isinstance(execution.get('stdout'), str):
            try:
                if json.loads(execution['stdout']) == detail['data']:
                    execution['stdout'] = '[与 data 相同的 JSON 已省略；完整原文见证据]'
            except (ValueError, TypeError):
                pass
        view['execution'] = execution
    for key, value in detail.items():
        if key not in view and key not in {'execution', 'evidence_artifacts'}:
            view[key] = value
    for key in ('error', 'error_code', 'evidence_error', 'wp_record_error'):
        if key in response:
            view['receipt_' + key] = response[key]
    return view


def model_for(a, folder, report, rows, metadata, verification, errors, pending):
    import ctf_wp as wp
    from ctf_wp_review import analyze
    quality = analyze(folder, rows)
    intake = [e for e in rows if e['kind'] == 'intake']
    context = quality.get('context', {})
    sections = {}
    observations = {}
    for event in rows:
        data = event['data']
        if event['kind'] == 'writeup_section':
            sections[data['section']] = dict(data, event_seq=event['seq'])
        if event['kind'] == 'note' and data['status'] == 'observed':
            observations.setdefault(data['source_step'], []).append(data['text'])
    blocks = []
    def add(kind, **kw):
        blocks.append(dict(type=kind, **kw))
    def para(text): add('paragraph', text=str(text))
    def heading(text, level=1): add('heading', level=level, text=text)
    def narrative(section, fallback):
        value = sections.get(section)
        para(value['text'] if value else fallback)
        if value and value.get('source_steps'):
            para('Agent 撰写说明，引用证据步骤：' + ', '.join(map(str, value['source_steps'])) + '。引用关联不等于记录器独立验证解释。')
    heading('题目信息')
    para('题型：%s　比赛：%s　题号：%s' % (metadata['category'], metadata['competition'], a['case']))
    para('解题状态：' + ('CTFd 已接受本次候选，见结果验证。' if verification else '尚无记录器识别的可信平台接受回执。'))
    para('正文已对常见凭据和 flag 作文本遮盖；私有原始证据可能含原值。图片像素未经自动去密。')
    heading('原题面', 2)
    para(context.get('description') or '未记录完整题面；请从原题补充，不能从输出反推原题。')
    if context.get('source'):
        para('题源：' + json.dumps(context['source'], ensure_ascii=False))
    artifacts = context.get('artifacts', [])
    if artifacts:
        add('table', headers=['原附件', '字节数', 'SHA256'], rows=[[x['name'], str(x['bytes']), x['sha256']] for x in artifacts])
        for item in artifacts:
            rel = 'evidence/' + item['path']
            if (report / rel).is_file():
                add('link', text='原附件 ' + item['name'], target=rel)
    heading('解题概述')
    para(a.get('summary') or sections.get('overview', {}).get('text') or '尚未补充解题概述。以下按真实记录排列，不能等同于已提炼的完整解法。')
    heading('分析思路')
    narrative('analysis', '尚未填写有证据引用的分析思路。')
    heading('解题方法')
    narrative('solution', '尚未填写有证据引用的解题主线。')
    heading('已验证')
    para('已核对时间线、检查点和所记录文件的 SHA256。该检查发现本地意外改动，不是第三方签名，也不证明推理正确。')
    heading('实际步骤')
    selected = {step for name, section in sections.items() if name != 'overview' for step in section.get('source_steps', [])}
    if selected:
        para('正文展示分析、解法、验证或复现章节引用的步骤；所有调用、失败和重试仍完整保存在技术附录及证据索引。')
    steps, evidence = [], []
    for event in rows:
        data, seq = event['data'], event['seq']
        for item in event.get('files', []):
            rel = 'evidence/' + item['path']
            evidence.append(dict(item, source_seq=seq, relative_path=rel if (report / rel).is_file() else None))
        if event['kind'] not in {'call', 'capture'}:
            continue
        block_start = len(blocks)
        number = len(steps) + 1
        heading('步骤 %d  %s' % (number, data.get('tool') or data.get('caption') or '画面采集'), 2)
        para('证据步骤 %d　时间 %s' % (seq, event['at']))
        entry = dict(display_no=number, source_seq=seq, observations=observations.get(seq, []), asset_refs=[])
        if event['kind'] == 'call':
            raw = json.loads((folder / event['files'][0]['path']).read_text(encoding='utf-8'))
            response = raw['response']
            state = '成功返回' if response.get('ok') is True else '失败（保留错误，不当作成功）'
            para('状态：%s；耗时：%s ms。' % (state, data.get('duration_ms')))
            para('行动目的：' + (data.get('purpose') or '未补充'))
            if data.get('expectation'): para('预期检查：' + data['expectation'] + '（预期不是已验证结论）')
            args = {k: v for k, v in raw['arguments'].items() if not k.startswith('wp_')}
            operation, op_cut, op_size = excerpt(args, 1800, 22)
            output, cut, size = excerpt(output_view(response))
            add('code', text='实际参数\n' + operation)
            add('code', text='实际返回预览\n' + output)
            if cut or op_cut: para('预览已截短；输出显示 %d / %d 字符。完整参数和回执见证据。' % (len(output), size))
            raw_rel = 'evidence/' + event['files'][0]['path']
            if not (report / raw_rel).is_file():
                raw_rel = 'redacted/%04d-call.json' % seq
                wp.write_json(report / raw_rel, redact(raw))
            add('link', text='完整调用证据 步骤 %d' % seq, target=raw_rel)
            para('原始证据 SHA256：' + event['files'][0]['sha256'])
            for key in ('task_health', 'warnings', 'error_code'):
                if key not in response: continue
                if key == 'task_health' and isinstance(response[key], dict):
                    health = response[key]
                    para('回执 task_health：累计调用 %s 次，失败 %s 次，工具耗时 %s 秒。%s' % (
                        health.get('calls', '?'), health.get('failed_calls', '?'), health.get('active_tool_seconds', '?'),
                        '提醒：' + json.dumps(health['warnings'], ensure_ascii=False) if health.get('warnings') else '无新增健康提醒。'))
                elif response[key]: para('回执提示 ' + key + '：' + excerpt(response[key], 1000, 12)[0])
            entry.update(tool=data.get('tool'), operation_id=data.get('operation_id'), status=state,
                         purpose=data.get('purpose'), duration_ms=data.get('duration_ms'),
                         operation_text=operation, output_excerpt=output, output_truncated=cut,
                         output_characters=size, evidence_ref=raw_rel,
                         receipt_metadata={key: response[key] for key in ('task_health', 'warnings', 'error_code') if key in response})
        for text in observations.get(seq, []): para('观察结论（Agent 引用此步骤）：' + text)
        if not observations.get(seq): para('观察结论：未补充。')
        for item in event.get('files', []):
            kind = item['kind']
            if kind in {'vm_screenshot', 'imported_image', 'windows_screenshot', 'browser_screenshot'}:
                target = report / 'images' / ('%04d-' % seq + Path(item['path']).name)
                if a.get('include_images') is True and target.is_file():
                    caption = data.get('caption') or item.get('source') or '实际采集画面'
                    add('image', path=target.relative_to(report).as_posix(), caption='证据步骤 %d；%s；%s' % (seq, kind, caption))
                    entry['asset_refs'].append(target.relative_to(report).as_posix())
                else:
                    para('图片证据已保存，本次未导出。')
        entry['in_main_text'] = not selected or seq in selected
        if not entry['in_main_text']:
            del blocks[block_start:]
        steps.append(entry)
    if not steps: para('尚无实际调用或截图记录。')
    heading('结果验证')
    for item in verification:
        para('CTFd 第 %s 题在证据步骤 %d 返回 correct，证明本次候选被平台接受；不自动证明所有分析解释正确。' % (item['challenge_id'], item['step']))
    if not verification: para('尚无可信平台接受回执。工具成功、格式匹配和 Agent 观察均不能代替答案判对。')
    narrative('validation', '尚未补充原程序对照或独立回放的验证说明。')
    heading('复现说明')
    narrative('reproduction', '请按实际证据中的原附件摘要、命令和脚本复现；尚未补充完整复现说明。')
    for subdir in ('scripts', 'requests', 'data', 'recordings'):
        for path in sorted((report / subdir).glob('*')):
            if path.is_file(): add('link', text=subdir + ' ' + path.name, target=path.relative_to(report).as_posix())
    heading('未验证')
    hypotheses = [e['data']['text'] for e in rows if e['kind'] == 'note' and e['data']['status'] == 'hypothesis']
    for text in hypotheses or ['没有单独记录的假设；记录器不判断推理正确性。']: para(text)
    heading('未完成')
    todos = [e['data']['text'] for e in rows if e['kind'] == 'note' and e['data']['status'] == 'todo']
    for text in todos: para(text)
    for item in quality.get('issues', []): para('稿件缺项：' + json.dumps(item, ensure_ascii=False))
    for item in errors: para('证据采集缺项：' + json.dumps(item, ensure_ascii=False) + '。原动作未为补证据重跑。')
    for item in pending: para('操作 ' + item['data']['operation_id'] + ' 已开始但没有完成回执；先检查原状态。')
    if not todos and not errors and not pending: para('未新增待办；仍须核对正文及比赛提交要求。')
    heading('复现与证据')
    para('日志渲染图属于非屏幕截图；实际截图、日志渲染和回放分别标注。完整技术记录包含失败与重试，不自动重演原操作。')
    add('link', text='完整技术记录和失败过程', target='technical.md')
    add('link', text='机器可读稿件和证据索引', target='report.json')
    if a.get('private_bundle') is True:
        para('本包包含私有原始记录。对外分享前审阅正文、原始文件和图片像素；请勿直接上传完整证据 ZIP 到公开仓库。')
    model = dict(schema_version=2, title=metadata['title'] + ' 解题记录', subtitle='CTF系统 中文 WP',
                 include_images=a.get('include_images') is True, challenge=dict(metadata, **context),
                 summary=a.get('summary') or '', steps=steps, sections=sections, verification=verification,
                 quality=quality, gaps=errors, pending_operations=[x['data'] for x in pending],
                 evidence=evidence, blocks=blocks, text_redaction='best_effort', images_reviewed=False)
    # A redacted structured model is shareable only after an actual review.
    return redact(model)


def write_markdown(model, path):
    import ctf_wp as wp
    lines = ['# ' + model['title'], '']
    for block in model['blocks']:
        kind = block['type']
        if kind == 'heading': lines.append('#' * (1 + block['level']) + ' ' + block['text'])
        elif kind == 'paragraph': lines.append(block['text'])
        elif kind == 'code': lines.append(wp.fence(block['text']))
        elif kind == 'image': lines.append('![%s](%s)' % (block['caption'].replace(']', ''), block['path']))
        elif kind == 'link': lines.append('[%s](%s)' % (block['text'].replace(']', ''), block['target']))
        elif kind == 'table':
            def row(xs): return '| ' + ' | '.join(str(x).replace('|', '\\|').replace('\n', ' ') for x in xs) + ' |'
            lines.extend([row(block['headers']), row(['---'] * len(block['headers']))])
            lines.extend(row(r) for r in block['rows'])
        lines.append('')
    path.write_text('\n'.join(lines), encoding='utf-8')


def write_html(model, path):
    esc = html.escape
    body = ['<h1>' + esc(model['title']) + '</h1>']
    for b in model['blocks']:
        k = b['type']
        if k == 'heading': body.append('<h%d>%s</h%d>' % (b['level'] + 1, esc(b['text']), b['level'] + 1))
        elif k == 'paragraph': body.append('<p>' + esc(b['text']).replace('\n', '<br>') + '</p>')
        elif k == 'code': body.append('<pre>' + esc(b['text']) + '</pre>')
        elif k == 'image': body.append('<figure><img src="%s"><figcaption>%s</figcaption></figure>' % (esc(b['path'], quote=True), esc(b['caption'])))
        elif k == 'link': body.append('<p><a href="%s">%s</a></p>' % (esc(b['target'], quote=True), esc(b['text'])))
        elif k == 'table':
            body.append('<table><thead><tr>' + ''.join('<th>' + esc(str(x)) + '</th>' for x in b['headers']) + '</tr></thead><tbody>')
            body.extend('<tr>' + ''.join('<td>' + esc(str(x)) + '</td>' for x in row) + '</tr>' for row in b['rows'])
            body.append('</tbody></table>')
    path.write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>' + esc(model['title']) + '</title><style>body{font:16px/1.7 system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 24px;color:#18212b}h1,h2,h3{line-height:1.35}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:16px}table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{border:1px solid #ccd2d9;padding:8px;overflow-wrap:anywhere}img{max-width:100%;height:auto}figure{margin:24px 0}figcaption{font-size:14px;color:#4a5663}@media print{body{max-width:none;margin:0}h2,h3{break-after:avoid}pre,figure{break-inside:auto}}</style><body>' + '\n'.join(body) + '</body></html>', encoding='utf-8')


def extra_formats(a, report):
    import ctf_wp as wp
    config = wp.BASE / 'config' / 'ctf_wp.local.json'
    cfg = json.loads(config.read_text(encoding='utf-8-sig')) if config.is_file() else {}
    formats = a.get('formats', cfg.get('formats', ['docx', 'pdf']))
    if not isinstance(formats, list) or any(x not in {'docx', 'pdf'} for x in formats):
        raise ValueError('formats 只能为 docx/pdf 数组，可传 [] 只生成 Markdown/HTML')
    if not formats: return {'ok': True, 'formats': {}}
    if cfg.get('template', 'plain-v1') not in {'plain-v1', 'ctf-wp-letter/1.0.0'}:
        return {'ok': False, 'formats': {x: {'ok': False, 'error': 'Unsupported WP template; only plain-v1 is available'} for x in formats}}
    python = os.environ.get('CTF_WP_EXPORT_PYTHON') or cfg.get('export_python') or sys.executable
    try:
        proc = subprocess.run([python, '-X', 'utf8', str(Path(__file__).with_name('ctf_wp_formats.py')),
            '--model', str(report / 'report.json'), '--output', str(report), '--formats', ','.join(formats)],
            capture_output=True, text=True, encoding='utf-8', timeout=180,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        value = json.loads(proc.stdout)
        if not isinstance(value.get('formats'), dict): raise ValueError('Invalid format exporter receipt')
        for fmt in formats:
            if fmt not in value['formats']:
                value['formats'][fmt] = {'ok': False, 'error': value.get('error') or 'Renderer did not return the requested format'}
        value['ok'] = proc.returncode == 0 and all(value['formats'][fmt].get('ok') is True for fmt in formats)
        return value
    except Exception as exc:
        return {'ok': False, 'formats': {x: {'ok': False, 'error': str(exc)} for x in formats}}
