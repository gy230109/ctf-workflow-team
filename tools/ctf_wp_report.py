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


def inline_text(value):
    """Remove prose markup, preserving literal inline code and technical symbols."""
    literals = []
    def protect(match):
        literals.append(match.group(2))
        return '\ue000%d\ue001' % (len(literals) - 1)
    text = re.sub(r'(`+)([^\n]*?)\1', protect, str(value))
    text = re.sub(r'!?\[([^\]\n]+)\]\(([^\n)]+)\)', r'\1（\2）', text)
    for pattern in (r'\*\*(\S(?:.*?\S)?)\*\*', r'(?<!\w)__(\S(?:.*?\S)?)__(?!\w)',
                    r'(?<![\w*])\*(\S(?:.*?\S)?)\*(?![\w*])'):
        text = re.sub(pattern, r'\1', text)
    for index, literal in enumerate(literals):
        text = text.replace('\ue000%d\ue001' % index, literal)
    return text


def prose_blocks(value):
    """Parse a small, inert Markdown subset into the shared report model.

    Never load images/URLs supplied in prose. Only the reviewed evidence pipeline
    may create image blocks. Code fences bypass prose cleanup byte for byte.
    """
    lines = str(value).splitlines()
    blocks, paragraph = [], []
    def flush():
        if paragraph:
            blocks.append(dict(type='paragraph', text=inline_text('\n'.join(paragraph))))
            paragraph.clear()
    def cells(line):
        return [inline_text(cell.strip().replace('\\|', '|'))
                for cell in re.split(r'(?<!\\)\|', line.strip().strip('|'))]
    index = 0
    while index < len(lines):
        line = lines[index]
        fence = re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            flush()
            marker, code = fence.group(1), []
            index += 1
            while index < len(lines):
                if re.fullmatch(r' {0,3}' + re.escape(marker[0]) + '{%d,} *' % len(marker), lines[index]):
                    index += 1
                    break
                code.append(lines[index])
                index += 1
            blocks.append(dict(type='code', text='\n'.join(code)))
            continue
        if not line.strip() or re.fullmatch(r'\s*(?:-{3,}|\*{3,}|_{3,})\s*', line):
            flush()
        elif re.match(r'^ {0,3}#{1,6}\s+\S', line):
            flush()
            title = re.sub(r'^ {0,3}#{1,6}\s+', '', line)
            title = re.sub(r'\s+#+\s*$', '', title)
            blocks.append(dict(type='heading', level=2, text=inline_text(title)))
        elif (index + 1 < len(lines) and '|' in line
              and re.fullmatch(r'\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*', lines[index + 1])
              and 1 < len(cells(line)) <= 8):
            flush()
            headers, rows = cells(line), []
            index += 2
            while index < len(lines) and '|' in lines[index] and len(cells(lines[index])) == len(headers):
                rows.append(cells(lines[index]))
                index += 1
            blocks.append(dict(type='table', headers=headers, rows=rows))
            continue
        elif re.match(r'^\s*(?:[-*+]\s+|>\s?)', line):
            flush()
            blocks.append(dict(type='paragraph', text=inline_text(re.sub(r'^\s*(?:[-*+]\s+|>\s?)', '', line))))
        else:
            paragraph.append(line)
        index += 1
    flush()
    return blocks


def redact(value, keep_flags=False):
    """Redact values without running text substitutions across JSON syntax.

    keep_flags=True preserves flag literals (needed by shareable write-ups) while
    still hiding credentials, keys and cookies.
    """
    import ctf_wp as wp
    if isinstance(value, dict):
        return {key: '[已遮盖]' if re.fullmatch(r'(?i)(password|passwd|token|api[_-]?key|authorization|cookie|secret|submission_flag)', str(key))
                else redact(item, keep_flags) for key, item in value.items()}
    if isinstance(value, list): return [redact(item, keep_flags) for item in value]
    if isinstance(value, str):
        if not keep_flags: return wp.scrub(value)
        marks = []
        def hold(match):
            marks.append(match.group(0))
            return '\x00FLAG%d\x00' % (len(marks) - 1)
        out = wp.scrub(re.sub(r'(?i)\b(?:flag|ctf|gwht|qwb|pwn\.college)\{[^}\n]*\}', hold, value))
        for index, flag in enumerate(marks): out = out.replace('\x00FLAG%d\x00' % index, flag)
        return out
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


def output_text(value):
    """Display actual stdout/stderr as lines, never as JSON-escaped strings."""
    if not isinstance(value, dict):
        return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    parts = []
    for key, item in value.items():
        if key in {'stdout', 'stderr'} and isinstance(item, str):
            if item: parts.append(key + ':\n' + item.rstrip('\n'))
        elif key == 'execution' and isinstance(item, dict):
            parts.append('execution:\n' + output_text(item))
        else:
            parts.append(key + ': ' + json.dumps(item, ensure_ascii=False))
    return '\n'.join(parts)


def brief(value, limit=110):
    """One-line rendering of an argument for the narrative step block."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = text.replace('\n', ' ')
    return text if len(text) <= limit else text[:limit] + '…'


def observation_text(text):
    """Drop recorder bookkeeping notes; keep notes that describe the target.

    Some notes quote a WP tool call verbatim to explain why a later export or
    section write failed. That is process bookkeeping, not a solving
    observation, so it does not belong in the main narrative.
    """
    text = str(text).strip()
    if re.match(r'(?i)^(?:ctf|wp)_[a-z_]+\s*[（(]', text):
        return ''
    return text


def output_view(response):
    """Avoid repeating JSON embedded in execution.stdout and data."""
    detail = response.get('result', response)
    if not isinstance(detail, dict):
        return detail
    view = {}
    for key in ('error', 'error_code', 'stderr', 'exit', 'returncode', 'exit_code', 'timed_out', 'truncated'):
        if key in detail and (detail[key] not in ('', None, False) or key in {'returncode', 'exit_code'}):
            view[key] = detail[key]
    execution = detail.get('execution')
    if isinstance(execution, dict):
        execution = {key: value for key, value in execution.items()
                     if key in {'returncode', 'exit_code', 'timed_out', 'stdout', 'stderr', 'truncated'}
                     and (value not in ('', False, None) or key in {'returncode', 'exit_code'})}
        if 'data' in detail and isinstance(execution.get('stdout'), str):
            try:
                if json.loads(execution['stdout']) == detail['data']:
                    execution['stdout'] = '[与 data 相同的 JSON 已省略；完整原文见证据]'
            except (ValueError, TypeError):
                pass
        view['execution'] = execution
    for key, value in detail.items():
        if key not in view and key not in {'execution', 'evidence_artifacts'}:
            if 'run_id' in detail and key in {'run_id', 'case_root', 'cwd', 'command', 'timeout_seconds',
                                              'started_at_utc', 'duration_seconds', 'stdout_bytes', 'stderr_bytes',
                                              'output_truncated', 'guest_log', 'guest_ip', 'transport_seconds'}:
                continue
            if key in {'bridge_exit', 'case', 'on', 'transport', 'input_sha256', 'upload_verified'}:
                continue
            if value in ('', False, None) and key not in {'returncode', 'exit_code', 'stdout'}: continue
            view[key] = value
    for key in ('error', 'error_code', 'evidence_error', 'wp_record_error'):
        if key in response:
            view['receipt_' + key] = response[key]
    return view


def model_for(a, folder, report, rows, metadata, verification, errors, pending):
    import ctf_wp as wp
    from ctf_wp_policy import has_flag, flags_in
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
    def para(text): blocks.extend(prose_blocks(text))
    def heading(text, level=1): add('heading', level=level, text=text)
    def narrative(section, fallback):
        value = sections.get(section)
        if value:
            para(value['text'])
            if value.get('source_steps'):
                para('证据记录：' + '、'.join('步骤 %d' % step for step in value['source_steps']) + '。')
            return
        para(fallback)
    heading('题目信息')
    para('题型：%s　比赛：%s　题号：%s' % (metadata['category'], metadata['competition'], a['case']))
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
    para(a.get('summary') or sections.get('overview', {}).get('text') or '未填写概述；以下按真实记录排列。')
    heading('分析思路')
    narrative('analysis', '未记录分析思路；可在执行时补 wp_section(section=analysis)。')
    heading('解题方法')
    narrative('solution', '未记录解题主线；可在执行时补 wp_section(section=solution)。')
    heading('解题过程')
    selected = {step for name, section in sections.items() if name != 'overview' for step in section.get('source_steps', [])}
    key_steps, linked_captures = set(), {}
    call_steps = {event['seq'] for event in rows if event['kind'] == 'call'}
    for event in rows:
        if event['kind'] == 'capture':
            key_steps.add(event['seq'])
            source = event['data'].get('source_step')
            if source in call_steps:
                key_steps.add(source)
                linked_captures.setdefault(source, []).append(event)
        elif event['kind'] == 'call':
            try:
                raw = json.loads((folder / event['files'][0]['path']).read_text(encoding='utf-8'))
            except (OSError, ValueError, IndexError):
                continue
            if has_flag(raw.get('response', {})):
                key_steps.add(event['seq'])
    steps, evidence = [], []
    displayed, figure_number = 0, 0
    for event in rows:
        data, seq = event['data'], event['seq']
        for item in event.get('files', []):
            rel = 'evidence/' + item['path']
            evidence.append(dict(item, source_seq=seq, relative_path=rel if (report / rel).is_file() else None))
        if event['kind'] not in {'call', 'capture'}:
            continue
        in_main = not selected or seq in selected or seq in key_steps
        attached_capture = event['kind'] == 'capture' and data.get('source_step') in linked_captures
        if attached_capture:
            in_main = False
        number = None
        if in_main:
            displayed += 1
            number = displayed
        block_start = len(blocks)
        if in_main:
            action = data.get('purpose') or data.get('caption') or data.get('tool') or '采集关键画面'
            heading('第 %d 步　%s' % (number, inline_text(brief(action, 90))), 2)
        shown_observations = [text for text in observations.get(seq, []) if observation_text(text)]
        entry = dict(display_no=number, source_seq=seq, observations=shown_observations, asset_refs=[])
        if event['kind'] == 'call':
            raw = json.loads((folder / event['files'][0]['path']).read_text(encoding='utf-8'))
            response = raw['response']
            state = '成功返回' if response.get('ok') is True else '失败（保留错误，不当作成功）'
            if response.get('ok') is not True:
                para('本次调用失败，错误输出保留如下。')
            args = {k: v for k, v in raw['arguments'].items() if not k.startswith('wp_')}
            operation = json.dumps(dict(tool=data.get('tool'), arguments={k: v for k, v in args.items()
                                   if k not in {'case', 'wp_case'}}), ensure_ascii=False, indent=2)
            view = output_view(response)
            symbols = ((view.get('data') or {}).get('symbols') if isinstance(view, dict) else None)
            if isinstance(symbols, dict):
                view = dict(view, data=dict(view['data'],
                    symbols={k: v for k, v in symbols.items() if k.startswith('got.')}))
            output, cut, size = excerpt(output_text(view), 1400, 22)
            # Preserve code's actual line breaks instead of printing a JSON
            # string containing literal backslash-n and escaped path slashes.
            display_operation = args['code'] if data.get('tool') == 'py_run' and isinstance(args.get('code'), str) else operation
            if display_operation != operation: para('实际执行的 Python 代码')
            shown_operation, args_cut, _ = excerpt(display_operation, 2600, 42)
            add('code', text=shown_operation)
            if args_cut: para('以上参数为节选，完整输入见本步原始记录。')
            add('code', text=output)
            if cut: para('以上输出为节选，完整输出见本步原始记录。')
            raw_rel = 'evidence/' + event['files'][0]['path']
            if not (report / raw_rel).is_file():
                raw_rel = 'redacted/%04d-call.json' % seq
                wp.write_json(report / raw_rel, redact(raw))
            add('link', text='原始记录 步骤 %d' % seq, target=raw_rel)
            receipt = {key: response[key] for key in ('task_health', 'warnings', 'error_code') if key in response}
            if receipt and response.get('ok') is not True: add('code', text=json.dumps(receipt, ensure_ascii=False))
            entry.update(tool=data.get('tool'), operation_id=data.get('operation_id'), status=state,
                         purpose=data.get('purpose'), duration_ms=data.get('duration_ms'),
                         operation_text=operation, output_excerpt=output, output_truncated=cut,
                         output_characters=size, evidence_ref=raw_rel,
                         receipt_metadata={key: response[key] for key in ('task_health', 'warnings', 'error_code') if key in response})
        for text in shown_observations: para(text)
        for capture_event in linked_captures.get(seq, []):
            for text in observations.get(capture_event['seq'], []):
                if observation_text(text): para(text)
        image_events = [event] + linked_captures.get(seq, [])
        for image_event, item in [(image_event, item) for image_event in image_events for item in image_event.get('files', [])]:
            kind = item['kind']
            if kind in {'vm_screenshot', 'imported_image', 'windows_screenshot', 'browser_screenshot', 'terminal_screenshot'}:
                image_seq, image_data = image_event['seq'], image_event['data']
                target = report / 'images' / ('%04d-' % image_seq + Path(item['path']).name)
                if a.get('include_images') is True and target.is_file():
                    caption = image_data.get('caption') or item.get('source') or '实际采集画面'
                    origin = image_data.get('source_step') or image_seq
                    if in_main: figure_number += 1
                    add('image', path=target.relative_to(report).as_posix(),
                        caption='图 %d（原始记录 %d，来源步骤 %d）：%s' % (figure_number, image_seq, origin, caption))
                    entry['asset_refs'].append(target.relative_to(report).as_posix())
                else:
                    para('图片证据已保存，本次未导出。')
        entry['in_main_text'] = in_main
        if not entry['in_main_text']:
            del blocks[block_start:]
        steps.append(entry)
    if not steps: para('尚无实际调用或截图记录。')
    step_no = {entry['source_seq']: entry['display_no'] for entry in steps if entry['display_no']}
    flags, failures = [], []
    for event in rows:
        if event['kind'] != 'call': continue
        try:
            raw = json.loads((folder / event['files'][0]['path']).read_text(encoding='utf-8'))
        except (OSError, ValueError, IndexError):
            continue
        response = raw.get('response', {})
        for flag in flags_in(response):
            if flag not in flags: flags.append(flag)
        if response.get('ok') is not True:
            failures.append((event['seq'], event['data'].get('tool') or '未知工具',
                             str(response.get('error') or response.get('error_code') or '未返回原因')[:180]))
    heading('最终结果')
    if flags:
        for flag in flags: add('code', text='flag：' + flag)
        para('flag 取自工具的真实回显，未经改写。')
    else:
        para('解题结果以原始回显和下节验证记录为依据。')
    closing = None
    result_images = quality['screenshot_evidence']['images']
    result_images = [item for item in result_images if item['stage'] in {'result', 'process_and_result'}]
    if result_images:
        image = result_images[-1]
        closing = (image['step'], image, image['caption'])
    if closing and a.get('include_images') is True:
        seq, item, caption = closing
        target = report / 'images' / ('%04d-' % seq + Path(item['path']).name)
        if target.is_file() and not any(block['type'] == 'image' and block['path'] == target.relative_to(report).as_posix() for block in blocks):
            figure_number += 1
            tail = '；' + caption if caption else ''
            label = step_no.get(seq)
            add('image', path=target.relative_to(report).as_posix(),
                caption=('图 %d 结果截图' % figure_number) + tail)
    elif flags:
        if not result_images:
            para('已记录 flag 回显，但缺少关联结果步骤的截图；本稿保留截图缺项。')
    heading('结果验证')
    narrative('validation', '未填写结果验证说明；以下仅列实际平台回执。')
    if verification:
        for item in verification:
            para('CTFd 第 %s 题在证据步骤 %d 返回 correct。' % (item['challenge_id'], item['step']))
    else:
        para('已保存原始工具输出；尚无真实平台正确回执。')
    document_gaps = [item['message'] for item in quality['issues'] if item['code'] != 'answer_not_verified']
    if document_gaps: heading('证据缺项')
    for message in document_gaps: para(message)
    heading('复现说明')
    narrative('reproduction', '未记录复现说明；请按证据中的原附件摘要与命令复现。')
    names = {(item['source_seq'], item.get('kind')): item.get('original_name')
             for item in evidence if item.get('original_name')}
    for subdir, label in (('scripts', '脚本'), ('requests', '请求文件'), ('data', '数据导出'), ('recordings', '过程回放')):
        for path in sorted((report / subdir).glob('*')):
            if not path.is_file(): continue
            match = re.match(r'(\d+)-', path.name)
            seq = int(match.group(1)) if match else None
            original = next((name for (source, _), name in names.items() if source == seq), None)
            add('link', text='%s %s' % (label, original or path.name), target=path.relative_to(report).as_posix())
    if failures:
        heading('踩坑与排障')
        for seq, tool, reason in failures:
            show = step_no.get(seq)
            para((('第 %d 步 ' % show) if show else '') + '%s 报错：%s' % (tool, reason))
    hypotheses = [e['data']['text'] for e in rows if e['kind'] == 'note' and e['data']['status'] == 'hypothesis']
    if hypotheses:
        heading('待验证的猜测')
        for text in hypotheses: para(text)
    heading('原始材料')
    add('link', text='完整技术记录（含失败与重试）', target='technical.md')
    if a.get('include_images') is not True:
        # 口径统一：只有存在已核验的真实截图却未嵌入时才算"图片缺项"；
        # 本题本来就没有可嵌入图片时不重复压低 screenshots_complete，
        # 避免 wp_status 与 wp_build 对同一时间线给出矛盾的完成度。
        has_reviewed = bool(quality['screenshot_evidence']['images'])
        quality['quality']['document_complete'] = False
        if has_reviewed:
            quality['quality']['screenshots_complete'] = False
        quality['issues'].append({'code':'images_not_included', 'severity':'needs_attention',
                                 'message':('本次未嵌入真实截图（存在 %d 张已核验图片），仅可作为草稿。' % len(quality['screenshot_evidence']['images']))
                                 if has_reviewed else '本次未嵌入图片；本题暂无已核验截图，按截图缺项口径处理。','steps':[]})
        quality['submission_ready'] = False
        quality['status'] = 'draft'
    suffix = ' 解题记录' if quality['quality']['document_complete'] else ' 解题记录（草稿·待补证据）'
    model = dict(schema_version=2, title=metadata['title'] + suffix, subtitle='',
                 include_images=a.get('include_images') is True, challenge=dict(metadata, **context),
                 summary=a.get('summary') or '', steps=steps, sections=sections, verification=verification,
                 quality=quality, gaps=errors, pending_operations=[x['data'] for x in pending],
                 evidence=evidence, blocks=blocks, text_redaction='best_effort', images_reviewed=False,
                 flags_exposed=a.get('expose_flag') is True)
    # A redacted structured model is shareable only after an actual review.
    return redact(model, a.get('expose_flag') is True)


def write_markdown(model, path):
    import ctf_wp as wp
    lines = ['# ' + model['title'], '']
    for block in model['blocks']:
        kind = block['type']
        if kind == 'heading': lines.append('#' * (1 + block['level']) + ' ' + block['text'])
        elif kind == 'paragraph': lines.append(block['text'])
        elif kind == 'code': lines.append(wp.fence(block['text'], model.get('flags_exposed') is True))
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
