"""CTF-first screenshot requirements, evaluated over saved evidence only."""
import json
import re

VERSION = 'ctf-real-capture/20261030.3'
IMAGE_KINDS = frozenset({'vm_screenshot', 'imported_image', 'windows_screenshot', 'browser_screenshot', 'terminal_screenshot'})
FLAG = re.compile(r'(?i)\b(?:flag|ctf|gwht|qwb|pwn\.college)\{[^}\n]*\}')


def contract():
    return {'version': VERSION, 'primary_goal': '解出并验证本题 flag',
            'redteam_role': 'fully-integrated',
            'modules': {
                'solving': {'goal': '融合传统CTF与破甲能力，提高解出并验证flag的能力',
                            'capability_policy': 'fully-integrated',
                            'selection': '按本题证据选择有效工具、POC、工具链或角色协作；破甲能力可以承担主力，不设辅助位或仅内网可用限制。',
                            'routing_hints_are_allowlists': False},
                'writeup': {'goal': '同步留证，以实际解题过程和证据写出可复现的WP',
                            'writing_policy': 'evidence-narrative/20261030.1',
                            'narrative': '沿本题实际解题路线写：看到了什么线索、据此做了什么、原始结果是什么、这个结果为何支持下一步。每个关键判断引用实际source_steps，截图紧跟对应操作并解释可见内容。',
                            'style': '用简洁自然的中文写具体事实；不堆工具调用状态、固定总结或空泛的首先其次综上所述；不编造思考过程、操作、输出或成功经历。',
                            'format': 'Word正文使用正常标题和段落，不保留Markdown的井号、星号和围栏；命令、脚本、请求及输出中的技术符号保持原样。',
                            'proof': '保留关键输入、payload或脚本、原始输出和真实截图；输出节选必须明确标注并能回查完整原件。取得候选flag、本地验证与平台判对分别说明。',
                            'layout_review': '交付Word前渲染为逐页图片并查看全部页面，检查中文、代码、表格、截图清晰度、图注和分页；修正后重新渲染。导出成功或结构检查不等于排版已验收。',
                            'capture_policy': 'at_key_milestones',
                            'capture_when': ['题面或关键线索页面', '支撑关键判断的操作或调试画面', 'flag结果或验证回执'],
                            'selection': '选择必要、合适、可读的真实截图；复用已采原图，一张图覆盖过程与结果时可共同引用，不为凑数量重复截图。'}},
            'writeup_sections': [
                'overview', 'analysis', 'solution', 'validation', 'reproduction'],
            'screenshots': '关键解题过程同步保存真实截图；取得 flag 后保存关联结果步骤的真实截图；正文嵌入并注明来源与步骤。',
            'capture_tool': 'wp_capture(mode=kali_vm|windows_window|file, source_step=实际调用步骤, stage=process|result|process_and_result)',
            'automatic_capture': '浏览器/调试器采集当前实际画面。SSH后台执行没有可截图的终端；需截图的命令可用kali_terminal_record(capture_window=true)，在隔离X11真实xterm中执行一次并采集原窗口，不能事后套模板或打印日志冒充。',
            'pixel_review': '用图像查看工具打开原图，检查可读的实际题面/工具界面/命令及输出，核对source_step，再用wp_capture_review绑定原图SHA256记录。锁屏、空桌面、日志模板和为补图复刻的页面须rejected。',
            'failure_policy': '截图失败如实留缺项，继续保存解题结果；不重放有副作用的动作，不把日志渲染或回放冒充截图。',
            'completion_policy': '截图或正文缺项只能导出明确标记的草稿；平台验证与稿件完整性分别记录。'}


def flags_in(value):
    # Match actual strings, not JSON-escaped text: "\\nflag{...}" would lose
    # the word boundary when regex is run over a serialized JSON envelope.
    pending, found = [value], []
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            for flag in FLAG.findall(item):
                if flag not in found:
                    found.append(flag)
        elif isinstance(item, dict):
            pending.extend(reversed(list(item.values())))
        elif isinstance(item, (list, tuple)):
            pending.extend(reversed(item))
    return found


def has_flag(response):
    return bool(flags_in(response))


def inspect(folder, rows, platform_verified=False):
    flag_steps = set()
    for event in rows:
        if event['kind'] != 'call':
            continue
        raw_file = next((x for x in event.get('files', []) if x.get('kind') == 'tool_output'), None)
        if raw_file:
            raw = json.loads((folder / raw_file['path']).read_text(encoding='utf-8'))
            if has_flag(raw.get('response', {})):
                flag_steps.add(event['seq'])
    from ctf_wp_capture_review import eligible
    candidates = eligible(folder, rows)
    approved = {(x['step'], x['path']): x for x in candidates if x['accepted']}
    images = []
    for event in rows:
        if event['kind'] not in {'call', 'capture'}:
            continue
        data = event['data']
        source_step = data.get('source_step') or event['seq']
        for item in event.get('files', []):
            if item.get('kind') not in IMAGE_KINDS or (event['seq'], item['path']) not in approved:
                continue
            stage = (approved[(event['seq'], item['path'])]['review'].get('stage')
                     or data.get('stage') or ('result' if source_step in flag_steps else 'process'))
            images.append({'step': event['seq'], 'source_step': source_step,
                           'stage': stage, 'kind': item['kind'], 'path': item['path'], 'sha256': item['sha256'],
                           'pixel_review': approved[(event['seq'], item['path'])]['review'],
                           'caption': data.get('caption') or item.get('source') or '实际采集画面'})
    process = [x for x in images if x['stage'] in {'process', 'process_and_result'}]
    result = [x for x in images if x['stage'] in {'result', 'process_and_result'}]
    issues = []
    if not process:
        issues.append({'code': 'missing_process_screenshot', 'severity': 'needs_attention',
                       'message': '缺少已查看原图并核验内容及步骤关系的真实过程截图；先查看原图，再用wp_capture_review记录。锁屏、空桌面、日志渲染和复刻页面不计。', 'steps': []})
    result_required = bool(flag_steps or platform_verified)
    if result_required and not result:
        issues.append({'code': 'missing_result_screenshot', 'severity': 'needs_attention',
                       'message': '已取得 flag 或正确回执，但缺少关联结果步骤的真实截图；用 wp_capture(stage=result, source_step=...) 保存当前结果画面。',
                       'steps': sorted(flag_steps)})
    return {'version': VERSION, 'images': images, 'process_count': len(process),
            'result_count': len(result), 'result_required': result_required,
            'flag_steps': sorted(flag_steps), 'complete': not issues, 'issues': issues,
            'pixel_content_verified': False, 'pixel_review_recorded': bool(images),
            'candidates': candidates, 'excluded_count': sum(not x['accepted'] for x in candidates)}


def guidance(tool, response):
    step = (response.get('wp_record') or {}).get('step')
    result = has_flag(response.get('result', {}))
    visual = tool in {'web_browser_session', 'web_browser_capture', 'win_debug_call',
                      'kali_debug_session', 'kali_terminal_record'}
    return {'primary_goal': '解出并验证本题 flag', 'source_step': step,
            'capture_policy': 'at_key_milestones', 'capture_recommended': result or visual,
            'stage': 'result' if result else 'process',
            'next': ('及时采集真实工具当前画面并关联source_step；打开原图确认内容，再用wp_capture_review记录。SSH后台输出不是可见终端；锁屏、空桌面、日志模板、事后复刻页不可作为截图。一张原图确实覆盖过程与结果时可共同引用。'
                     if result or visual else
                     '保留本次原始输出；只在出现关键、合适的可见页面时截图，不为状态查询、记账或后台计算凑图。')}
