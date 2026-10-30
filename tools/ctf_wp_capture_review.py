"""Append pixel-review decisions bound to an existing frame and source call.

This records the reviewer's observations; it is not an authenticity detector.
Hashes prove preservation, not that pixels show the claimed application/action.
"""
IMAGE_KINDS = {'vm_screenshot', 'imported_image', 'windows_screenshot', 'browser_screenshot', 'terminal_screenshot'}
ORIGINS = {'live_screen', 'live_browser', 'rendered_log', 'reconstructed', 'unknown'}


def frame_check(path):
    try:
        from PIL import Image, ImageStat
        with Image.open(path) as image:
            image.load()
            width, height = image.size
            if width < 200 or height < 100:
                return '图像过小，无法作为可读的操作截图'
            if max(ImageStat.Stat(image.convert('RGB')).var) < 0.5:
                return '空白或近乎纯色画面'
    except Exception as exc:
        return '图片像素检查失败：' + str(exc)
    return None


def review(a):
    import ctf_wp as wp
    folder = wp.case_dir(a['case'])
    with wp.locked(folder):
        rows = wp.verify(folder)
        step = a.get('image_step')
        if type(step) is not int or not 1 <= step <= len(rows):
            raise ValueError('image_step 必须引用已保存截图的步骤')
        event = rows[step - 1]
        item = next((f for f in event.get('files', [])
                     if f.get('kind') in IMAGE_KINDS and f.get('sha256') == a.get('image_sha256')), None)
        if item is None:
            raise ValueError('该步骤没有与 image_sha256 匹配的截图')
        verdict, origin = a.get('verdict'), a.get('capture_origin', 'unknown')
        stage = a.get('stage')
        if stage is not None and stage not in {'process', 'result', 'process_and_result'}:
            raise ValueError('无效的截图用途阶段')
        if verdict not in {'accepted', 'rejected'} or origin not in ORIGINS:
            raise ValueError('无效的截图核验结论或来源类型')
        observed = str(a.get('observed_content') or '').strip()
        reason = str(a.get('reason') or '').strip()
        if len(observed) < 8 or len(reason) < 8 or max(len(observed), len(reason)) > 4000:
            raise ValueError('observed_content 和 reason 须具体说明所见内容及其与解题步骤的关系（8..4000字）')
        source_step = event.get('data', {}).get('source_step') or event['seq']
        if verdict == 'accepted':
            if origin not in {'live_screen', 'live_browser'}:
                raise ValueError('日志渲染、复刻画面和未知来源不能当作真实截图')
            if type(source_step) is not int or rows[source_step - 1]['kind'] != 'call':
                raise ValueError('有效截图必须关联本题实际工具调用；不能只引用一张图片')
            error = frame_check(folder / item['path'])
            if error:
                raise ValueError(error)
        saved = wp.append(folder, 'image_review', {
            'image_step': step, 'image_sha256': item['sha256'], 'image_path': item['path'],
            'source_step': source_step, 'verdict': verdict, 'capture_origin': origin,
            'stage': stage,
            'observed_content': observed, 'reason': reason,
            'scope': 'reviewer inspected pixels and relevance; no automatic authenticity certification'})
    return {'case': a['case'], 'step': saved['seq'], 'image_step': step,
            'image_sha256': item['sha256'], 'verdict': verdict}


def eligible(folder, rows):
    decisions = {}
    for event in rows:
        if event['kind'] == 'image_review':
            data = event['data']
            decisions[(data.get('image_step'), data.get('image_sha256'))] = data
    found = []
    for event in rows:
        if event['kind'] not in {'call', 'capture'}:
            continue
        for item in event.get('files', []):
            if item.get('kind') not in IMAGE_KINDS:
                continue
            decision = decisions.get((event['seq'], item.get('sha256')), {})
            error = frame_check(folder / item['path'])
            accepted = (decision.get('verdict') == 'accepted'
                        and decision.get('capture_origin') in {'live_screen', 'live_browser'}
                        and decision.get('image_path') == item['path'] and not error)
            found.append({'step': event['seq'], 'path': item['path'], 'sha256': item.get('sha256'),
                          'accepted': accepted, 'review': decision,
                          'exclusion': error or (decision.get('reason') if decision else '尚未查看原图并核验与解题步骤的关系')})
    return found


TOOLS = {'wp_capture_review': (review,
    '查看原图后记录内容及步骤关联核验；锁屏、桌面、日志渲染或复刻画面不得接受；摘要绑定原图，核验不能认证flag',
    {'type': 'object', 'properties': {
        'case': {'type': 'string'}, 'image_step': {'type': 'integer', 'minimum': 1},
        'image_sha256': {'type': 'string', 'pattern': '^[a-f0-9]{64}$'},
        'verdict': {'type': 'string', 'enum': ['accepted', 'rejected']},
        'capture_origin': {'type': 'string', 'enum': sorted(ORIGINS)},
        'stage': {'type': 'string', 'enum': ['process', 'result', 'process_and_result']},
        'observed_content': {'type': 'string'}, 'reason': {'type': 'string'}},
     'required': ['case', 'image_step', 'image_sha256', 'verdict', 'capture_origin', 'observed_content', 'reason'],
     'additionalProperties': False})}
