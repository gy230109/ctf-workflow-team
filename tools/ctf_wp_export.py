"""Team CTF workflow component. See README.md for configuration and verified scope."""
import json
from pathlib import Path
import shutil
import uuid
from datetime import datetime, timezone

IMAGE_KINDS = {'vm_screenshot','imported_image','windows_screenshot','browser_screenshot'}
REPLAY_KINDS = {'browser_trace','terminal_recording'}


def build(a):
    import ctf_wp as wp
    folder = wp.case_dir(a['case'])
    if not wp.exists(a['case']): raise ValueError('先 wp_init')
    include_images = a.get('include_images') is True
    private = a.get('private_bundle') is True
    with wp.locked(folder):
        rows = wp.verify(folder)
        metadata = json.loads((folder/'session.json').read_text(encoding='utf-8'))
        report = folder/'reports'/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-')+uuid.uuid4().hex[:8])
        (report/'images').mkdir(parents=True)
        generated, captures, replays, errors = [], 0, 0, []
        completed = {e['data'].get('operation_id') for e in rows if e['kind']=='call'}
        pending = [e for e in rows if e['kind']=='operation_started' and e['data']['operation_id'] not in completed]
        notes = {}
        for e in rows:
            if e['kind']=='note' and e['data']['status']=='observed': notes.setdefault(e['data']['source_step'],[]).append(e['data']['text'])
        verification = []
        for e in rows:
            if e['kind']!='call': continue
            raw=json.loads((folder/e['files'][0]['path']).read_text(encoding='utf-8'))
            response=raw['response']; actual=response.get('result') or {}
            if e['data'].get('tool')=='ctfd_submit' and response.get('ok') is True and actual.get('candidate_verified') is True and actual.get('judge_status')=='correct':
                verification.append({'step':e['seq'],'platform':'CTFd','challenge_id':actual.get('challenge_id'),'source_evidence':response.get('evidence_path')})
        lines=['# '+wp.scrub(metadata['title'])+' — 中文 WP','',
               '- 题型：'+wp.scrub(metadata['category']),'- 比赛：'+wp.scrub(metadata['competition']),'- 题号：'+a['case'],
               '- 导出范围：'+('本机完整证据包，未经对外审阅' if private else '文本导出；图片按选项包含'),
               '- 解题状态：'+('平台已接受候选；见结果验证回执。' if verification else '未由记录器判定；工具成功不等于答案正确。'),'',
               '## 解题概述','',wp.scrub(str(a.get('summary') or '以下为实际操作、输出及证据；行动说明由解题 Agent 补充。')),'',
               '## 已验证','','以下验证真实调用及证据完整性，过程结论以引用的实际输出为依据。','', '## 解题过程','']

        def copy_asset(event, item):
            nonlocal captures, replays
            kind=item['kind']; source=folder/item['path']
            if kind in IMAGE_KINDS:
                if not include_images:
                    lines.extend(['图片证据已保存，本次未导出。','']);return
                target=report/'images'/('%04d-'%event['seq']+source.name)
                shutil.copyfile(source,target);generated.append(wp.file_record(report,target,kind));captures+=1
                provenance=item.get('source') or event['data'].get('source','')
                lines.extend(['来源：'+wp.scrub(str(provenance))+'；类型：'+kind+'。',
                    '![步骤 %d 的图像证据](images/%s)'%(event['seq'],target.name),''])
            elif kind in REPLAY_KINDS and private and (include_images or kind!='browser_trace'):
                target=report/'recordings'/source.name;target.parent.mkdir(exist_ok=True)
                shutil.copyfile(source,target);generated.append(wp.file_record(report,target,kind));replays+=1
                lines.extend(['过程回放：[%s](recordings/%s)；类型：%s。'%(source.name,source.name,kind),''])
            elif kind=='script_snapshot' and private:
                target=report/'scripts'/source.name;target.parent.mkdir(exist_ok=True)
                shutil.copyfile(source,target);generated.append(wp.file_record(report,target,kind))
                lines.extend(['实际工具输入脚本快照：[%s](scripts/%s)。'%(wp.scrub(item.get('original_name',source.name)),target.name),''])
            elif kind=='data_export' and private:
                target=report/'data'/source.name;target.parent.mkdir(exist_ok=True)
                shutil.copyfile(source,target);generated.append(wp.file_record(report,target,kind))
                lines.extend(['实际工具导出数据：[%s](data/%s)。'%(wp.scrub(item.get('original_name',source.name)),target.name),''])

        for event in rows:
            data, seq=event['data'],event['seq']
            if event['kind']=='call':
                raw=json.loads((folder/event['files'][0]['path']).read_text(encoding='utf-8'))
                response=raw['response']; detail=response.get('result',response)
                state='成功返回' if response.get('ok') is True else '失败（保留错误，不当作成功）'
                lines.extend(['### 步骤 %d：%s'%(seq,wp.scrub(str(data.get('tool')))),'',
                    '时间：%s；状态：%s；耗时：%s ms。'%(event['at'],state,data.get('duration_ms')),''])
                if data.get('operation_id'):lines.extend(['操作编号：`'+data['operation_id']+'`。',''])
                lines.extend(['**行动目的：** '+wp.scrub(data.get('purpose') or '未单独填写；见实际操作。'),''])
                if data.get('expectation'):lines.extend(['**预期检查：** '+wp.scrub(data['expectation'])+'（预期不作为已验证结论）。',''])
                command='参数：\n'+json.dumps(raw['arguments'],ensure_ascii=False,indent=2)
                output='实际返回：\n'+json.dumps(detail,ensure_ascii=False,indent=2)
                lines.extend(['**实际操作与结果：**',wp.fence(command+'\n'+output),'',
                    '原始证据 SHA256：`'+event['files'][0]['sha256']+'`。',''])
                for note in notes.get(seq,[]):lines.extend(['**观察结论（Agent 引用本步骤）：** '+wp.scrub(note),''])
                pic=report/'images'/('%04d-log.png'%seq)
                if wp.render_log(command+'\n'+output,pic):
                    lines.extend(['![步骤 %d 的日志渲染图（非屏幕截图）](images/%s)'%(seq,pic.name),''])
                    generated.append(wp.file_record(report,pic,'log_render'))
                for item in event['files'][1:]: copy_asset(event,item)
                for error in data.get('capture_errors',[]):
                    errors.append({'step':seq,**error});lines.extend(['证据采集缺项：'+wp.scrub(json.dumps(error,ensure_ascii=False))+'。原动作未为补证据重跑。',''])
                if response.get('wp_record_error') or response.get('evidence_error'):errors.append({'step':seq,'error':'Evidence write failed'})
            elif event['kind']=='capture':
                lines.extend(['### 步骤 %d：%s'%(seq,wp.scrub(data['caption'])),''])
                copy_asset(event,event['files'][0])
                for note in notes.get(seq,[]):lines.extend(['**观察结论（Agent 引用本步骤）：** '+wp.scrub(note),''])
            elif event['kind']=='note' and data['status']=='observed' and data['source_step'] not in notes:
                lines.extend(['观察注释：'+wp.scrub(data['text']),''])
        lines.extend(['## 结果验证',''])
        if verification:
            for item in verification:lines.extend(['- CTFd 第 %s 题在步骤 %d 返回 correct；证明该次候选被平台接受，不自动证明所有解释正确。'%(item['challenge_id'],item['step'])])
        else:lines.extend(['当前没有被记录器识别的可信平台验证回执；已有计算或原程序验证请在观察说明中引用相应步骤。'])
        lines.append('')
        for heading,kind,fallback in [('未验证','hypothesis','尚无单独记录的假设；记录器不验证推理正确性。'),('未完成','todo','没有新增待办；最终解题状态以真实验证依据为准。')]:
            lines.extend(['## '+heading,''])
            items=[e['data']['text'] for e in rows if e['kind']=='note' and e['data']['status']==kind]
            lines.extend(['- '+wp.scrub(x) for x in items] or [fallback]);lines.append('')
        for event in pending:
            lines.extend(['- 操作 `%s` 已开始但没有完成回执：%s。应检查原操作状态，禁止直接假设可重跑。'%(event['data']['operation_id'],wp.scrub(event['data']['tool']))])
        if errors:lines.extend(['- 有 %d 项证据采集缺项，详见对应步骤和 manifest.json。'%len(errors),''])
        lines.extend(['## 复现与证据','',
            '按上述命令、脚本与参数复现，核对实际输出和输入摘要。原始事件/回放保留失败过程。',
            '终端 .cast 使用 asciinema play 查看；网页 trace.zip 使用 Playwright Trace Viewer 本地查看。',
            '时间线共 %d 条，末端摘要 `%s`。'%(len(rows),rows[-1]['sha256']),
            '摘要用于发现本地意外改动，不是第三方签名。日志渲染图不属于屏幕截图。',''])
        if private:
            lines.extend(['本包包含私有原始证据与未经像素审阅的图像，分享版本需另行检查。',''])
            evidence=report/'evidence';evidence.mkdir()
            for name in ('timeline.jsonl','checkpoint.json'):
                target=evidence/name;shutil.copyfile(folder/name,target);generated.append(wp.file_record(report,target,'timeline'))
            copied=set()
            for event in rows:
                for item in event.get('files',[]):
                    if item['path'] in copied:continue
                    if not include_images and item['kind'] in IMAGE_KINDS|{'browser_trace'}:continue
                    target=evidence/item['path'];target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(folder/item['path'],target);generated.append(wp.file_record(report,target,'private_evidence'));copied.add(item['path'])
        path=report/'writeup.md';path.write_text('\n'.join(lines),encoding='utf-8');generated.append(wp.file_record(report,path,'markdown'))
        manifest={'case':a['case'],'timeline_head':rows[-1]['sha256'],'files':generated,'private_bundle':private,
            'text_redaction':'best_effort','images_reviewed':False,'capture_errors':errors,
            'pending_operations':[e['data']['operation_id'] for e in pending],
            'recording_complete':not errors and not pending,'platform_verification':verification,
            'images_included':captures,'recordings_included':replays,'scripts_included':sum(f['kind']=='script_snapshot' for f in generated)}
        wp.write_json(report/'manifest.json',manifest)
        archive=shutil.make_archive(str(report), 'zip',root_dir=report) if a.get('bundle',True) is True else None
    return {'case':a['case'],'path':str(path),'bundle_path':archive,'records':len(rows),'integrity_verified':True,
        'images_included':captures,'recordings_included':replays,'recording_complete':manifest['recording_complete'],
        'capture_errors':errors,'pending_operations':manifest['pending_operations'],'solved_verified':False,
        'platform_answer_verified':bool(verification),'review_required_before_sharing':'原始证据、正文语义与图片像素须另行检查'}
