"""Competition process controls; no model calls, automatic submission or guessed results."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile

VERSION = 'competition/1.0'
FIELDS = ('goal', 'environment', 'success_criteria', 'submission_requirements')
READ_ONLY = frozenset({'ctf_profile', 'kali_file', 'kali_strings', 'misc_file_inspect',
    'misc_archive_list', 'misc_image_inspect', 'reverse_binary_info', 'rea_status',
    'rea_ops', 'ctf_runtime_status', 'ctf_specialist_status', 'ctf_task_health',
    'ctfd_status', 'ctfd_list', 'ctfd_challenge', 'ctfd_scoreboard', 'env_prep_check'})


def stamp():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def settings(root):
    path = Path(root) / 'config/competition.local.json'
    cfg = json.loads(path.read_text(encoding='utf-8-sig')) if path.is_file() else {}
    minutes = cfg.get('checkpoint_minutes', 15)
    if type(minutes) is not int or not 1 <= minutes <= 120:
        raise ValueError('checkpoint_minutes must be an integer from 1 to 120')
    return dict(cfg, checkpoint_minutes=minutes)


def metadata(task):
    # Legacy tasks are advisory until explicitly reviewed. Never rewrite old evidence.
    return task.get('competition') or {'version': VERSION, 'enforced': False,
                                      'owner': '', 'checkpoints': [], 'results': []}


def initialize(task):
    task['competition'] = {'version': VERSION, 'enforced': True, 'owner': '',
                           'checkpoints': [], 'results': [], 'status': 'active'}


def sources(task, folder):
    """Read bounded original text/README members; never extract or execute archives."""
    found = []
    if task.get('description', '').strip():
        text = task['description']
        found.append({'id': 'problem', 'sha256': hashlib.sha256(text.encode()).hexdigest(),
                      'text': text[:16000], 'truncated': len(text) > 16000})
    total = 0
    for item in task.get('artifacts', []):
        p = (Path(folder) / item['relative_path']).resolve(strict=True)
        if not p.is_relative_to(Path(folder).resolve()) or digest(p) != item['sha256']:
            raise ValueError('Original attachment changed; stop and inspect intake')
        found.append({'id': 'attachment:' + item['name'], 'sha256': item['sha256'],
                      'text': '原附件身份记录。未从该记录推断目标或规则；未提供的题面/环境/提交要求必须明确记为未提供。'})
        if p.suffix.lower() in {'.md', '.txt', '.json'} and p.stat().st_size <= 65536:
            raw = p.read_bytes()
            found.append({'id': item['name'], 'sha256': hashlib.sha256(raw).hexdigest(),
                          'text': raw.decode('utf-8-sig', errors='replace')[:16000]})
        elif p.suffix.lower() == '.zip':
            try:
                with zipfile.ZipFile(p) as archive:
                    # Bounded central directory scan and decompression, including bomb protection.
                    members = archive.infolist()
                    if len(members) > 5000:
                        continue
                    for member in members:
                        name = member.filename
                        if (member.is_dir() or member.flag_bits & 1 or member.file_size > 65536
                                or not re.search(r'(^|/)(readme[^/]*|rules[^/]*|problem\.json)$', name, re.I)):
                            continue
                        if member.file_size > max(member.compress_size, 1) * 200 or total + member.file_size > 131072:
                            continue
                        raw = archive.read(member)
                        total += len(raw)
                        found.append({'id': item['name'] + '!' + name,
                                      'sha256': hashlib.sha256(raw).hexdigest(),
                                      'text': raw.decode('utf-8-sig', errors='replace')[:16000]})
                        if len(found) >= 20:
                            return found
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
                continue
        if len(found) >= 20:
            break
    return found


def review(task, folder, rules, source_ids, owner=''):
    if not isinstance(rules, dict) or set(rules) != set(FIELDS):
        raise ValueError('rules must contain goal/environment/success_criteria/submission_requirements')
    if any(not isinstance(rules[k], str) or not rules[k].strip() or len(rules[k]) > 4000 for k in FIELDS):
        raise ValueError('Each rule needs a nonempty summary; explicitly state undisclosed requirements')
    available = {row['id']: row for row in sources(task, folder)}
    if (not isinstance(source_ids, list) or not source_ids or
            any(not isinstance(key, str) or key not in available for key in source_ids)):
        raise ValueError('Reference source_ids returned by ctf_progress.rule_sources; do not invent rules')
    if not isinstance(owner, str) or len(owner) > 160:
        raise ValueError('owner must be a short label')
    value = dict(metadata(task), enforced=True, owner=owner or metadata(task).get('owner', ''),
                 rules=dict(rules), reviewed_at=stamp(), status='active',
                 rule_sources=[{'id': key, 'sha256': available[key]['sha256']} for key in source_ids],
                 review_scope='AI recorded its interpretation of original sources; not independent semantic verification')
    task['competition'] = value
    return value


def evidence_steps(task, steps):
    if not isinstance(steps, list) or any(type(x) is not int for x in steps):
        raise ValueError('evidence_steps must be integer step numbers')
    actual = {e['wp_record']['step'] for e in task.get('events', [])
              if isinstance(e.get('wp_record'), dict) and type(e['wp_record'].get('step')) is int}
    if set(steps) - actual:
        raise ValueError('Only actual recorded call steps can be referenced')


def checkpoint(task, findings, excluded_routes, blocker, next_action, decision, evidence, owner=''):
    evidence_steps(task, evidence)
    if decision not in {'continue', 'pause', 'handoff'}:
        raise ValueError('decision must be continue/pause/handoff')
    for name, rows in [('findings', findings), ('excluded_routes', excluded_routes)]:
        if not isinstance(rows, list) or len(rows) > 30 or any(not isinstance(x, str) or len(x) > 2000 for x in rows):
            raise ValueError(name + ' must be a bounded list of text')
    if findings and not evidence:
        raise ValueError('Findings need actual evidence steps; use [] when there is no confirmed progress')
    if not isinstance(blocker, str) or len(blocker) > 4000 or not isinstance(next_action, str) or not next_action.strip() or len(next_action) > 4000:
        raise ValueError('Record the blocker and a concrete next_action')
    if not isinstance(owner, str) or len(owner) > 160:
        raise ValueError('owner must be a short label')
    value = dict(metadata(task))
    row = {'at': stamp(), 'findings': findings, 'excluded_routes': excluded_routes,
           'blocker': blocker, 'next_action': next_action, 'decision': decision,
           'evidence_steps': evidence, 'owner': owner or value.get('owner', '')}
    value['checkpoints'] = value.get('checkpoints', []) + [row]
    value['status'] = {'continue': 'active', 'pause': 'paused', 'handoff': 'handoff'}[decision]
    value['owner'] = row['owner']
    task['competition'] = value
    return row


def result(task, kind, detail, evidence, receipt_file=None):
    if kind not in {'local_validation', 'submitted', 'accepted_reported', 'rejected', 'not_submitted'}:
        raise ValueError('Unknown result kind')
    if not isinstance(detail, str) or not detail.strip() or len(detail) > 4000:
        raise ValueError('Record a bounded explanation')
    evidence_steps(task, evidence)
    receipt = None
    if receipt_file:
        p = Path(receipt_file).resolve(strict=True)
        if not p.is_file():
            raise ValueError('receipt_file must be an actual file')
        receipt = {'path': str(p), 'sha256': digest(p), 'bytes': p.stat().st_size}
    if kind != 'not_submitted' and not evidence and not receipt:
        raise ValueError('Attach actual evidence or a receipt file')
    row = {'at': stamp(), 'kind': kind, 'detail': detail, 'evidence_steps': evidence,
           'receipt': receipt, 'scope': 'recorded report; only trusted platform correct receipts set answer_verified'}
    value = dict(metadata(task))
    value['results'] = value.get('results', []) + [row]
    task['competition'] = value
    # A note or arbitrary screenshot can never promote a candidate to platform-verified.
    return row


def view(task, cfg, clock=None):
    value = metadata(task)
    clock = clock or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    last = (value.get('checkpoints') or [{}])[-1]
    start = last.get('at') or value.get('reviewed_at') or task['created_at']
    elapsed = max(0, (clock - datetime.fromisoformat(start)).total_seconds())
    due = value.get('enforced') is True and elapsed >= cfg.get('checkpoint_minutes', 15) * 60
    records = value.get('results', [])
    submissions = [x for x in records if x['kind'] != 'local_validation']
    return {'version': VERSION, 'enforced': value.get('enforced') is True,
            'rules_reviewed': bool(value.get('rules')), 'owner': value.get('owner', ''),
            'status': value.get('status', 'active'), 'checkpoint_due': due,
            'minutes_since_checkpoint': round(elapsed / 60, 1), 'checkpoint': last,
            'local_validation_recorded': any(x['kind'] == 'local_validation' for x in records),
            'submission_status': 'platform_correct' if task.get('answer_verified') is True else (submissions[-1]['kind'] if submissions else 'unknown'),
            'platform_verified': task.get('answer_verified') is True,
            'scope': 'This computer only; checkpoints measure elapsed wall time, not model cost or wasted time'}


def gate(task, tool, cfg):
    current = view(task, cfg)
    if not current['enforced'] or tool in READ_ONLY or tool.startswith('wp_') or tool == 'ctfd_submit':
        return
    if not current['rules_reviewed']:
        raise ValueError('rules_review_required: read ctf_progress.rule_sources, then record ctf_plan before solving')
    if current['status'] in {'paused', 'handoff'}:
        raise ValueError('task_paused: record ctf_checkpoint(decision=continue, owner=...) to resume')
    if current['checkpoint_due']:
        raise ValueError('checkpoint_required: record findings/evidence, excluded routes, blocker and next_action with ctf_checkpoint')


def normalize(tool, args, task, entry):
    value = dict(args)
    changes = []
    props = entry.get('inputSchema', {}).get('properties', {})
    def rename(old, new):
        if old in value and new in props and new not in value:
            value[new] = value.pop(old)
            changes.append({'from': old, 'to': new})
    if tool == 'ctf_profile' and value.get('category') in {None, 'unknown', 'mobile'}:
        category = task.get('category')
        value['category'] = category if category in {'web', 'pwn', 'reverse', 'crypto', 'misc', 'forensics'} else 'misc'
        changes.append({'field': 'category', 'to': value['category'], 'scope': 'generic triage; does not prove the challenge type'})
    if tool == 'flag_format_check':
        rename('flag', 'candidate')
    if tool == 'wp_section':
        rename('content', 'text')
    if tool == 'misc_archive_list':
        for key in ('path', 'target'):
            if key in value and 'local_file' not in value and 'local_file' in props and Path(str(value[key])).is_file():
                rename(key, 'local_file')
    return value, changes


def export_key(task, args):
    body = {k: task.get(k) for k in ('title', 'description', 'artifacts', 'events', 'source', 'answer_verified', 'competition')}
    return hashlib.sha256(json.dumps([body, args], sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def deliver(task, response, cfg, root):
    actual = response.get('result') or {}
    word = actual.get('formats', {}).get('docx') or {}
    if word.get('ok') is not True or not word.get('path'):
        raise ValueError('Word export failed: ' + str(word.get('error') or 'No successful docx receipt'))
    source = Path(word['path']).resolve(strict=True)
    if not source.is_relative_to((Path(root) / 'wp/cases' / task['task_id']).resolve()):
        raise ValueError('Exporter returned a document outside this task')
    if not zipfile.is_zipfile(source):
        raise ValueError('Exported Word is not a valid DOCX container')
    target = source
    if cfg.get('delivery_dir'):
        directory = Path(cfg['delivery_dir']).absolute()
        if any(p.is_symlink() or getattr(p, 'is_junction', lambda: False)() for p in (directory, *directory.parents)):
            raise ValueError('Delivery directory cannot use links or junctions')
        directory.mkdir(parents=True, exist_ok=True)
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', task['title']).strip(' .')[:65] or 'CTF'
        target = directory / (name + '-WP-' + task['task_id'][-8:] + '.docx')
        # Never replace an unrelated pre-existing document.
        previous = task.get('delivery') or {}
        if target.exists() and (previous.get('path') != str(target) or digest(target) != previous.get('sha256')):
            target = _alternate_delivery_path(directory, name, task['task_id'][-8:])
        temporary = target.with_name(target.name + '.tmp')
        try:
            shutil.copyfile(source, temporary)
            if digest(temporary) != digest(source):
                raise ValueError('Document copy checksum mismatch')
            temporary.replace(target)
        except PermissionError as exc:
            # 目标被 Word/预览/索引占用（WinError 32）：自动换新文件名交付，
            # 不阻塞导出；旧文件保留原样，避免误删用户正打开的文档。
            fallback = _alternate_delivery_path(directory, name, task['task_id'][-8:])
            temporary.unlink(missing_ok=True)
            shutil.copyfile(source, fallback)
            if digest(fallback) != digest(source):
                raise ValueError('Document copy checksum mismatch')
            target = fallback
            exc.add_note('目标文件被占用，已改存新文件名：' + str(fallback))
        finally:
            temporary.unlink(missing_ok=True)
    return {'path': str(target), 'sha256': digest(target), 'bytes': target.stat().st_size,
            'format': 'docx', 'platform_verified': task.get('answer_verified') is True}


def _alternate_delivery_path(directory, name, suffix):
    """Timestamped sibling name; keeps every delivered version distinct."""
    stamp = datetime.now(timezone.utc).strftime('%H%M%S')
    return directory / ('%s-WP-%s-%s.docx' % (name, suffix, stamp))
