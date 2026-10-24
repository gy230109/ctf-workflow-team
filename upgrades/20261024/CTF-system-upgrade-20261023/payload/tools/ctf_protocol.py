"""Server-owned workflow rules shared by every CTF client and model."""
import hashlib
import json

VERSION = 'ctf-system/1.1'
NAMESPACE = 'ctf_system'
DIAGNOSTICS = frozenset({'status','ctf_runtime_status','ctf_specialist_status',
    'ctf_task_health','rea_status','rea_ops','ctfd_status','ctfd_list',
    'ctfd_challenge','ctfd_scoreboard','cracktools_status'})
PREFLIGHT = DIAGNOSTICS | {'ctf_profile','kali_file','misc_file_inspect'}


class WorkflowError(ValueError):
    """A rejected transition, with a stable code and actionable next operation."""
    def __init__(self, code, message, required_next):
        super().__init__(message)
        self.code = code
        self.required_next = required_next


def contract(tools):
    schemas = {name: row[1] for name, row in tools.items()}
    digest = hashlib.sha256(json.dumps(schemas, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return {'version': VERSION, 'namespace': NAMESPACE, 'operations': list(tools),
            'schema_sha256': digest, 'workflow_owner': 'CTF_system',
            'model_binding': 'external_replaceable', 'native_client_tools_managed': False,
            'client_requirement': 'Route CTF execution through these operations; native tool restrictions require a client adapter.'}


def state(task):
    """Migrate only workflow metadata; never invent historical tool evidence."""
    if 'workflow' not in task:
        events = task.get('events', [])
        triaged = any(e.get('tool') == 'ctf_profile' and e.get('ok') is True for e in events)
        count = sum(e.get('ok') is True and bool(e.get('tool')) and
                    e['tool'] not in PREFLIGHT and not e['tool'].startswith('wp_') for e in events)
        pending = None
        for event in events:
            if event.get('tool') and event.get('ok') is False:
                pending = failure_record(event['tool'], event)
            elif pending and event.get('resolve_error') is True and event.get('source_step') == pending['source_step']:
                pending = None
        task['workflow'] = {'version': VERSION, 'triaged': triaged,
                            'analysis_calls': count, 'pending_error': pending}
    value = task['workflow']
    if value.get('version') != VERSION:
        raise WorkflowError('workflow_version_mismatch', 'This task uses another workflow version; do not rewrite it silently.', ['ctf_progress'])
    return value


def view(task):
    value = state(task)
    if value['pending_error']:
        phase, following = 'needs_recovery', ['ctf_note(resolve_error=true)', 'ctf_finish(state=blocked)']
    elif task.get('answer_verified') is True:
        phase, following = 'verified', ['ctf_finish']
    elif task.get('state') in {'blocked','needs_input'}:
        phase, following = task['state'], ['ctf_progress']
    elif task.get('state') == 'analysis_complete':
        phase, following = 'analysis_complete_unverified', ['ctf_progress']
    elif not value['triaged']:
        phase, following = 'needs_triage', ['ctf_analyze(tool=ctf_profile)']
    else:
        phase, following = 'analysis', ['ctf_analyze', 'ctf_call', 'ctf_note']
    return dict(value, phase=phase, required_next=following,
                answer_verified=task.get('answer_verified') is True)


def before_call(task, tool):
    value = state(task)
    if value['pending_error'] and tool not in DIAGNOSTICS:
        raise WorkflowError('recovery_required', 'Resolve the recorded failure with ctf_note(resolve_error=true) before another execution.',
                            ['ctf_note(resolve_error=true)', 'ctf_finish(state=blocked)'])
    if not value['triaged'] and tool not in PREFLIGHT:
        raise WorkflowError('triage_required', 'Call ctf_profile successfully before solving tools.', ['ctf_analyze(tool=ctf_profile)'])


def failure_record(tool, result):
    return {'tool': tool,
            'error_code': result.get('error_code') or 'tool_failed',
            'error': str(result.get('error') or 'Tool failed; inspect its original receipt.')[:600],
            'source_step': (result.get('wp_record') or {}).get('step'),
            'evidence_path': result.get('evidence_path')}


def after_call(task, tool, arguments, result):
    value = state(task)
    if result.get('ok') is not True:
        value['pending_error'] = failure_record(tool, result)
    elif tool == 'ctf_profile':
        category = (result.get('result') or {}).get('category')
        if category in {'web','pwn','reverse','crypto','misc','forensics'}:
            value['triaged'] = True
            task['category'] = category
    elif tool not in PREFLIGHT and not tool.startswith('wp_'):
        value['analysis_calls'] += 1


def validate_recovery(task, source_step):
    pending = state(task)['pending_error']
    if not pending:
        raise WorkflowError('no_pending_error', 'There is no unresolved tool failure.', ['ctf_progress'])
    if source_step != pending['source_step']:
        raise WorkflowError('wrong_failure_step', 'Reference the pending failure source_step returned by ctf_progress.', ['ctf_progress'])


def before_finish(task, completion):
    value = state(task)
    if completion != 'analysis_complete':
        return
    if value['pending_error']:
        raise WorkflowError('recovery_required', 'An unresolved failure cannot be reported as completed analysis.', ['ctf_note(resolve_error=true)', 'ctf_finish(state=blocked)'])
    if not value['triaged'] or value['analysis_calls'] == 0:
        raise WorkflowError('analysis_required', 'Completed analysis requires triage and an actual successful analysis call.', ['ctf_analyze(tool=ctf_profile)', 'ctf_analyze'])


def validate_arguments(arguments, schema, path='arguments'):
    """Validate the schema subset emitted by the eight public operations."""
    expected = schema.get('type')
    checks = {'object': lambda x: isinstance(x, dict), 'array': lambda x: isinstance(x, list),
              'string': lambda x: isinstance(x, str), 'boolean': lambda x: type(x) is bool,
              'integer': lambda x: type(x) is int}
    if expected in checks and not checks[expected](arguments):
        raise ValueError(path + ' must be ' + expected)
    if 'enum' in schema and arguments not in schema['enum']:
        raise ValueError(path + ' is not an allowed value')
    if expected == 'object':
        props = schema.get('properties', {})
        if set(schema.get('required', [])) - set(arguments):
            raise ValueError(path + ' is missing required fields')
        if schema.get('additionalProperties') is False and set(arguments) - set(props):
            raise ValueError(path + ' contains unknown fields')
        for key, value in arguments.items():
            if key in props:
                validate_arguments(value, props[key], path + '.' + key)
    if expected == 'array' and 'items' in schema:
        for value in arguments:
            validate_arguments(value, schema['items'], path + '[]')
    json.dumps(arguments, allow_nan=False)


def request_fingerprint(tool, arguments):
    return hashlib.sha256(json.dumps({'tool': tool, 'arguments': arguments}, sort_keys=True,
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()
