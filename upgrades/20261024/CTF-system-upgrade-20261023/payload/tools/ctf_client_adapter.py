"""Provider-neutral CTF tool adapters; no model account or model API is owned here."""
import copy
import itertools
import json
from pathlib import Path
import subprocess
import sys

PREFIXES = ('mcp__ctf_system__', 'mcp__ctf-system__')


class AdapterError(ValueError):
    """Invalid provider envelope or a tool outside the CTF system surface."""


class StdioTransport:
    """Call the same stable MCP entry using only the Python standard library."""
    def __init__(self, root, python=None, timeout=710):
        self.root = Path(root).resolve(strict=True)
        self.python = python or sys.executable
        self.timeout = timeout

    def __call__(self, request):
        result = subprocess.run([self.python, '-X', 'utf8', '-B',
            str(self.root/'tools/ctf_entry.py'), '--stdio', '--root', str(self.root)],
            input=json.dumps(request, ensure_ascii=False)+'\n', capture_output=True,
            text=True, encoding='utf-8', timeout=self.timeout, cwd=self.root)
        if result.returncode:
            raise RuntimeError('CTF stdio transport failed: '+result.stderr[-1200:])
        response = json.loads(result.stdout)
        if response.get('id') != request['id']:
            raise AdapterError('MCP response id does not match request')
        return response


class CTFClient:
    """Adapt tool schemas and calls while keeping task state on the CTF server."""
    def __init__(self, transport):
        self.transport = transport
        self.sequence = itertools.count(1)
        self.catalog = None

    def rpc(self, method, params=None):
        response = self.transport({'jsonrpc':'2.0', 'id':next(self.sequence),
                                   'method':method, 'params':params or {}})
        if 'error' in response:
            raise AdapterError(response['error'].get('message', 'MCP request failed'))
        return response['result']

    def tools(self, provider='mcp'):
        self.catalog = self.rpc('tools/list')['tools']
        if provider == 'mcp':
            return copy.deepcopy(self.catalog)
        if provider in {'openai','deepseek'}:
            return [{'type':'function','function':{'name':t['name'],
                'description':t['description'],'parameters':copy.deepcopy(t['inputSchema'])}}
                for t in self.catalog]
        if provider == 'anthropic':
            return [{'name':t['name'],'description':t['description'],
                     'input_schema':copy.deepcopy(t['inputSchema'])} for t in self.catalog]
        raise AdapterError('Choose mcp, openai, deepseek or anthropic schema format')

    def call(self, name, arguments=None, call_id=None):
        if not isinstance(name, str):
            raise AdapterError('Tool name must be a string')
        for prefix in PREFIXES:
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        if self.catalog is None:
            self.tools()
        if name not in {t['name'] for t in self.catalog}:
            raise AdapterError('Tool is outside the CTF system: '+name)
        arguments = {} if arguments is None else arguments
        if not isinstance(arguments, dict):
            raise AdapterError('Tool arguments must be an object')
        arguments = copy.deepcopy(arguments)
        # A repeated provider call id is an execution retry, not a new action.
        if call_id is not None and name in {'ctf_call','ctf_analyze'}:
            arguments.setdefault('request_id', call_id)
        return self.rpc('tools/call', {'name':name, 'arguments':arguments})

    def openai_call(self, call):
        function = call.get('function') or {}
        try:
            args = json.loads(function['arguments'])
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterError('Invalid function arguments JSON') from exc
        if not isinstance(call.get('id'), str) or not call['id']:
            raise AdapterError('A provider tool call id is required')
        result = self.call(function.get('name'), args, call['id'])
        # Preserve isError and structuredContent rather than flattening failures.
        return {'role':'tool','tool_call_id':call['id'],
                'content':json.dumps(result, ensure_ascii=False)}

    def anthropic_call(self, block):
        if block.get('type') != 'tool_use' or not isinstance(block.get('id'), str) or not block['id']:
            raise AdapterError('A tool_use block and its id are required')
        result = self.call(block.get('name'), block.get('input'), block['id'])
        return {'type':'tool_result', 'tool_use_id':block['id'],
                'is_error':bool(result.get('isError')),
                'content':json.dumps(result, ensure_ascii=False)}
