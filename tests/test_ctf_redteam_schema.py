"""JSON Schema 结构回归测试（红队工具面）。

背景：2026-10-30 一轮运行直接失败，报

    Invalid schema for function 'mcp__ctf__system__redteam__asset__add':
    "object" is not of types "boolean", "object"

根因：``integrations/purge-redteam/runtime/catalogue.json`` 这一份目录快照生成于
ctx-shim 修好之前，``redteam_asset_add`` 的 ``names.items`` / ``ports.items`` 里把整个
``{type:'object', properties:{...}}`` 当成一个「属性」塞进了 ``properties``，于是
``properties`` 的键位出现了 ``"type": "object"`` 这种字符串。模型网关按 JSON Schema
规范（``properties`` 的值只能是 schema 或 boolean）直接拒收，整轮 inflight 失败。

本测试守三件事：
  1. 任何来源的工具 schema 经 ``_norm_tools`` 后，``properties`` 键位不得出现 schema 保留字；
  2. ``repair_schema`` 幂等，且能把「整层被包一层」的旧脏数据还原；
  3. 磁盘上的两份目录快照（runtime/catalogue.json 与数据区缓存）本身是干净的。
"""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'fusion_under_test', ROOT / 'tools/ctf_redteam_fusion.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

#: 出现在 ``properties`` 键位上、且值不是 schema 时，说明整层被包了一层。
#: 注意 ``title`` / ``format`` / ``default`` 本身是合法字段名，不能只看键名。
SCHEMA_KEYWORDS = {
    'type', 'properties', 'items', 'required', 'additionalProperties', 'enum',
    'pattern', 'format', 'minimum', 'maximum', 'anyOf', 'oneOf', 'allOf',
    'not', '$ref', 'title', 'default',
}


def _is_keyword_misuse(key, value):
    """``properties`` 的键是 schema 保留字、值又不是 schema → 违法。

    ``properties`` 的值只能是 schema（dict）或 boolean。所以 ``"type": "object"``
    这种字符串值一定不是合法字段定义。
    """
    if key not in SCHEMA_KEYWORDS:
        return False
    if isinstance(value, dict):
        return False                       # 字段名恰好叫 title，值是 schema —— 正常
    if key == 'additionalProperties' and isinstance(value, bool):
        return True
    return isinstance(value, (str, list, int, float, bool))


def schema_violations(node, path=''):
    """返回 [(path, reason)]；递归检查 properties / items / additionalProperties。"""
    out = []
    if isinstance(node, list):
        for i, item in enumerate(node):
            out += schema_violations(item, '%s[%d]' % (path, i))
        return out
    if not isinstance(node, dict):
        return out

    props = node.get('properties')
    if isinstance(props, dict):
        for key, value in props.items():
            here = '%s/properties/%s' % (path, key)
            if _is_keyword_misuse(key, value):
                out.append((here, 'schema keyword used as property name'))
            out += schema_violations(value, here)
    ap = node.get('additionalProperties')
    if ap is not None and not isinstance(ap, (bool, dict)):
        out.append((path + '/additionalProperties', 'must be boolean or schema'))
    elif isinstance(ap, dict):
        out += schema_violations(ap, path + '/additionalProperties')
    items = node.get('items')
    if items is not None:
        out += schema_violations(items, path + '/items')
    declared = node.get('type')
    if declared is not None and not isinstance(declared, (str, list)):
        out.append((path + '/type', 'must be a string or string array'))
    required = node.get('required')
    if required is not None and not (
            isinstance(required, list) and all(isinstance(r, str) for r in required)):
        out.append((path + '/required', 'must be a string array'))
    return out


class ToolSchemaTests(unittest.TestCase):
    def test_every_registered_schema_is_valid(self):
        self.assertTrue(F.TOOLS, 'redteam 工具目录为空，测试无意义')
        for name, (_handler, _desc, schema) in F.TOOLS.items():
            with self.subTest(tool=name):
                self.assertEqual(schema.get('type'), 'object')
                self.assertEqual(schema_violations(schema), [])

    def test_asset_add_nested_shapes_survive(self):
        """报错现场：names/ports 的 items 必须是标准 object schema。"""
        schema = F.TOOLS['redteam_asset_add'][2]
        names = schema['properties']['names']
        self.assertEqual(names['type'], 'array')
        self.assertEqual(names['items']['type'], 'object')
        self.assertEqual(names['items']['required'], ['name'])
        self.assertIn('name', names['items']['properties'])
        self.assertNotIn('properties', names['items']['properties'])

        ports = schema['properties']['ports']['items']
        self.assertEqual(ports['type'], 'object')
        self.assertEqual(ports['required'], ['port'])
        fingerprints = ports['properties']['fingerprints']['items']
        self.assertEqual(fingerprints['type'], 'object')
        self.assertIn('confidence', fingerprints['properties'])

    def test_repair_is_idempotent(self):
        for name, (_h, _d, schema) in F.TOOLS.items():
            once, problems = F.repair_schema(json.loads(json.dumps(schema)))
            self.assertEqual(problems, [], name)
            twice, again = F.repair_schema(json.loads(json.dumps(once)))
            self.assertEqual(again, [], name)
            self.assertEqual(once, twice, name)

    def test_repair_unwraps_double_nesting(self):
        dirty = {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'type': 'object',
                'properties': {'port': {'type': 'number', 'required': True}},
                'required': ['port'],
            },
        }
        fixed, problems = F.repair_schema(json.loads(json.dumps(dirty)))
        self.assertTrue(problems)
        self.assertEqual(set(fixed['properties']), {'port'})
        self.assertEqual(fixed['required'], ['port'])
        self.assertEqual(schema_violations(fixed), [])

    def test_repair_rejects_bad_scalars(self):
        dirty = {
            'type': 'object',
            'additionalProperties': 'false',
            'properties': {'a': {'type': {'nested': True}, 'items': 'oops'}},
        }
        fixed, problems = F.repair_schema(json.loads(json.dumps(dirty)))
        self.assertEqual(fixed['additionalProperties'], False)
        self.assertNotIn('items', fixed['properties']['a'])
        self.assertIsInstance(fixed['properties']['a']['type'], str)
        self.assertEqual(schema_violations(fixed), [])
        self.assertTrue(problems)

    def test_scheduler_fields_always_present(self):
        for name, (_h, _d, schema) in F.TOOLS.items():
            if name.startswith('ctf_redteam_'):
                continue            # 兼容入口自带 case/timeout，不走 fusion 补齐
            props = schema['properties']
            self.assertIn('case', props, name)
            self.assertIn('timeout', props, name)
            self.assertIn('source_step', props, name)


class CatalogueSnapshotTests(unittest.TestCase):
    """磁盘快照必须干净，否则下一次冷启动又会把脏 schema 发给客户端。"""

    def _check(self, path):
        if not path.is_file():
            self.skipTest('目录快照不存在: %s' % path)
        data = json.loads(path.read_text(encoding='utf-8-sig'))
        tools = F._norm_tools(data.get('tools'))
        self.assertTrue(tools, path)
        for entry in tools:
            with self.subTest(file=path.name, tool=entry['name']):
                self.assertEqual(schema_violations(entry['parameters']), [])

    def test_runtime_catalogue_clean(self):
        self._check(F.CATALOGUE_FILE)

    def test_data_cache_clean(self):
        self._check(F.CACHE_FILE)

    def test_bom_readable(self):
        """catalogue.json 带 BOM；``_read_json`` 必须能读出来而不是静默返回 None。"""
        if not F.CATALOGUE_FILE.is_file():
            self.skipTest('目录快照不存在')
        data = F._read_json(F.CATALOGUE_FILE)
        self.assertIsNotNone(data, '_read_json 读不出带 BOM 的 catalogue.json')
        self.assertTrue(data.get('tools'))


if __name__ == '__main__':
    unittest.main()
