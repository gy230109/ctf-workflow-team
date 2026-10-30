"""Report semantics over self-built evidence, without solving real tasks."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import ctf_wp as wp
import ctf_wp_report as report
from ctf_product import Product, save, sha


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patch = patch.object(wp, 'ROOT', self.root / 'cases')
        self.patch.start()
        wp.init({'case': 'fixture', 'title': '自建 WP 验证', 'category': 'misc'})

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def build(self, **extra):
        return wp.build(dict(case='fixture', formats=[], private_bundle=True,
                             include_log_renders=False, **extra))

    def test_context_and_originals_are_portable(self):
        handout = self.root / 'handout.txt'
        handout.write_text('self-built handout', encoding='utf-8')
        wp.intake({'case': 'fixture', 'description': '题面原文', 'source': {'platform': 'fixture'}, 'attachments': [str(handout)]})
        wp.intake({'case': 'fixture', 'description': '追加题面'})
        result = self.build()
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertEqual(model['challenge']['description'], '追加题面')
        self.assertEqual(len(model['challenge']['artifacts']), 1)
        with zipfile.ZipFile(result['bundle_path']) as archive:
            item = model['challenge']['artifacts'][0]
            self.assertEqual(archive.read('evidence/' + item['path']), handout.read_bytes())

    def test_preview_bounded_full_raw_and_health_retained(self):
        text = 'actual ' * 5000
        response = {'tool': 'fixture', 'ok': False, 'task_health': {'repeated': True},
                    'result': {'stderr': 'actual failure', 'exit_code': 9, 'stdout': text}}
        call = wp.record_call('fixture', {'wp_purpose': '检验错误原文'}, response)
        wp.note({'case': 'fixture', 'status': 'observed', 'source_step': call['step'], 'text': '真实错误退出码为 9'})
        result = self.build()
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        step = model['steps'][0]
        self.assertTrue(step['output_truncated'])
        self.assertLess(len(step['output_excerpt']), 3700)
        md = Path(result['path']).read_text(encoding='utf-8')
        self.assertIn('actual failure', md)
        self.assertIn('task_health', md)
        self.assertIn('真实错误退出码为 9', md)
        raw = json.loads((Path(result['path']).parent / step['evidence_ref']).read_text(encoding='utf-8'))
        self.assertEqual(raw['response']['result']['stdout'], text)
        self.assertFalse(list(Path(result['path']).parent.glob('images/*-log.png')))

    def test_falsy_payloads_are_not_replaced(self):
        for value in (False, 0, []):
            self.assertEqual(report.output_view({'result': value}), value)

    def test_redaction_preserves_json_syntax_and_masks_sensitive_keys(self):
        value = {'text': 'token=fixture', 'token': 'fixture', 'nested': [{'password': 'fixture'}], 'zero': 0}
        cleaned = report.redact(value)
        self.assertEqual(json.loads(json.dumps(cleaned)), cleaned)
        self.assertNotIn('fixture', json.dumps(cleaned))
        self.assertEqual(cleaned['zero'], 0)
        wp.record_call('fixture', {'token': 'fixture'}, {'tool': 'fixture', 'ok': True, 'result': 'token=fixture'})
        result = wp.build({'case': 'fixture', 'formats': [], 'private_bundle': False})
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        raw = (Path(result['path']).parent / model['steps'][0]['evidence_ref']).read_text(encoding='utf-8')
        self.assertNotIn('"token": "fixture"', raw)

    def test_duplicate_embedded_json_not_repeated_in_preview(self):
        value = {'answer': 'fixture'}
        view = report.output_view({'result': {'data': value, 'execution': {'stdout': json.dumps(value), 'exit_code': 0}}})
        self.assertEqual(view['data'], value)
        self.assertIn('已省略', view['execution']['stdout'])

    def test_capture_failure_propagates_to_report(self):
        with patch('ctf_os_runtime.settings', return_value={}):
            with self.assertRaises(ValueError):
                wp.capture({'case': 'fixture'})
        result = self.build()
        self.assertFalse(result['recording_complete'])
        self.assertEqual(result['capture_errors'][0]['kind'], 'capture_failed')

    def test_disabling_images_also_disables_log_pngs(self):
        wp.record_call('fixture', {}, {'tool': 'fixture', 'ok': True, 'result': 'real fixture output'})
        with self.assertRaisesRegex(ValueError, '日志渲染'):
            wp.build({'case': 'fixture', 'formats': [], 'include_images': False, 'include_log_renders': True})
        result = wp.build({'case': 'fixture', 'formats': [], 'include_images': False})
        self.assertFalse(list(Path(result['path']).parent.rglob('*.png')))

    def test_revised_input_scripts_keep_distinct_reproduction_links(self):
        source = self.root / 'solver.py'
        for value in ('first version', 'second version'):
            source.write_text(value, encoding='utf-8')
            args = {'script_file': str(source)}
            operation = wp.begin_call('fixture', 'fixture', args)
            wp.record_call('fixture', args, {'tool': 'fixture', 'ok': True, 'result': {}, 'wp_operation': operation})
        result = self.build()
        scripts = list((Path(result['path']).parent / 'scripts').glob('*.py'))
        self.assertEqual(len(scripts), 2)
        self.assertEqual({p.read_text(encoding='utf-8') for p in scripts}, {'first version', 'second version'})

    def test_annotation_does_not_certify_answer(self):
        call = wp.record_call('fixture', {}, {'tool': 'fixture', 'ok': True, 'result': 42})
        wp.section({'case': 'fixture', 'section': 'validation', 'text': '已成功', 'source_steps': [call['step']]})
        result = self.build()
        self.assertFalse(result['platform_answer_verified'])
        self.assertFalse(result['submission_ready'])
        self.assertFalse(result['solved_verified'])

    def test_manifest_covers_every_generated_file(self):
        result = self.build()
        directory = Path(result['path']).parent
        manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
        for item in manifest['files']:
            self.assertEqual(wp.digest(directory / item['path']), item['sha256'])
        self.assertEqual({x['path'] for x in manifest['files']},
                         {x.relative_to(directory).as_posix() for x in directory.rglob('*') if x.is_file() and x.name != 'manifest.json'})

    def test_product_context_deduplicates_and_checks_original_hash(self):
        product = Product(self.root)
        folder = self.root / 'task'
        folder.mkdir()
        source = folder / 'input.bin'
        source.write_bytes(b'fixture')
        task = {'task_id': 'fixture', 'description': 'original', 'artifacts': [
            {'name': source.name, 'relative_path': source.name, 'sha256': sha(source)}]}
        save(folder / 'task.json', task)
        with patch.object(product, 'core', return_value={'ok': True}) as core:
            product.sync_wp_context(folder, task)
            product.sync_wp_context(folder, task)
            self.assertEqual(core.call_count, 1)
            self.assertEqual(core.call_args.args[0], 'wp_intake')
            source.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                product.sync_wp_context(folder, task)

    def test_selected_mainline_keeps_other_calls_in_evidence(self):
        first = wp.record_call('fixture', {}, {'tool': 'routine', 'ok': True, 'result': 'ROUTINE_OUTPUT'})
        second = wp.record_call('fixture', {}, {'tool': 'key_action', 'ok': True, 'result': 'KEY_OUTPUT'})
        wp.section({'case': 'fixture', 'section': 'solution', 'text': '主线依据第二步', 'source_steps': [second['step']]})
        result = self.build()
        md = Path(result['path']).read_text(encoding='utf-8')
        self.assertIn('KEY_OUTPUT', md)
        self.assertNotIn('ROUTINE_OUTPUT', md)
        self.assertIn('ROUTINE_OUTPUT', Path(result['technical_path']).read_text(encoding='utf-8'))
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertEqual([x['in_main_text'] for x in model['steps']], [False, True])

    def test_old_product_context_imports_without_replay(self):
        folder = self.root / '.local/ctf-system/tasks/fixture'
        folder.mkdir(parents=True)
        source = folder / 'handout.txt'
        source.write_text('fixture', encoding='utf-8')
        save(folder / 'task.json', {'task_id': 'fixture', 'description': '旧任务真实题面',
             'artifacts': [{'name': source.name, 'relative_path': source.name, 'sha256': sha(source)}]})
        with patch.object(wp, 'BASE', self.root):
            result = self.build()
            again = self.build()
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertEqual(model['challenge']['description'], '旧任务真实题面')
        self.assertEqual(result['records'], again['records'])
        self.assertEqual(sum(e['kind'] == 'intake' for e in wp.records(wp.case_dir('fixture'))), 1)

    def test_global_format_failure_is_reported_per_requested_format(self):
        from types import SimpleNamespace
        directory = self.root / 'export'
        directory.mkdir()
        reply = SimpleNamespace(returncode=1, stdout=json.dumps({'ok': False, 'formats': {}, 'error': 'model invalid'}))
        with patch('ctf_wp_report.subprocess.run', return_value=reply):
            result = report.extra_formats({'formats': ['docx', 'pdf']}, directory)
        self.assertFalse(result['ok'])
        self.assertEqual(set(result['formats']), {'docx', 'pdf'})
        self.assertEqual(result['formats']['pdf']['error'], 'model invalid')


if __name__ == '__main__':
    unittest.main(verbosity=2)
