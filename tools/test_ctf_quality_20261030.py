"""Regression coverage for real inventory, unknown health and screenshot WP rules."""
import base64
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ctf_envprep as env
import ctf_redteam as redteam
import ctf_wp as wp
from ctf_product import Product

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aHh8AAAAASUVORK5CYII=')


class InventoryTests(unittest.TestCase):
    def test_public_mcp_context_resolves_core_registry(self):
        fake = types.SimpleNamespace(ALL_TOOLS={'rea_run': object(), 'web_html_parse': object()})
        with patch.dict(sys.modules, {'ctf_os': None, '__main__': types.SimpleNamespace()}), \
                patch('importlib.import_module', return_value=fake):
            self.assertEqual(redteam._existing_names(), {'rea_run', 'web_html_parse'})

    def test_unavailable_inventory_is_unknown_not_empty(self):
        with patch.dict(sys.modules, {'ctf_os': None, '__main__': types.SimpleNamespace()}), \
                patch('importlib.import_module', return_value=types.SimpleNamespace()):
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                redteam._existing_names()

    def test_reverse_route_uses_real_rea_entry(self):
        self.assertIn('rea_run', redteam.ROUTES['reverse'])
        self.assertNotIn('rea_inspect', redteam.ROUTES['reverse'])


class TwoModuleTests(unittest.TestCase):
    def test_contract_keeps_both_modules_and_full_integration(self):
        from ctf_wp_policy import contract
        policy = contract()
        self.assertEqual(set(policy['modules']), {'solving', 'writeup'})
        self.assertEqual(policy['redteam_role'], 'fully-integrated')
        self.assertEqual(policy['modules']['solving']['capability_policy'], 'fully-integrated')
        self.assertEqual(policy['modules']['writeup']['capture_policy'], 'at_key_milestones')

    def test_crypto_task_also_has_full_fused_workflow(self):
        plan = redteam.plan_for(Path('.'), {'task_id':'fixture', 'category':'crypto'})
        self.assertEqual(plan['redteam_role'], 'fully-integrated')
        self.assertFalse(plan['routing_hints_are_allowlists'])
        self.assertNotIn('not_required', plan)
        self.assertIn('redteam_', plan['redteam_discovery'])

    def test_admin_metadata_does_not_request_a_screenshot(self):
        from ctf_wp_policy import guidance
        self.assertFalse(guidance('redteam_asset_add', {'result':{'id':1}})['capture_recommended'])
        self.assertFalse(guidance('status', {'result':{'ok':True}})['capture_recommended'])
        self.assertTrue(guidance('web_browser_session', {'result':{'ok':True}})['capture_recommended'])

    def test_project_upgrades_remain_confined_to_named_files(self):
        import importlib.util
        path = Path(__file__).resolve().parents[1] / 'integrations/purge-redteam/upgrade-installer.py'
        spec = importlib.util.spec_from_file_location('quality_upgrade_fixture', path)
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ['AGENTS.md', 'tests/test_ctf_wp.py', 'tests/test_ctf_wp_review.py']:
                self.assertTrue(installer.safe(root, name).is_relative_to(root))
            for name in ['../AGENTS.md', 'config/ctfd.local.json', 'tests/unrelated.py', 'C:/escape', 'skills/custom/SKILL.md']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    installer.safe(root, name)


class HealthTests(unittest.TestCase):
    def test_unknown_does_not_become_healthy(self):
        for levels in [[], ['na'], ['ok', 'na'], ['unexpected']]:
            with self.subTest(levels=levels):
                self.assertEqual(env._worst([{'status': x} for x in levels]), env.NA)

    def test_failure_warning_and_known_good_priorities(self):
        for values, expected in [(['ok'], 'ok'), (['warn', 'na'], 'warn'), (['fail', 'warn', 'na'], 'fail')]:
            self.assertEqual(env._worst([{'status': x} for x in values]), expected)

    def test_update_event_permission_failure_is_in_summary(self):
        with patch.object(env, '_run', return_value=(0, 'START_TYPE : 3 DEMAND_START')), \
                patch.object(env, '_ps', side_effect=RuntimeError('access denied')):
            result = env.check_windows_update({}, {})
        self.assertEqual(result['status'], env.NA)
        self.assertEqual(result['items'][-1]['status'], env.NA)

    def test_service_query_failure_not_reported_stopped(self):
        with patch.object(env, '_run', return_value=(-1, 'access denied')), \
                patch.object(env, '_ps', side_effect=RuntimeError('access denied')):
            result = env.check_windows_update({}, {})
        self.assertEqual(result['items'][0]['status'], env.NA)

    def test_snapshot_parse_failure_not_reported_zero(self):
        with patch.object(env, '_find_vmrun', return_value=('vmrun', 'fixture')), \
                patch.object(env, '_default_vmx_list', return_value=['fixture.vmx']), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(env, '_run', side_effect=[(0, 'Total running VMs: 0\n'), (0, 'unrecognized output')]):
            result = env.check_vm({}, {})
        self.assertEqual(result['items'][-1]['status'], env.NA)
        self.assertNotIn('没有任何快照', result['items'][-1]['detail'])

    def test_service_health_uses_cheap_version_endpoint(self):
        opened = []
        class Opener:
            def open(self, url, **kwargs):
                opened.append(url)
                return io.BytesIO(json.dumps({'source_fingerprint': 'fixture'}).encode())
        with patch.object(env, '_read_json', return_value={'server_url': 'http://127.0.0.1:8787'}), \
                patch.object(env.urllib.request, 'build_opener', return_value=Opener()):
            result = env.check_network({'platform_urls': []}, {'platform_urls': []})
        self.assertEqual(opened, ['http://127.0.0.1:8787/version'])
        self.assertEqual(result['items'][-1]['status'], env.OK)


class ScreenshotWPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=r'D:\Temp' if sys.platform == 'win32' and Path(r'D:\Temp').is_dir() else None)
        self.root = Path(self.tmp.name)
        self.patcher = patch.object(wp, 'ROOT', self.root / 'cases')
        self.patcher.start()
        wp.init({'case': 'fixture', 'title': '自建截图规范验收'})
        wp.intake({'case': 'fixture', 'description': '仅用于软件回归的自建样例，不计真实解题率。'})
        self.image = self.root / 'fixture.png'
        self.image.write_bytes(PNG)

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def call(self, stdout='fixture output'):
        args = {'wp_purpose': '检查自建样例输出'}
        started = wp.begin_call('fixture', 'fixture', args)
        result = wp.record_call('fixture', args, {'tool': 'fixture', 'ok': True,
            'result': {'stdout': stdout}, 'wp_operation': started})
        wp.note({'case': 'fixture', 'status': 'observed', 'source_step': result['step'], 'text': '读取实际自建输出。'})
        return result['step']

    def capture(self, step, stage='process'):
        return wp.capture({'case': 'fixture', 'mode': 'file', 'file_path': str(self.image),
            'source': 'Software test PNG fixture, not a real challenge screenshot',
            'source_step': step, 'stage': stage, 'caption': '仅为回归测试的图像样例'})

    def sections(self, step):
        for name in ['overview', 'analysis', 'solution', 'validation', 'reproduction']:
            wp.section({'case': 'fixture', 'section': name, 'text': '自建样例章节及实际证据引用。', 'source_steps': [step]})

    def test_text_only_writeup_is_incomplete(self):
        step = self.call()
        self.sections(step)
        review = wp.review({'case': 'fixture'})
        self.assertFalse(review['quality']['document_complete'])
        self.assertIn('missing_process_screenshot', {x['code'] for x in review['issues']})
        self.assertTrue(any('截图' in gap for gap in Product(self.root).writeup_gate(wp.case_dir('fixture'))))

    def test_flag_needs_linked_result_image(self):
        step = self.call('flag{software_regression_fixture}')
        self.capture(step, 'process')
        self.sections(step)
        review = wp.review({'case': 'fixture'})
        self.assertIn('missing_result_screenshot', {x['code'] for x in review['issues']})
        self.assertFalse(review['quality']['document_complete'])

    def test_multiline_flag_output_is_detected_before_json_escaping(self):
        from ctf_wp_policy import guidance, flags_in
        response = {'result': {'data': {'snapshot': {'text': '实际执行结果\nflag{newline_fixture}\n结束'}}},
                    'wp_record': {'step': 14}}
        self.assertEqual(guidance('web_browser_session', response)['stage'], 'result')
        self.assertEqual(flags_in(response), ['flag{newline_fixture}'])

    def test_process_and_result_images_complete_document_without_certifying_flag(self):
        first = self.call()
        self.capture(first)
        last = self.call('flag{software_regression_fixture}')
        self.capture(last, 'result')
        self.sections(last)
        review = wp.review({'case': 'fixture'})
        self.assertTrue(review['quality']['document_complete'])
        self.assertEqual(review['screenshot_evidence']['process_count'], 1)
        self.assertEqual(review['screenshot_evidence']['result_count'], 1)
        self.assertFalse(review['platform_answer_verified'])

    def test_one_appropriate_image_can_document_process_and_result(self):
        step = self.call('flag{shared_image_fixture}')
        self.capture(step, 'process_and_result')
        self.sections(step)
        review = wp.review({'case':'fixture'})
        self.assertTrue(review['quality']['document_complete'])
        self.assertEqual(len(review['screenshot_evidence']['images']), 1)
        self.assertEqual(review['screenshot_evidence']['process_count'], 1)
        self.assertEqual(review['screenshot_evidence']['result_count'], 1)
        result = wp.build({'case':'fixture', 'formats':[]})
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertEqual(sum(x['type']=='image' for x in model['blocks']), 1)

    def test_result_image_must_reference_actual_call(self):
        step = self.call()
        for source in [None, True, 9999, 1]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.capture(source, 'result')

    def test_log_render_never_counts_as_real_capture(self):
        step = self.call()
        folder = wp.case_dir('fixture')
        target = folder / 'fake-log.png'
        target.write_bytes(PNG)
        with wp.locked(folder):
            wp.append(folder, 'capture', {'source_step': step}, [wp.file_record(folder, target, 'log_render')])
        review = wp.review({'case': 'fixture'})
        self.assertEqual(review['screenshot_evidence']['process_count'], 0)

    def test_build_defaults_embed_images_and_label_incomplete_draft(self):
        step = self.call()
        self.capture(step)
        result = wp.build({'case': 'fixture', 'formats': [], 'private_bundle': True})
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertTrue(model['include_images'])
        self.assertTrue(any(b['type'] == 'image' for b in model['blocks']))
        self.assertIn('草稿', model['title'])
        self.assertFalse(list(Path(result['model_path']).parent.glob('images/*-log.png')))

    def test_disabling_images_cannot_claim_complete_document(self):
        step = self.call()
        self.capture(step)
        self.sections(step)
        result = wp.build({'case': 'fixture', 'formats': [], 'include_images': False})
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertFalse(model['quality']['quality']['document_complete'])
        self.assertIn('草稿', model['title'])

    def test_unrelated_process_capture_not_called_flag_screen(self):
        first = self.call()
        self.capture(first)
        self.call('flag{software_regression_fixture}')
        result = wp.build({'case': 'fixture', 'formats': []})
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        captions = [b.get('caption', '') for b in model['blocks'] if b['type'] == 'image']
        self.assertFalse(any('解出时' in s or '结果截图' in s for s in captions))


if __name__ == '__main__':
    unittest.main(verbosity=2)
