"""Regression coverage for readable WP prose without weakening the evidence."""
import importlib.util
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


class EvidenceNarrativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.root_patch = patch.object(wp, 'ROOT', self.folder / 'cases')
        self.root_patch.start()
        wp.init({'case': 'fixture', 'title': '自建格式回归样例', 'category': 'misc'})

    def tearDown(self):
        self.root_patch.stop()
        self.temp.cleanup()

    def build(self, **extra):
        args = dict(case='fixture', formats=[], include_images=True, private_bundle=True, expose_flag=True)
        args.update(extra)
        result = wp.build(args)
        return result, json.loads(Path(result['model_path']).read_text(encoding='utf-8'))

    def call(self, text='actual fixture output', **arguments):
        return wp.record_call('fixture', arguments, {'tool': 'fixture', 'ok': True, 'result': text})

    def test_prose_markers_become_structure_without_changing_code(self):
        code = '# actual comment\nprint("a*b#c")\n#include <stdio.h>'
        blocks = report.prose_blocks('## 观察结果\n\n发现 **固定前缀**，检查 `value_name`。\n\n```python\n' + code + '\n```')
        self.assertEqual(blocks[0]['text'], '观察结果')
        self.assertEqual(blocks[1]['text'], '发现 固定前缀，检查 value_name。')
        self.assertEqual(blocks[2], {'type': 'code', 'text': code})
        self.assertEqual(report.inline_text('`a*b*c` 与 https://example.test/#part'),
                         'a*b*c 与 https://example.test/#part')

    def test_prose_never_loads_unreviewed_markdown_images(self):
        blocks = report.prose_blocks('![所谓证据](../../outside.png)\n\n![外图](https://example.test/proof.png)')
        self.assertFalse(any(block['type'] in {'image', 'link'} for block in blocks))
        self.assertIn('outside.png', str(blocks))

    def test_table_markup_and_unclosed_code_do_not_leak_into_prose(self):
        blocks = report.prose_blocks('| 字段 | 结果 |\n| --- | --- |\n| `a_b` | **42** |\n\n~~~text\n# literal\na*b')
        self.assertEqual(blocks[0]['rows'], [['a_b', '42']])
        self.assertEqual(blocks[1]['text'], '# literal\na*b')

    def test_stdout_is_readable_and_metadata_and_errors_are_preserved(self):
        shown = report.output_text({'stdout': 'first\nsecond\n', 'stderr': 'actual error', 'exit_code': 9})
        self.assertIn('stdout:\nfirst\nsecond', shown)
        self.assertIn('stderr:\nactual error', shown)
        self.assertIn('exit_code: 9', shown)
        self.assertNotIn('first\\nsecond', shown)

    def test_old_export_cache_is_invalidated_after_the_formatter_upgrade(self):
        from ctf_product import Product, save, sha
        import ctf_competition as competition
        task_id = 'ctf-' + '1' * 16
        product = Product(self.folder)
        task_folder = product.state / task_id
        task_folder.mkdir(parents=True)
        old_word = self.folder / 'old.docx'
        old_word.write_bytes(b'old cached document')
        export_args = dict(case=task_id, include_images=True, include_log_renders=False,
                           expose_flag=False, summary='', formats=['docx'], bundle=False, private_bundle=True)
        task = dict(task_id=task_id, title='fixture', events=[], answer_verified=False,
                    delivery=dict(path=str(old_word), sha256=sha(old_word)))
        task['competition_export'] = {'key': competition.export_key(task, export_args)}
        save(task_folder / 'task.json', task)
        with patch('ctf_product.protocol.before_finish'), \
             patch.object(product, 'sync_wp_context', return_value={'ok': True}), \
             patch.object(product, 'writeup_gate', return_value=[]), \
             patch.object(product, 'core', return_value={'ok': False, 'error': 'fixture rebuild requested'}) as core:
            response = product.finish(task_id)
        self.assertEqual(response['error'], 'fixture rebuild requested')
        self.assertEqual(core.call_args.args[0], 'wp_build')

    def test_missing_analysis_is_not_filled_with_repeated_action_purposes(self):
        self.call(wp_purpose='检查自建附件文件头')
        _, model = self.build()
        paragraphs = [block['text'] for block in model['blocks'] if block['type'] == 'paragraph']
        self.assertTrue(any('未记录分析思路' in text for text in paragraphs))
        self.assertIn('analysis', model['quality']['quality']['missing_sections'])
        self.assertFalse(model['quality']['platform_answer_verified'])

    def test_long_inputs_and_outputs_remain_recoverable_with_explicit_excerpt_notice(self):
        payload = 'A' * 5000 + '#tail*'
        output = 'real-output ' * 1000
        call = self.call(output, payload=payload, wp_purpose='检查长输入是否完整保存')
        wp.section({'case': 'fixture', 'section': 'solution', 'text': '用原输入检查输出。', 'source_steps': [call['step']]})
        result, model = self.build()
        step = model['steps'][0]
        raw = json.loads((Path(result['path']).parent / step['evidence_ref']).read_text(encoding='utf-8'))
        self.assertEqual(raw['arguments']['payload'], payload)
        self.assertEqual(raw['response']['result'], output)
        self.assertIn(payload, step['operation_text'])
        text = Path(result['path']).read_text(encoding='utf-8')
        self.assertIn('以上参数为节选', text)
        self.assertIn('以上输出为节选', text)
        self.assertIn('证据记录：步骤 %d' % call['step'], text)

    def test_capture_is_embedded_with_its_action_and_only_once(self):
        from PIL import Image
        from ctf_wp_capture_review import review
        first = self.call('flag{fixture_image_only}', wp_purpose='观察自建输出')
        other = self.call('other fixture output', wp_purpose='检查后续数据')
        image = self.folder / 'fixture.png'
        Image.effect_noise((400, 200), 80).convert('RGB').save(image)
        captured = wp.capture({'case': 'fixture', 'mode': 'file', 'file_path': str(image),
                               'source': 'test fixture only', 'source_step': first['step'],
                               'stage': 'process_and_result', 'caption': '自建关联测试图片，并非真实赛题证据'})
        event = wp.records(wp.case_dir('fixture'))[captured['step'] - 1]
        review({'case': 'fixture', 'image_step': captured['step'], 'image_sha256': event['files'][0]['sha256'],
                'verdict': 'accepted', 'capture_origin': 'live_screen', 'stage': 'process_and_result',
                'observed_content': '自建随机像素图片，仅用于检查证据关联排版',
                'reason': '测试专用数据，不写入任何比赛或实际任务'})
        picture = Image.open(image).copy()
        picture.putpixel((0, 0), (1, 2, 3))
        second_image = self.folder / 'second.png'
        picture.save(second_image)
        second_capture = wp.capture({'case': 'fixture', 'mode': 'file', 'file_path': str(second_image),
                                     'source': 'second fixture only', 'source_step': other['step']})
        second_event = wp.records(wp.case_dir('fixture'))[second_capture['step'] - 1]
        review({'case': 'fixture', 'image_step': second_capture['step'], 'image_sha256': second_event['files'][0]['sha256'],
                'verdict': 'accepted', 'capture_origin': 'live_screen',
                'observed_content': '第二张随机像素测试图片，只检查连续图号',
                'reason': '测试专用数据，不写入任何比赛或实际任务'})
        wp.section({'case': 'fixture', 'section': 'solution', 'text': '引用后一步测试主线筛选。', 'source_steps': [other['step']]})
        before = (wp.case_dir('fixture') / 'timeline.jsonl').read_bytes()
        _, model = self.build()
        images = [block for block in model['blocks'] if block['type'] == 'image']
        self.assertEqual(len(images), 2)
        action = next(step for step in model['steps'] if step['source_seq'] == first['step'])
        self.assertTrue(action['in_main_text'])
        self.assertEqual(action['asset_refs'], [images[0]['path']])
        self.assertIn('来源步骤 %d' % first['step'], images[0]['caption'])
        self.assertTrue(images[0]['caption'].startswith('图 1（'))
        self.assertTrue(images[1]['caption'].startswith('图 2（'))
        image_index = model['blocks'].index(images[0])
        later_index = next(i for i, block in enumerate(model['blocks'])
                           if block['type'] == 'heading' and '检查后续数据' in block['text'])
        self.assertLess(image_index, later_index)
        self.assertEqual(before, (wp.case_dir('fixture') / 'timeline.jsonl').read_bytes())

    @unittest.skipUnless(importlib.util.find_spec('docx'), 'python-docx is optional')
    def test_word_contains_readable_prose_and_exact_technical_characters(self):
        from docx import Document
        call = self.call(wp_purpose='核对自建样例')
        code = '# literal comment\nprint("flag{a*b#c}")'
        wp.section({'case': 'fixture', 'section': 'solution', 'source_steps': [call['step']],
                    'text': '## 核对数据\n\n输出中的 **固定字段** 对应 `value_name`。\n\n```python\n' + code + '\n```'})
        result, _ = self.build(formats=['docx'])
        output = Path(result['path']).parent / 'writeup.docx'
        document = Document(output)
        paragraphs = [(paragraph.style.name, paragraph.text) for paragraph in document.paragraphs]
        self.assertIn(('Heading 2', '核对数据'), paragraphs)
        self.assertTrue(any(text == '输出中的 固定字段 对应 value_name。' for _, text in paragraphs))
        code_lines = [text for style, text in paragraphs if style == 'CTF Code']
        self.assertIn('# literal comment', code_lines)
        self.assertIn('print("flag{a*b#c}")', code_lines)
        for style, text in paragraphs:
            if style != 'CTF Code':
                self.assertNotIn('## ', text)
                self.assertNotIn('**', text)
                self.assertNotIn('```', text)
        with zipfile.ZipFile(output) as archive:
            self.assertIn('word/document.xml', archive.namelist())


if __name__ == '__main__':
    unittest.main(verbosity=2)
