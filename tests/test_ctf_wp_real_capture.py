"""Screenshot evidence regression; generated fixtures are software tests only."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import ctf_wp as wp
from ctf_wp_capture_review import review


class RealCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='D:/Temp')
        self.root = Path(self.temp.name)
        self.patch = patch.object(wp, 'ROOT', self.root / 'cases')
        self.patch.start()
        wp.init({'case': 'sample'})
        started = wp.begin_call('sample', 'fixture', {'wp_purpose': 'software regression'})
        self.step = wp.record_call('sample', {}, {'tool': 'fixture', 'ok': True,
            'result': {'stdout': 'flag{unit_test_only}'}, 'wp_operation': started})['step']
        from PIL import Image, ImageDraw
        self.image = self.root / 'fixture.png'
        frame = Image.new('RGB', (640, 240), 'white')
        ImageDraw.Draw(frame).text((20, 20), 'SOFTWARE FIXTURE ONLY', fill='black')
        frame.save(self.image)

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def capture(self):
        return wp.capture({'case': 'sample', 'mode': 'file', 'file_path': str(self.image),
            'source': 'Software test fixture only', 'source_step': self.step,
            'stage': 'process_and_result'})

    def decision(self, captured, **changes):
        args = {'case': 'sample', 'image_step': captured['step'], 'image_sha256': wp.digest(self.image),
                'verdict': 'accepted', 'capture_origin': 'live_screen',
                'observed_content': 'Software fixture only; no actual challenge screenshot',
                'reason': 'Unit test for review bookkeeping only'}
        args.update(changes)
        return review(args)

    def test_unreviewed_png_and_caption_do_not_count(self):
        self.capture()
        evidence = wp.review({'case': 'sample'})['screenshot_evidence']
        self.assertEqual(evidence['process_count'], 0)
        self.assertEqual(evidence['excluded_count'], 1)

    def test_review_must_match_original_digest(self):
        image = self.capture()
        with self.assertRaisesRegex(ValueError, 'SHA256|sha256'):
            self.decision(image, image_sha256='0' * 64)

    def test_log_or_reconstruction_cannot_be_accepted(self):
        image = self.capture()
        for origin in ['rendered_log', 'reconstructed', 'unknown']:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.decision(image, capture_origin=origin)

    def test_blank_and_tiny_images_cannot_be_accepted(self):
        from PIL import Image
        for size in [(640, 240), (24, 24)]:
            Image.new('RGB', size, 'white').save(self.image)
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.decision(self.capture())

    def test_rejected_locked_desktop_stays_out_of_word(self):
        image = self.capture()
        self.decision(image, verdict='rejected',
                      observed_content='Only a lock/login screen is visible',
                      reason='No original solving tool, command or result is visible')
        result = wp.build({'case': 'sample', 'formats': [], 'private_bundle': True})
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertFalse(any(x['type'] == 'image' for x in model['blocks']))
        self.assertEqual(result['images_included'], 0)
        self.assertTrue(list(Path(result['model_path']).parent.glob('evidence/**/*.png')))

    def test_reviewed_duplicate_is_shown_once_and_flag_not_certified(self):
        for _ in range(2):
            self.decision(self.capture())
        result = wp.build({'case': 'sample', 'formats': []})
        self.assertEqual(result['images_included'], 1)
        model = json.loads(Path(result['model_path']).read_text(encoding='utf-8'))
        self.assertEqual(sum(x['type'] == 'image' for x in model['blocks']), 1)
        self.assertFalse(result['platform_answer_verified'])

    def test_explicit_log_render_option_is_rejected(self):
        with self.assertRaisesRegex(ValueError, '日志渲染'):
            wp.build({'case': 'sample', 'formats': [], 'include_log_renders': True})

    def test_later_rejection_supersedes_acceptance_without_changing_original(self):
        image = self.capture()
        self.decision(image)
        self.decision(image, verdict='rejected', reason='Subsequent inspection found this unrelated to the solving action')
        self.assertEqual(wp.review({'case': 'sample'})['screenshot_evidence']['process_count'], 0)
        self.assertEqual(wp.digest(self.image), wp.digest(image['path']))


if __name__ == '__main__':
    unittest.main()
