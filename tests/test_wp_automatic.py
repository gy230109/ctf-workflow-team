"""Automatic evidence invariants: begin/end, real assets and private export."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import ctf_wp as wp
import ctf_os


class AutomaticWPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.patcher=patch.object(wp,'ROOT',self.root/'cases');self.patcher.start()
        wp.init({'case':'automatic','title':'Self-built automatic evidence check'})
    def tearDown(self):
        self.patcher.stop();self.tmp.cleanup()
    def image(self):
        from PIL import Image
        import random as _random
        # 20261030 口径：截图须通过像素核验（>=200x100、非纯色）；
        # 100x80 纯蓝图会被 frame_check 拒绝，改用可读噪声图。
        p=self.root/'actual-fixture.png'
        img=Image.new('RGB',(400,200));px=img.load()
        _random.seed(42)
        for y in range(200):
            for x in range(400):
                px[x,y]=(_random.randint(0,255),_random.randint(0,255),_random.randint(0,255))
        img.save(p);return p
    def test_begin_without_completion_is_pending_and_never_replayed(self):
        started=wp.begin_call('automatic','fixture',{})
        state=wp.status({'case':'automatic'})
        self.assertEqual(state['pending_operations'][0]['operation_id'],started['operation_id'])
        export=wp.build({'case':'automatic'})
        self.assertFalse(export['recording_complete'])
        self.assertIn(started['operation_id'],export['pending_operations'])
    def test_purpose_is_recorded_but_not_sent_to_algorithm(self):
        real=ctf_os._call_tool
        seen=[]
        def execute(name,args):seen.append(dict(args));return real(name,args)
        with patch.object(ctf_os,'_call_tool',side_effect=execute):
            result=ctf_os.call_tool('math_gcd',{'wp_case':'automatic','values':[12,18],'wp_purpose':'验证公因子','wp_expectation':'输出整数'})
        self.assertTrue(result['ok']);self.assertNotIn('wp_purpose',seen[0])
        self.assertFalse(wp.status({'case':'automatic'})['pending_operations'])
        report=wp.build({'case':'automatic'})
        self.assertIn('验证公因子',Path(report['path']).read_text(encoding='utf-8'))
    def test_hashed_asset_is_copied_and_private_bundle_is_portable(self):
        image=self.image();cast=self.root/'record.cast';cast.write_text('{"version":2,"width":80,"height":24}\n[0,"o","actual fixture output"]\n')
        assets=[{'path':str(p),'sha256':wp.digest(p),'kind':kind,'source':'self-built fixture'} for p,kind in [(image,'browser_screenshot'),(cast,'terminal_recording')]]
        result=wp.record_call('automatic',{}, {'tool':'fixture','ok':True,'result':{'evidence_artifacts':assets}})
        self.assertEqual(result['assets'],2)
        # 20261030 口径：图片须先经 wp_capture_review accepted 才计入嵌入。
        from ctf_wp_capture_review import review
        review({'case':'automatic','image_step':result['step'],'image_sha256':wp.digest(image),
                'verdict':'accepted','capture_origin':'live_browser',
                'observed_content':'自建样例：400x200 噪声图，验证资产复制链路',
                'reason':'回归测试样例，非真实赛题截图'})
        report=wp.build({'case':'automatic','include_images':True,'private_bundle':True})
        self.assertEqual(report['images_included'],1);self.assertEqual(report['recordings_included'],1)
        with zipfile.ZipFile(report['bundle_path']) as archive:
            self.assertIn('evidence/timeline.jsonl',archive.namelist())
            self.assertTrue(any(p.startswith('recordings/') for p in archive.namelist()))
        image.unlink();cast.unlink()
        self.assertTrue(wp.status({'case':'automatic'})['integrity_verified'])
    def test_bad_hash_marks_gap_without_repeating_tool(self):
        image=self.image()
        calls=[]
        def execute(*_):
            calls.append(1)
            return {'ok':True,'result':{'evidence_artifacts':[{'path':str(image),'sha256':'0'*64,'kind':'browser_screenshot'}]}}
        with patch.object(ctf_os,'_call_tool',side_effect=execute):
            result=ctf_os.call_tool('math_gcd',{'wp_case':'automatic','values':[1,2]})
        self.assertEqual(len(calls),1);self.assertTrue(result['ok'])
        self.assertTrue(result['wp_record']['capture_errors'])
        self.assertFalse(wp.build({'case':'automatic'})['recording_complete'])
    def test_old_export_exclusion_does_not_embed_pixel_traces(self):
        image=self.image()
        wp.record_call('automatic',{}, {'tool':'fixture','ok':True,'result':{'evidence_artifacts':[{'path':str(image),'sha256':wp.digest(image),'kind':'browser_screenshot'}]}})
        report=wp.build({'case':'automatic','include_images':False})
        self.assertEqual(report['images_included'],0)
        with zipfile.ZipFile(report['bundle_path']) as archive:self.assertFalse(any('actual-fixture' in p or p.startswith('evidence/') for p in archive.namelist()))
    def test_imported_image_observation_stays_attached(self):
        capture=wp.capture({'case':'automatic','mode':'file','file_path':str(self.image()),'source':'self-built image'})
        wp.note({'case':'automatic','status':'observed','source_step':capture['step'],'text':'图注对应此步骤'})
        report=wp.build({'case':'automatic','include_images':True})
        self.assertIn('图注对应此步骤',Path(report['path']).read_text(encoding='utf-8'))

if __name__=='__main__':unittest.main(verbosity=2)
