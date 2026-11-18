import importlib.util
import unittest
import sys
from pathlib import Path


sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ci'))

spec = importlib.util.spec_from_file_location('engine_releases', Path(__file__).resolve().parents[1]/'ci/engine_releases.py')
engine = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(engine)
except FileNotFoundError:
    engine = None

def release(tag='v2.0.0', prerelease=False):
    return {'tag_name':tag,'prerelease':prerelease,'draft':False,'assets':[{'name':'engine-arm64.tar.gz','browser_download_url':'https://github.com/official/engine/releases/download/'+tag+'/engine-arm64.tar.gz','digest':'sha256:'+'a'*64}]}

class LatestEnginePolicy(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(engine, 'latest engine resolver absent')
    def test_newer_compatible_selected_without_ceiling(self):
        chosen, rejected = engine.select_compatible([release('v99.0.0'),release('v1.0.0')],lambda r: None)
        self.assertEqual(chosen['tag_name'],'v99.0.0')
        self.assertEqual(rejected,[])
    def test_incompatible_newer_falls_back_only_after_validation(self):
        seen=[]
        def check(r):
            seen.append(r['tag_name'])
            if r['tag_name']=='v2.0.0':raise engine.Incompatible('Gecko fields removed')
        chosen,rejected=engine.select_compatible([release(),release('v1.0.0')],check)
        self.assertEqual(seen,['v2.0.0','v1.0.0'])
        self.assertEqual(chosen['tag_name'],'v1.0.0')
        self.assertEqual(rejected[0]['reason'],'Gecko fields removed')
    def test_upstream_failure_is_not_compatibility_fallback(self):
        def check(r):raise engine.IntegrityError('API unavailable')
        with self.assertRaises(engine.IntegrityError):engine.select_compatible([release(),release('v1.0.0')],check)
    def test_http_404_is_not_found_but_other_errors_stay_integrity_failures(self):
        import io, urllib.error
        from unittest import mock
        api = engine.OfficialAPI()
        def raise_code(code):
            def opener(*a, **k):
                raise urllib.error.HTTPError('https://api.github.com/x', code, 'x', {}, io.BytesIO(b''))
            return opener
        with mock.patch('urllib.request.urlopen', raise_code(404)):
            with self.assertRaises(engine.NotFound):
                api.json('o/r/contents/a.go?ref=v1')
        with mock.patch('urllib.request.urlopen', raise_code(503)):
            with self.assertRaises(engine.IntegrityError) as caught:
                api.json('o/r/contents/a.go?ref=v1')
            self.assertNotIsInstance(caught.exception, engine.NotFound)
        self.assertTrue(issubclass(engine.NotFound, engine.IntegrityError))
    def test_missing_and_mismatched_digest_abort(self):
        item=release()['assets'][0]
        item.pop('digest')
        with self.assertRaises(engine.IntegrityError):engine.validate_asset(item,'official/engine','v2.0.0')
        item['digest']='sha256:'+'a'*64
        with self.assertRaises(engine.IntegrityError):engine.verify_bytes(b'changed',item)
    def test_prereleases_and_drafts_excluded(self):
        draft=release('v100.0.0');draft['draft']=True
        chosen,_=engine.select_compatible([draft,release('v99.0.0',True),release('v2.0.0')],lambda r:None)
        self.assertEqual(chosen['tag_name'],'v2.0.0')
    def test_all_incompatible_has_no_unverified_default(self):
        def check(r):raise engine.Incompatible('unsupported full profile contract')
        with self.assertRaises(engine.Incompatible):engine.select_compatible([release()],check)


class ExactResolvedLock(unittest.TestCase):
    def test_missing_or_mixed_source_lock_is_rejected(self):
        import tempfile
        buildspec=importlib.util.spec_from_file_location('buildlib',Path(__file__).resolve().parents[1]/'ci/buildlib.py')
        build=importlib.util.module_from_spec(buildspec);buildspec.loader.exec_module(build)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'build').mkdir();(root/'out').mkdir()
            (root/'build/versions.lock.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'resolved'):
                build.load_resolved_lock(root,root/'out')

class ReleaseInputBoundary(unittest.TestCase):
    def test_malicious_tag_archive_and_url_rejected(self):
        for tag, name, url in [
            ('v2.0.0\nEVIL:=yes', 'engine.tar.gz', None),
            ('v2.0.0', '..', None),
            ('v2.0.0', '$(shell touch evil).tar.gz', None),
            ('v2.0.0', 'engine.tar.gz', 'https://attacker.invalid/engine.tar.gz'),
        ]:
            asset={'name':name,'browser_download_url':url or f'https://github.com/official/engine/releases/download/{tag}/{name}','digest':'sha256:'+'a'*64}
            with self.subTest(tag=tag,name=name), self.assertRaises(engine.IntegrityError):
                engine.validate_asset(asset,'official/engine',tag)
    def test_exact_component_architecture_asset_relationship(self):
        item={'version':'99.1.0','release_tag':'v99.1.0','archive':'sing-box-99.1.0-linux-arm64-musl.tar.gz',
              'url':'https://github.com/SagerNet/sing-box/releases/download/v99.1.0/sing-box-99.1.0-linux-arm64-musl.tar.gz','sha256':'a'*64,
              'validation_asset':{'name':'sing-box-99.1.0-linux-amd64-musl.tar.gz','url':'https://github.com/SagerNet/sing-box/releases/download/v99.1.0/sing-box-99.1.0-linux-amd64-musl.tar.gz','sha256':'b'*64}}
        engine.validate_selection('sing_box',item)
        item['validation_asset']['name']=item['archive']
        with self.assertRaises(engine.IntegrityError):engine.validate_selection('sing_box',item)

class ResolvedLockPayloadGate(unittest.TestCase):
    def setUp(self):
        import copy, hashlib, json, sys, tempfile
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ci'))
        import buildlib
        self.build=buildlib; self.json=json
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); (self.root/'build').mkdir();(self.root/'out').mkdir()
        reference=json.loads((Path(__file__).resolve().parents[1]/'build/versions.lock.json').read_text())
        # This fixture deliberately tests the historical official-release layout.
        reference['sing_box']={'version':'1.14.2','packaging':'official-prebuilt-release','libc':'musl'}
        source=json.dumps(reference).encode();(self.root/'build/versions.lock.json').write_bytes(source)
        self.lock=copy.deepcopy(reference)
        components={}
        for name,repo in engine.REPOSITORIES.items():
            arm,host=engine.asset_names(name,'99.1.0')
            item={'version':'99.1.0','release_tag':'v99.1.0','archive':arm,'url':f'https://github.com/{repo}/releases/download/v99.1.0/{arm}','sha256':'a'*64,
                'validation_asset':{'name':host,'url':f'https://github.com/{repo}/releases/download/v99.1.0/{host}','sha256':'b'*64},
                'compatibility':{'level':'arm64-static-and-matching-amd64-native-config','cases':['fixture'],'arm64_binary_sha256':'c'*64,'host_binary_sha256':'d'*64,'hardware_tested':False,'end_to_end_tested':False}}
            item['compatibility']['payload_sha256']={'usr/share/licenses/'+('sing-box' if name=='sing_box' else name)+'/LICENSE':'a'*64}
            if name=='zapret2':
                item['compatibility']['payload_sha256'].update({'usr/share/flr-bypass/lua/'+helper+'.lua':'b'*64 for helper in ['zapret-lib','zapret-antidpi','zapret-auto']})
            components[name]=item
            selected=self.lock['sing_box'] if name=='sing_box' else self.lock['native'][name]
            selected.update({k:item[k] for k in ['version','release_tag','archive','url','sha256']})
        for field in ['module','tools']:
            from awg_release import REQUIRED
            paths=['src/uapi/wireguard.h','src/netlink.c'] if field=='module' else ['src/uapi/linux/linux/wireguard.h','src/config.c']
            components['awg_'+field]={'version':'99.1.0','tag_name':'v99.1.0','commit':'e'*40,'uapi':{key:index for index,key in enumerate(REQUIRED)},'source_blobs':{path:{'git_blob':'f'*40,'sha256':'a'*64} for path in paths}}
            self.lock['awg'][field+'_version']='99.1.0';self.lock['awg'][field+'_commit']='e'*40
        self.lock['engine_resolution']={'format':'flr-engine-resolution-v1','policy':'latest-compatible-stable','source_commit':'f'*40,'source_lock_sha256':hashlib.sha256(source).hexdigest(),'contract_sha256':'a'*64,'components':components,'hardware_tested':False,'end_to_end_tested':False}
    def load(self):
        (self.root/'out/resolved-versions.lock.json').write_text(self.json.dumps(self.lock))
        return self.build.load_resolved_lock(self.root,self.root/'out','f'*40)
    def test_newer_exact_selection_accepted(self):
        self.assertEqual(self.load()['sing_box']['version'],'99.1.0')
    def test_mixed_payload_platform_and_provenance_rejected(self):
        for key in ['payload','platform','source','host-digest','awg-commit','package-path','missing-lua','missing-awg-field']:
            import copy
            original=copy.deepcopy(self.lock)
            if key=='payload':self.lock['native']['xray']['sha256']='b'*64
            if key=='platform':self.lock['openwrt']['kernel']='99.0'
            if key=='source':self.lock['engine_resolution']['source_commit']='a'*40
            if key=='host-digest':self.lock['engine_resolution']['components']['xray']['validation_asset']['sha256']='bad'
            if key=='awg-commit':
                self.lock['awg']['module_commit']='$(shell evil)';self.lock['engine_resolution']['components']['awg_module']['commit']='$(shell evil)'
            if key=='missing-lua':self.lock['engine_resolution']['components']['zapret2']['compatibility']['payload_sha256'].pop('usr/share/flr-bypass/lua/zapret-lib.lua')
            if key=='missing-awg-field':
                for field in ['module','tools']:self.lock['engine_resolution']['components']['awg_'+field]['uapi'].pop('WGDEVICE_A_HEADER_PROTECTION_KEY')
            if key=='package-path':self.lock['native']['xray']['binary']='etc/evil'
            with self.subTest(key=key), self.assertRaises(ValueError):self.load()
            self.lock=original


class BoundedReleasePagination(unittest.TestCase):
    def test_small_pages_skip_prereleases_and_preserve_newest_stable(self):
        import json
        class Fixture(engine.OfficialAPI):
            def __init__(self):self.paths=[]
            def read(self,url,limit=engine.MAX_DOWNLOAD):
                path=url.split('/repos/')[1];self.paths.append(path)
                data={'official/engine/releases/latest':release('v9.0.0')}
                pages=[[release('v10.0.0',True),release('v9.0.0')],
                       [release('v8.0.0'),release('v7.0.0')],
                       [release('v6.0.0'),release('v5.0.0')],
                       [release('v4.0.0'),release('v3.0.0')],
                       [release('v2.0.0'),release('v1.0.0')]]
                data.update({'official/engine/releases?per_page=2&page='+str(i+1):page for i,page in enumerate(pages)})
                self.assert_small(limit)
                return json.dumps(data[path]).encode()
            def assert_small(self,limit):assert limit==8*1024*1024
        api=Fixture();items=api.releases('official/engine')
        self.assertEqual([r['tag_name'] for r in items],['v'+str(n)+'.0.0' for n in range(9,1,-1)])
        self.assertEqual(len(api.paths),6)
    def test_history_page_budget_is_bounded_even_when_all_prerelease(self):
        class Fixture(engine.OfficialAPI):
            def __init__(self):self.pages=[]
            def json(self,path):
                if path.endswith('/latest'):return release('v1.0.0')
                self.pages.append(path)
                return [release('v99.0.0',True),release('v98.0.0',True)]
        api=Fixture();items=api.releases('official/engine')
        self.assertEqual(len(api.pages),16)
        self.assertEqual([r['tag_name'] for r in items],['v1.0.0'])
    def test_oversized_history_page_aborts_without_increasing_json_bound(self):
        import io,json
        from unittest.mock import patch
        from contextlib import closing
        def response(request,timeout):
            data=json.dumps(release()).encode() if request.full_url.endswith('/latest') else b' '* (8*1024*1024+1)
            return closing(io.BytesIO(data))
        with patch('urllib.request.urlopen',side_effect=response):
            with self.assertRaisesRegex(engine.IntegrityError,'exceeds bounded size'):
                engine.OfficialAPI().releases('official/engine')

if __name__=='__main__':unittest.main()
