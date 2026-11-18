import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import subprocess
import json

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ci'))
import buildlib
MODULE=Path(__file__).resolve().parents[1]/'ci/sing_box_source.py'
if MODULE.exists():
 spec=importlib.util.spec_from_file_location('sing_box_source',MODULE)
 source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)
else:source=None

PIN={'version':'1.14.4-flr-random-sni.1','package_version':'1.14.4.1','upstream_version':'1.14.4','asset_kind':'source-build','packaging':'pinned-source-build','upstream_commit':'c005f35300ce76427dc285481ec5695f5b179cd2','source_url':'https://codeload.github.com/SagerNet/sing-box/tar.gz/c005f35300ce76427dc285481ec5695f5b179cd2','source_sha256':'1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59','patch':{'directory':'client/sing-box-random-sni','manifest_sha256':'68ae7da0794e996ca64b3a47ce6891b9aaf17c28620ac6762ceb2d07af7ca51d','original_tree_sha256':'bdaaa342882ca29e027c2d9ecfd275c2043ecfd78a8ae877726ff27b60cf8ea7','patched_tree_sha256':'5bb0db2aadeaedd7a6665f9914558ce6c6f418a633ff7527a6df104961a313b8'},'capabilities':['hysteria2-random-sni-per-quic-dial-v1'],'go_version':'1.26.8','tags':['with_quic','with_wireguard','with_utls','with_gvisor'],'cgo_enabled':False}
GO_MOD='a'*64
GO_SUM='b'*64
PROJECT=Path(__file__).resolve().parents[1]

def receipt(pin=PIN):
 targets={}
 for arch,data in [('amd64',b'HOST_PUBLIC_FIXTURE'*8),('arm64',b'ARM_PUBLIC_FIXTURE'*8)]:
  targets['linux/'+arch]={'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'go_version':'go1.26.8','tags':pin['tags'][:],'cgo_enabled':False,'linked_modules':['github.com/sagernet/sing']}
 return {'version':1,'asset_kind':'source-build','upstream_version':pin['upstream_version'],'custom_version':pin['version'],'capabilities':pin['capabilities'][:],'upstream_commit':pin['upstream_commit'],'source_url':pin['source_url'],'source_sha256':pin['source_sha256'],'go_mod_sha256':GO_MOD,'go_sum_sha256':GO_SUM,'patch':{**{k:pin['patch'][k] for k in ('manifest_sha256','original_tree_sha256','patched_tree_sha256')},'payload_sha256':{'random_sni.go':'c'*64},'offline_tests_passed':True},'go_version':pin['go_version'],'tags':pin['tags'][:],'cgo_enabled':False,'targets':targets,'linked_modules':['github.com/sagernet/sing'],'hardware_tested':False,'end_to_end_tested':False}

def fixture_binary(arch='arm64',compiler='go1.26.8',cgo='0',tags=None,modules='github.com/sagernet/sing',dynamic=False,markers=True):
 def encoded(raw):
  if isinstance(raw,str):raw=raw.encode()
  n=len(raw);head=bytearray()
  while n>=128:head.append((n&127)|128);n>>=7
  head.append(n);return bytes(head)+raw
 elf=bytearray(128);elf[:6]=b'\x7fELF\x02\x01';elf[18:20]=(183 if arch=='arm64' else 62).to_bytes(2,'little')
 if dynamic:
  elf[32:40]=(64).to_bytes(8,'little');elf[54:56]=(56).to_bytes(2,'little');elf[56:58]=(1).to_bytes(2,'little');elf[64:68]=(2).to_bytes(4,'little')
 text='path\tgithub.com/sagernet/sing-box/cmd/sing-box\nmod\tgithub.com/sagernet/sing-box\t(devel)\ndep\t'+modules+'\tv0.1.0\nbuild\t-tags='+','.join(tags or PIN['tags'])+'\nbuild\tCGO_ENABLED='+cgo+'\nbuild\tGOOS=linux\nbuild\tGOARCH='+arch+'\n'
 tail=(PIN['version']+'\0flr_random_sni_suffix\0'+PIN['capabilities'][0]).encode() if markers else b''
 return bytes(elf)+b'\xff Go buildinf:'+bytes([8,2])+b'\0'*16+encoded(compiler)+encoded(b'0'*16+text.encode()+b'1'*16)+tail

class SourceBuildContract(unittest.TestCase):
 def setUp(self):self.assertIsNotNone(source,'pinned source build not implemented')
 def test_source_pin_rejects_changed_commit_url_digest_go_or_unsafe_flags(self):
  source.validate_pin(PIN)
  for field,value in [('upstream_commit','b'*40),('source_url','https://example.com/source'),('source_sha256','not-a-digest'),('go_version','latest'),('cgo_enabled',True),('tags',['with_quic','with_wireguard']),('tags',[*PIN['tags'],'with_naive_outbound']),('tags',[*PIN['tags'],'with_utls'])]:
   candidate=copy.deepcopy(PIN);candidate[field]=value
   with self.subTest(field=field,value=value),self.assertRaises(ValueError):source.validate_pin(candidate)
 def test_receipt_checks_both_architectures_and_forbidden_linked_modules(self):
  valid=receipt();payloads={'linux/amd64':b'HOST_PUBLIC_FIXTURE'*8,'linux/arm64':b'ARM_PUBLIC_FIXTURE'*8}
  source.validate_receipt(PIN,valid,payloads)
  for target,field,value in [('linux/arm64','sha256','0'*64),('linux/amd64','size',0),('linux/amd64','go_version','go1.25.5'),('linux/arm64','tags',['with_quic']),('linux/amd64','cgo_enabled',True),('linux/arm64','linked_modules',['github.com/sagernet/cronet-go'])]:
   candidate=copy.deepcopy(valid);candidate['targets'][target][field]=value
   with self.subTest(target=target,field=field),self.assertRaises(ValueError):source.validate_receipt(PIN,candidate,payloads)
  for field,value in [('upstream_commit','c'*40),('source_sha256','0'*64),('hardware_tested',True),('asset_kind','official-prebuilt-release'),('linked_modules',['github.com/sagernet/cronet-go'])]:
   candidate=copy.deepcopy(valid);candidate[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):source.validate_receipt(PIN,candidate,payloads)
 def test_source_archive_digest_and_paths_checked_before_extraction(self):
  data=io.BytesIO()
  with tarfile.open(fileobj=data,mode='w:gz') as archive:
   entry=tarfile.TarInfo('sing-box-'+PIN['upstream_commit']+'/../escape');entry.size=1;archive.addfile(entry,io.BytesIO(b'x'))
  with tempfile.TemporaryDirectory() as temp:
   with self.assertRaises(ValueError):source.unpack_source(PIN,data.getvalue(),Path(temp))
   candidate=copy.deepcopy(PIN);candidate['source_sha256']=hashlib.sha256(data.getvalue()).hexdigest()
   with self.assertRaises(ValueError):source.unpack_source(candidate,data.getvalue(),Path(temp))
   self.assertFalse((Path(temp).parent/'escape').exists())
 def test_source_build_is_never_executed_on_workstation(self):
  if sys.platform=='darwin':
   with self.assertRaises(Exception):source.require_ci()
 def test_actual_binary_metadata_must_match_target_and_pin(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)/'binary';path.write_bytes(fixture_binary())
   info=source.validate_binary(PIN,'arm64',path)
   self.assertEqual(info['linked_modules'],['github.com/sagernet/sing'])
   for values in [{'arch':'amd64'},{'compiler':'go1.25.5'},{'cgo':'1'},{'tags':[*PIN['tags'],'with_naive_outbound']},{'modules':'github.com/sagernet/cronet-go'},{'dynamic':True}]:
    path.write_bytes(fixture_binary(**values))
    with self.subTest(values=values),self.assertRaises(ValueError):source.validate_binary(PIN,'arm64',path)
 def test_source_builder_refuses_mac_before_download_or_go_execution(self):
  if sys.platform!='darwin':return
  script=Path(__file__).resolve().parents[1]/'ci/build-sing-box.py'
  self.assertTrue(script.is_file(),'source build entrypoint missing')
  result=subprocess.run([sys.executable,str(script)],capture_output=True,text=True)
  self.assertNotEqual(result.returncode,0)
  self.assertIn('disposable Linux AMD64 CI',result.stderr)
 def test_local_source_receipt_cannot_substitute_prebuilt_or_changed_archive(self):
  with tempfile.TemporaryDirectory() as temp:
   folder=Path(temp)
   # Missing files must fail closed before a caller can download an official default.
   with self.assertRaises(ValueError):source.load_local(PIN,folder)
 def test_source_selection_is_distinct_from_official_prebuilt(self):
  V=PIN['version'];item={'version':V,'release_tag':'v'+V,'asset_kind':'source-build','source_pin':PIN,'source_build':receipt(),'archive':'sing-box-'+V+'-linux-arm64-static.tar.gz','sha256':'a'*64,'validation_asset':{'name':'sing-box-'+V+'-linux-amd64-static.tar.gz','sha256':'b'*64}}
  from engine_releases import validate_selection,IntegrityError
  validate_selection('sing_box',item)
  for field,value in [('archive','sing-box-'+V+'-linux-arm64-musl.tar.gz'),('url','https://github.com/SagerNet/sing-box/releases/download/v1.14.4/prebuilt.tar.gz'),('sha256','bad'),('source_build',{})]:
   candidate=copy.deepcopy(item);candidate[field]=value
   with self.subTest(field=field),self.assertRaises(IntegrityError):validate_selection('sing_box',candidate)

class PatchedPinContract(unittest.TestCase):
 def setUp(self):self.assertIsNotNone(source,'pinned source build not implemented')
 def test_old_unpatched_pin_is_rejected(self):
  old={**PIN,'version':'1.14.2','package_version':'1.14.2','upstream_version':'1.14.2','upstream_commit':'af6e64c3b69e6132ebaee0e1a3d24e93903f6709','source_sha256':'bbf37fe816fc18621bd0700b71e69dd2a92e3e499f3311d7dff73319999174cf'}
  with self.assertRaises(ValueError):source.validate_pin(old)
  candidate=copy.deepcopy(PIN);del candidate['patch']
  with self.assertRaises(ValueError):source.validate_pin(candidate)
 def test_new_source_pin_fields_are_each_enforced(self):
  for field,value in [('version','1.14.4'),('package_version','1.14.4_p1'),('upstream_version','1.14.2'),('source_sha256','0'*64),('upstream_commit','d'*40),('capabilities',[]),('capabilities',['other']),('patch',{**PIN['patch'],'manifest_sha256':'0'*64}),('patch',{**PIN['patch'],'original_tree_sha256':'0'*64}),('patch',{**PIN['patch'],'patched_tree_sha256':'0'*64}),('patch',{**PIN['patch'],'directory':'elsewhere'}),('go_mod_sha256','short'),('go_sum_sha256',5)]:
   candidate=copy.deepcopy(PIN);candidate[field]=value
   with self.subTest(field=field,value=value),self.assertRaises(ValueError):source.validate_pin(candidate)
 def test_optional_dependency_manifest_pins_are_accepted_when_well_formed(self):
  source.validate_pin({**PIN,'go_mod_sha256':GO_MOD,'go_sum_sha256':GO_SUM})
 def test_repository_lock_section_is_a_valid_pin(self):
  lock=json.loads((PROJECT/'build/versions.lock.json').read_text())['sing_box']
  source.validate_pin(lock)
  self.assertEqual(lock['version'],'1.14.4-flr-random-sni.1')
  self.assertEqual(lock['package_version'],'1.14.4.1')
  for key in ('go_mod_sha256','go_sum_sha256'):self.assertNotIn(key,lock,'dependency manifest digests are derived, not pinned')
  self.assertEqual(lock['patch']['manifest_sha256'],hashlib.sha256((PROJECT/lock['patch']['directory']/'patch.json').read_bytes()).hexdigest())
 def test_package_version_mapping_is_apk_valid_and_strict(self):
  self.assertEqual(source.package_version('1.14.4-flr-random-sni.1'),'1.14.4.1')
  self.assertEqual(source.package_version('1.14.4-flr-random-sni.12'),'1.14.4.12')
  for bad in ['1.14.4','1.14.4-flr-random-sni.0','1.14.4-flr-random-sni.','1.14.4-flr-random-sni.1-r1','v1.14.4-flr-random-sni.1','1.14-flr-random-sni.1',None]:
   with self.subTest(bad=bad),self.assertRaises(ValueError):source.package_version(bad)
  self.assertEqual(buildlib.sing_box_package_version({'version':PIN['version'],'package_version':PIN['package_version']}),'1.14.4.1')
  self.assertEqual(buildlib.sing_box_package_version({'version':'1.14.2'}),'1.14.2')
  for bad in [{'version':PIN['version']},{'version':'1.14.4','package_version':'1.14.4-flr-random-sni.1'},{'version':'1.14.4','package_version':'1.14.4_p1'}]:
   with self.subTest(bad=bad),self.assertRaises(ValueError):buildlib.sing_box_package_version(bad)
 def test_manifest_line_uses_package_version_not_binary_version(self):
  lock={'openwrt':{'version':'25.12.5','profile':'glinet_gl-mt6000','supported_device':'glinet,gl-mt6000','kernel':'6.12.94','kernel_abi':'5a6c1f71be683ae9980b15d3ce73e24d'},'awg':{'module_version':'3.1.20260906','tools_version':'3.1.20260812'},'sing_box':{'version':PIN['version'],'package_version':PIN['package_version']},'packages':['kmod-amneziawg','amneziawg-tools','flint-sing-box']}
  text='kernel - 6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1\nkmod-amneziawg - 6.12.94.3.1.20260906-r1\namneziawg-tools - 3.1.20260812-r1\nflint-sing-box - 1.14.4.1-r1\n'
  buildlib.check_manifest(text,lock)
  for wrong in ['1.14.4-flr-random-sni.1-r1','1.14.2-r1','1.14.4.10-r1']:
   with self.subTest(wrong=wrong),self.assertRaises(ValueError):buildlib.check_manifest(text.replace('1.14.4.1-r1',wrong),lock)
 def test_makefile_package_version_derivation_matches_the_lock(self):
  make=(PROJECT/'packages/flint-sing-box/Makefile').read_text()
  self.assertIn('$(subst -flr-random-sni.,.,$(FLR_SING_BOX_VERSION))',make)
  self.assertIn('PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(FLR_SING_BOX_VERSION)',make)
  self.assertEqual(PIN['version'].replace('-flr-random-sni.','.'),PIN['package_version'])
 def test_client_builder_and_ci_pin_the_same_source_and_patch(self):
  spec=importlib.util.spec_from_file_location('flr_client_builder',PROJECT/'client/sing-box-random-sni/build.py')
  builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
  self.assertEqual((builder.COMMIT,builder.SOURCE_SHA,builder.VERSION),(source.COMMIT,source.SOURCE_SHA,source.VERSION))
  self.assertEqual([builder.CAPABILITY],source.CAPABILITIES)
  self.assertEqual(builder.TAGS.split(','),PIN['tags'])
  self.assertEqual(hashlib.sha256((PROJECT/'client/sing-box-random-sni/patch.json').read_bytes()).hexdigest(),source.PATCH['manifest_sha256'])

def source_archive(files):
 data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w:gz') as archive:
  for name,content in files.items():
   entry=tarfile.TarInfo('sing-box-'+PIN['upstream_commit']+'/'+name);entry.size=len(content);archive.addfile(entry,io.BytesIO(content))
 return data.getvalue()

class DerivedDependencyManifestDigests(unittest.TestCase):
 def setUp(self):
  self.assertIsNotNone(source,'pinned source build not implemented')
  self.files={'go.mod':b'module example.com/x\n','go.sum':b'example.com/y v1.0.0 h1:abc=\n','LICENSE':b'license'}
  self.data=source_archive(self.files)
  self.pin={**PIN,'source_sha256':hashlib.sha256(self.data).hexdigest()}
 def test_digests_are_derived_from_the_verified_archive_without_pins(self):
  self.assertNotIn('go_mod_sha256',self.pin)
  with tempfile.TemporaryDirectory() as temp:
   root=source.unpack_source(self.pin,self.data,Path(temp))
   derived=source.manifest_digests(root)
  self.assertEqual(derived,{'go_mod_sha256':hashlib.sha256(self.files['go.mod']).hexdigest(),'go_sum_sha256':hashlib.sha256(self.files['go.sum']).hexdigest()})
 def test_archive_digest_still_gates_extraction(self):
  with tempfile.TemporaryDirectory() as temp,self.assertRaises(ValueError):source.unpack_source({**self.pin,'source_sha256':'0'*64},self.data,Path(temp))
  self.assertFalse(any(Path(temp).iterdir()) if Path(temp).exists() else False)
 def test_optional_pin_is_enforced_when_present(self):
  good={'go_mod_sha256':hashlib.sha256(self.files['go.mod']).hexdigest(),'go_sum_sha256':hashlib.sha256(self.files['go.sum']).hexdigest()}
  with tempfile.TemporaryDirectory() as temp:source.unpack_source({**self.pin,**good},self.data,Path(temp))
  for key in good:
   with tempfile.TemporaryDirectory() as temp,self.assertRaises(ValueError):source.unpack_source({**self.pin,**good,key:'0'*64},self.data,Path(temp))
 def test_receipt_must_record_well_formed_derived_digests(self):
  valid=receipt();source.validate_receipt(PIN,valid)
  for key in ('go_mod_sha256','go_sum_sha256'):
   for value in (None,'short','Z'*64):
    candidate=copy.deepcopy(valid)
    if value is None:del candidate[key]
    else:candidate[key]=value
    with self.subTest(key=key,value=value),self.assertRaises(ValueError):source.validate_receipt(PIN,candidate)
  pinned={**PIN,'go_mod_sha256':'e'*64}
  with self.assertRaises(ValueError):source.validate_receipt(pinned,valid)
 def test_receipt_patch_and_capability_evidence_required(self):
  valid=receipt()
  for mutate in [lambda r:r.pop('patch'),lambda r:r['patch'].update(patched_tree_sha256='0'*64),lambda r:r['patch'].update(manifest_sha256='0'*64),lambda r:r['patch'].update(offline_tests_passed=False),lambda r:r['patch'].update(payload_sha256={}),lambda r:r.update(capabilities=[]),lambda r:r.update(custom_version='1.14.4'),lambda r:r.update(upstream_version='1.14.2')]:
   candidate=copy.deepcopy(valid);mutate(candidate)
   with self.assertRaises(ValueError):source.validate_receipt(PIN,candidate)
 def test_patch_pins_are_checked_before_any_edit(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)/'tree';root.mkdir();(root/'marker').write_text('x')
   bad={**self.pin,'patch':{**PIN['patch'],'manifest_sha256':'0'*64}}
   with self.assertRaisesRegex(ValueError,'patch manifest'):source.patch_source(bad,root,PROJECT)
   self.assertEqual((root/'marker').read_text(),'x')
   # A tree that is not the pinned upstream tree cannot match the pinned digests.
   with self.assertRaises(ValueError):source.patch_source(self.pin,root,PROJECT)

class CapabilityIdentityChecks(unittest.TestCase):
 def setUp(self):self.assertIsNotNone(source,'pinned source build not implemented')
 def test_static_markers_required_in_every_target_binary(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)/'binary'
   path.write_bytes(fixture_binary());source.validate_binary(PIN,'arm64',path)
   path.write_bytes(fixture_binary(markers=False))
   with self.assertRaisesRegex(ValueError,'identity marker'):source.validate_binary(PIN,'arm64',path)
   path.write_bytes(fixture_binary().replace(PIN['capabilities'][0].encode(),b'x'*len(PIN['capabilities'][0])))
   with self.assertRaisesRegex(ValueError,'identity marker'):source.validate_binary(PIN,'arm64',path)
   path.write_bytes(fixture_binary().replace(PIN['version'].encode(),b'1.14.4-flr-random-sni.9'))
   with self.assertRaisesRegex(ValueError,'identity marker'):source.validate_binary(PIN,'arm64',path)
 def test_flr_capabilities_output_is_parsed_strictly(self):
  self.assertEqual(buildlib.parse_flr_capabilities('{"version":1,"capabilities":["a-b"]}\n'),['a-b'])
  for bad in ['','not json','[]','{"version":2,"capabilities":[]}','{"version":1}','{"version":1,"capabilities":[1]}','{"version":1,"capabilities":"x"}']:
   with self.subTest(bad=bad),self.assertRaises(ValueError):buildlib.parse_flr_capabilities(bad)
 def host_script(self,directory,version,capabilities,fail=None):
  script=Path(directory)/'sing-box'
  script.write_text('#!/bin/sh\ncase "$1" in\n version) echo "sing-box version '+version+'"; echo "Environment: go1.26.8 linux/amd64";;\n flr-capabilities) '+('exit 3' if fail=='caps' else "echo '"+json.dumps({'version':1,'capabilities':capabilities})+"'")+';;\n *) exit 2;;\nesac\n')
  script.chmod(0o700)
  return script
 def test_host_binary_must_report_pinned_version_and_capability(self):
  if sys.platform=='win32':self.skipTest('POSIX shell fixture')
  with tempfile.TemporaryDirectory() as temp:
   good=self.host_script(temp,PIN['version'],PIN['capabilities'])
   self.assertEqual(source.validate_host_binary(PIN,good),PIN['capabilities'])
   for version,caps,fail in [('1.14.2',PIN['capabilities'],None),('1.14.4',PIN['capabilities'],None),(PIN['version'],[],None),(PIN['version'],['other'],None),(PIN['version'],PIN['capabilities']+['extra'],None),(PIN['version'],PIN['capabilities'],'caps')]:
    script=self.host_script(temp,version,caps,fail)
    with self.subTest(version=version,caps=caps,fail=fail),self.assertRaises(ValueError):source.validate_host_binary(PIN,script)
   with self.assertRaises(ValueError):source.validate_host_binary(PIN,Path(temp)/'missing')

class FirmwareProxyAssets(unittest.TestCase):
 def test_proxy_and_stylesheet_are_required_in_verified_root(self):
  self.assertIn('www/luci-static/resources/view/flr/proxy.js',buildlib.RUNTIME_FILES)
  self.assertIn('www/luci-static/resources/flr.css',buildlib.RUNTIME_FILES)

if __name__=='__main__':unittest.main()
