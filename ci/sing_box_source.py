"""Pinned minimal engine provenance. No download/build runs during imports."""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import tarfile

from engine_compat import require_ci
from buildlib import check_elf, check_sing_box_capabilities, check_sing_box_markers, check_sing_box_host_identity, go_build_info
import sing_box_patch

# The firmware engine is the audited FLR random-SNI build of upstream sing-box
# 1.14.4: pinned upstream source plus the verified patch in
# client/sing-box-random-sni. Never fall back to an unpatched engine: the router
# controller refuses flr_random_sni_suffix profiles without the capability.
UPSTREAM_VERSION='1.14.4'
VERSION='1.14.4-flr-random-sni.1'
# The binary version above is not a valid apk-tools v3 version, so the package
# carries this mapped one (see package_version()).
PACKAGE_VERSION='1.14.4.1'
CAPABILITIES=['hysteria2-random-sni-per-quic-dial-v1']
COMMIT='c005f35300ce76427dc285481ec5695f5b179cd2'
SOURCE_SHA='1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59'
PATCH={'directory':'client/sing-box-random-sni',
 'manifest_sha256':'68ae7da0794e996ca64b3a47ce6891b9aaf17c28620ac6762ceb2d07af7ca51d',
 'original_tree_sha256':'bdaaa342882ca29e027c2d9ecfd275c2043ecfd78a8ae877726ff27b60cf8ea7',
 'patched_tree_sha256':'5bb0db2aadeaedd7a6665f9914558ce6c6f418a633ff7527a6df104961a313b8'}
# go.mod / go.sum digests of this commit are not pinned here. The pinned archive
# SHA256 already fixes every file in it (including both), so the digests are
# DERIVED from the verified archive by manifest_digests() and recorded in the
# receipt; the build re-derives them after compiling to prove the toolchain did
# not rewrite either file. A lock may still carry go_mod_sha256/go_sum_sha256
# as optional extra pins: when present they are enforced everywhere.
REQUIRED={'with_quic','with_wireguard','with_utls'}
ALLOWED=REQUIRED|{'with_gvisor'}
TARGETS={'linux/amd64','linux/arm64'}
HEX64='[0-9a-f]{64}'

def digest(data):return hashlib.sha256(data).hexdigest()

def package_version(version):
 """Map a binary version to its apk-tools v3 package version (digits and dots)."""
 match=re.fullmatch(r'([0-9]+\.[0-9]+\.[0-9]+)-flr-random-sni\.([1-9][0-9]{0,2})',version) if isinstance(version,str) else None
 if not match:raise ValueError('sing-box version has no apk package version mapping')
 return match.group(1)+'.'+match.group(2)

def validate_pin(pin):
 if not isinstance(pin,dict):raise ValueError('source pin object required')
 if package_version(VERSION)!=PACKAGE_VERSION:raise ValueError('internal package version mapping inconsistent')
 expected={'version':VERSION,'package_version':PACKAGE_VERSION,'upstream_version':UPSTREAM_VERSION,'asset_kind':'source-build','packaging':'pinned-source-build','upstream_commit':COMMIT,'source_url':'https://codeload.github.com/SagerNet/sing-box/tar.gz/'+COMMIT,'source_sha256':SOURCE_SHA,'patch':PATCH,'capabilities':CAPABILITIES,'go_version':'1.26.8','cgo_enabled':False}
 if any(pin.get(key)!=value for key,value in expected.items()):raise ValueError('minimal sing-box source/build pin mismatch')
 for key in ('go_mod_sha256','go_sum_sha256'):
  if key in pin and (not isinstance(pin[key],str) or not re.fullmatch(HEX64,pin[key])):raise ValueError('optional dependency manifest pin malformed')
 tags=pin.get('tags')
 if not isinstance(tags,list) or any(not isinstance(t,str) for t in tags) or len(tags)!=len(set(tags)) or not REQUIRED.issubset(tags) or not set(tags).issubset(ALLOWED):raise ValueError('minimal sing-box capability tags rejected')
 if pin.get('cgo_enabled') is not False:raise ValueError('CGO must be disabled')
 return pin

def validate_receipt(pin,receipt,payloads=None):
 validate_pin(pin)
 if not isinstance(receipt,dict):raise ValueError('source receipt object required')
 expected={'version':1,'asset_kind':'source-build','upstream_version':pin['upstream_version'],'custom_version':pin['version'],'upstream_commit':pin['upstream_commit'],'source_url':pin['source_url'],'source_sha256':pin['source_sha256'],'go_version':pin['go_version'],'tags':pin['tags'],'capabilities':pin['capabilities'],'cgo_enabled':False,'hardware_tested':False,'end_to_end_tested':False}
 if any(receipt.get(k)!=v for k,v in expected.items()):raise ValueError('source build receipt pin mismatch')
 for key in ('go_mod_sha256','go_sum_sha256'):
  # Derived from the verified archive when the pin does not carry the digest.
  if not isinstance(receipt.get(key),str) or not re.fullmatch(HEX64,receipt[key]) or key in pin and receipt[key]!=pin[key]:raise ValueError('source build receipt dependency manifest digest rejected')
 patch=receipt.get('patch')
 if not isinstance(patch,dict) or any(patch.get(k)!=pin['patch'][k] for k in ('manifest_sha256','original_tree_sha256','patched_tree_sha256')) or patch.get('offline_tests_passed') is not True:raise ValueError('source build receipt patch evidence mismatch')
 if not isinstance(patch.get('payload_sha256'),dict) or not patch['payload_sha256'] or any(not re.fullmatch(HEX64,v) for v in patch['payload_sha256'].values()):raise ValueError('source build receipt patch payload digests rejected')
 if any(receipt.get(k) is not False for k in ['cgo_enabled','hardware_tested','end_to_end_tested']):raise ValueError('false qualification flags required')
 targets=receipt.get('targets',{})
 if not isinstance(targets,dict):raise ValueError('source receipt target map required')
 if set(targets)!=TARGETS or payloads is not None and set(payloads)!=TARGETS:raise ValueError('both source build targets required')
 union=set()
 for name,target in targets.items():
  if not isinstance(target,dict) or not re.fullmatch('[0-9a-f]{64}',target.get('sha256','')) or type(target.get('size')) is not int or not 64<=target['size']<=128*1024*1024:raise ValueError('source build target digest/size rejected')
  if target.get('go_version')!='go'+pin['go_version'] or target.get('tags')!=pin['tags'] or target.get('cgo_enabled') is not False:raise ValueError('target compiler/flags mismatch')
  modules=target.get('linked_modules')
  if not isinstance(modules,list) or not modules or len(modules)>1024 or any(not isinstance(m,str) or not m or len(m)>300 or 'cronet' in m.lower() for m in modules):raise ValueError('linked source build modules rejected')
  union.update(modules)
  if payloads is not None and (digest(payloads[name])!=target['sha256'] or len(payloads[name])!=target['size']):raise ValueError('source build payload mismatch')
 modules=receipt.get('linked_modules')
 if not isinstance(modules,list) or set(modules)!=union or len(modules)!=len(set(modules)):raise ValueError('source build linked module union mismatch')
 return receipt

def manifest_digests(root):
 """Derive go.mod/go.sum digests from the (archive-verified) source tree."""
 return {key:digest((Path(root)/file).read_bytes()) for file,key in [('go.mod','go_mod_sha256'),('go.sum','go_sum_sha256')]}

def unpack_source(pin,data,directory):
 if len(data)>32*1024*1024 or digest(data)!=pin['source_sha256']:raise ValueError('source archive SHA256 mismatch')
 root=sing_box_patch.extract_source(data,pin['upstream_commit'],directory)
 derived=manifest_digests(root)
 for key,value in derived.items():
  if key in pin and pin[key]!=value:raise ValueError('pinned '+key+' mismatch')
 return root

def patch_source(pin,root,project):
 """Apply the verified FLR patch; every digest in the pin must match."""
 patch=sing_box_patch.load_patch(Path(project)/pin['patch']['directory'],pin['upstream_commit'])
 if patch['manifest_sha256']!=pin['patch']['manifest_sha256']:raise ValueError('patch manifest SHA256 mismatch')
 # Refuse to edit anything but the exact pinned upstream tree.
 if sing_box_patch.tree_sha(root)!=pin['patch']['original_tree_sha256']:raise ValueError('original source tree SHA256 mismatch')
 evidence=sing_box_patch.apply_patch(root,patch)
 if evidence['original_tree_sha256']!=pin['patch']['original_tree_sha256']:raise ValueError('original source tree SHA256 mismatch')
 if evidence['patched_tree_sha256']!=pin['patch']['patched_tree_sha256']:raise ValueError('patched source tree SHA256 mismatch')
 return evidence

def archive_bytes(version,arch,binary,license_data):
 import gzip
 output=io.BytesIO()
 with gzip.GzipFile(fileobj=output,mode='wb',mtime=0) as compressed:
  with tarfile.open(fileobj=compressed,mode='w') as archive:
   for name,data,mode in [('sing-box',binary,0o755),('LICENSE',license_data,0o644)]:
    entry=tarfile.TarInfo('sing-box-'+version+'-linux-'+arch+'-static/'+name);entry.size=len(data);entry.mode=mode;entry.mtime=0;archive.addfile(entry,io.BytesIO(data))
 return output.getvalue()

def validate_binary(pin,arch,path):
 validate_pin(pin)
 if arch not in ('arm64','amd64'):raise ValueError('source build architecture rejected')
 check_elf(path,static=True,machine=183 if arch=='arm64' else 62)
 check_sing_box_capabilities(path)
 check_sing_box_markers(path,pin['version'],pin['capabilities'])
 info=go_build_info(path);settings=info['settings']
 if info['go_version']!='go'+pin['go_version'] or settings.get('GOOS')!='linux' or settings.get('GOARCH')!=arch or settings.get('-tags','').split(',')!=pin['tags']:raise ValueError('actual source build compiler/architecture/tags mismatch')
 if not info['linked_modules']:raise ValueError('source build dependency evidence missing')
 return info

def validate_host_binary(pin,path):
 """Execute the AMD64 CI binary: version and flr-capabilities must match the pin."""
 validate_pin(pin)
 return check_sing_box_host_identity(path,pin['version'],pin['capabilities'])

def validate_source_selection(item):
 pin=validate_pin(item.get('source_pin',{}))
 validate_receipt(pin,item.get('source_build',{}))
 if item.get('asset_kind')!='source-build' or item.get('version')!=pin['version'] or item.get('release_tag')!='v'+pin['version'] or 'url' in item:raise ValueError('source selection cannot claim official prebuilt provenance')
 for arch,target in [('arm64',item),('amd64',item.get('validation_asset',{}))]:
  expected='sing-box-'+pin['version']+'-linux-'+arch+'-static.tar.gz'
  key='archive' if arch=='arm64' else 'name'
  if target.get(key)!=expected or 'url' in target or not re.fullmatch('[0-9a-f]{64}',target.get('sha256','')):raise ValueError('source selection archive/digest rejected')
 return item

def load_local(pin,folder):
 """Recheck generated local artifacts; never fetch a replacement on failure."""
 import json
 validate_pin(pin);folder=Path(folder)
 def read(path,bound):
  if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=bound:raise ValueError('missing or unsafe source build artifact: '+path.name)
  return path.read_bytes()
 raw=read(folder/'receipt.json',1024*1024)
 try:receipt=json.loads(raw)
 except (ValueError,UnicodeError) as e:raise ValueError('invalid source build receipt') from e
 validate_receipt(pin,receipt)
 payloads={};archives={};license_data=None
 for arch in ['arm64','amd64']:
  binary=folder/('linux-'+arch)/'sing-box'
  payloads['linux/'+arch]=read(binary,128*1024*1024)
  info=validate_binary(pin,arch,binary)
  if receipt.get('targets',{}).get('linux/'+arch,{}).get('linked_modules')!=info['linked_modules']:raise ValueError('receipt does not match linked binary modules')
  current_license=read(folder/('linux-'+arch)/'LICENSE',1024*1024)
  if license_data is not None and current_license!=license_data:raise ValueError('source build licenses mismatch')
  license_data=current_license
  name='sing-box-'+pin['version']+'-linux-'+arch+'-static.tar.gz'
  data=read(folder/name,128*1024*1024)
  with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
   entries=archive.getmembers();prefix=name.removesuffix('.tar.gz')+'/'
   if len(entries)!=2 or {entry.name for entry in entries}!={prefix+'sing-box',prefix+'LICENSE'} or any(not e.isfile() or e.size>128*1024*1024 for e in entries):raise ValueError('source build archive layout rejected')
   if archive.extractfile(prefix+'sing-box').read()!=payloads['linux/'+arch] or archive.extractfile(prefix+'LICENSE').read()!=license_data:raise ValueError('source build archive payload differs from receipt binary')
  archives[arch]={'name':name,'sha256':digest(data),'data':data}
 validate_receipt(pin,receipt,payloads)
 return {'receipt':receipt,'receipt_sha256':digest(raw),'archives':archives,'license_sha256':digest(license_data)}
