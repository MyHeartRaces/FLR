"""Verify official AWG tag/commit/blob identities and the shared 3.1 UAPI contract."""
import base64
import hashlib
import re

from engine_releases import Incompatible, IntegrityError, stable, version

MODULE_REPO = 'amnezia-vpn/amneziawg-linux-kernel-module'
TOOLS_REPO = 'amnezia-vpn/amneziawg-tools'
REQUIRED = ['WGDEVICE_A_'+x for x in ('PRIVATE_KEY','LISTEN_PORT','FWMARK','PEERS','JC','JMIN','JMAX','S1','S2','S3','S4','H1','H2','H3','H4','I1','I2','I3','I4','I5','HEADER_PROTECTION_KEY','CONTENT_PADDING_ADDITION','RANDOM_TRAILERS','DISABLE_COOKIES')]
FIELDS = ['HeaderProtectionKey','ContentPaddingAddition','RandomTrailers','DisableCookies']


def enum_values(header):
    for block in re.findall(r'enum[^{}]*\{([^{}]+)\}', header, re.S):
        if 'WGDEVICE_A_HEADER_PROTECTION_KEY' not in block:
            continue
        block = re.sub(r'/\*.*?\*/', '', block, flags=re.S)
        values = {}
        index = -1
        for item in block.split(','):
            match = re.fullmatch(r'\s*([A-Z_][A-Z0-9_]*)(?:\s*=\s*(\d+))?\s*', item)
            if not match:
                if item.strip():
                    raise Incompatible('AWG UAPI enum cannot be conservatively evaluated')
                continue
            index = int(match[2]) if match[2] else index + 1
            values[match[1]] = index
        if not all(name in values for name in REQUIRED):
            raise Incompatible('AWG 3.1 required netlink fields missing')
        return {name: values[name] for name in REQUIRED}
    raise Incompatible('AWG 3.1 device UAPI unavailable')


def source(api, repository, tag, cache):
    try:
        version(tag)
    except Incompatible as error:
        raise IntegrityError('unsafe AWG source tag') from error
    if repository not in (MODULE_REPO, TOOLS_REPO):
        raise IntegrityError('unapproved AWG repository')
    key = (repository, tag)
    if key in cache:
        return cache[key]
    commit = api.json(repository+'/commits/'+tag)
    sha = commit.get('sha','')
    if not re.fullmatch('[0-9a-f]{40}',sha):
        raise IntegrityError('official AWG tag commit unavailable')
    tree_sha = commit.get('commit', {}).get('tree', {}).get('sha', '')
    if not re.fullmatch('[0-9a-f]{40}', tree_sha):
        raise IntegrityError('official AWG tree identity unavailable')
    tree = api.json(repository+'/git/trees/'+tree_sha+'?recursive=1')
    if tree.get('truncated'):
        raise IntegrityError('official AWG source tree truncated')
    paths = ['src/uapi/wireguard.h','src/netlink.c'] if repository == MODULE_REPO else ['src/uapi/linux/linux/wireguard.h','src/config.c']
    contents = {}
    blobs = {}
    for path in paths:
        matches = [x for x in tree.get('tree',[]) if x.get('path')==path and x.get('type')=='blob']
        if len(matches)!=1:
            raise Incompatible('AWG source contract path unavailable: '+path)
        blob = api.json(repository+'/git/blobs/'+matches[0]['sha'])
        data = decode_blob(blob, matches[0]['sha'])
        digest = blob['sha']
        try:
            contents[path]=data.decode()
        except UnicodeDecodeError as error:
            raise IntegrityError('AWG source blob is not text') from error
        blobs[path]={'git_blob':digest,'sha256':hashlib.sha256(data).hexdigest()}
    header=contents[paths[0]]
    result={'tag_name':tag,'version':tag.removeprefix('v'),'commit':sha,'uapi':enum_values(header),'source_blobs':blobs}
    if repository==TOOLS_REPO and not all('"'+field+'"' in contents['src/config.c'] for field in FIELDS):
        raise Incompatible('AWG tools parser lacks complete 3.1 settings fields')
    if repository==MODULE_REPO and not all(field in contents['src/netlink.c'] for field in REQUIRED):
        raise Incompatible('AWG kernel implementation lacks required 3.1 fields')
    cache[key]=result
    return result


def resolve_pair(api, module_reference, tools_releases):
    # This repository has no GitHub Releases; numeric official tags are its
    # published stable source boundary. API failures never switch policy.
    tags=api.json(MODULE_REPO+'/tags?per_page=30')
    if not isinstance(tags,list):
        raise IntegrityError('official AWG module stable tags unavailable')
    releases=stable([{'tag_name':x.get('name'),'draft':False,'prerelease':False} for x in tags])
    if not releases:
        raise IntegrityError('official AWG module stable tags missing')
    if module_reference not in [x['tag_name'] for x in releases]:
        releases.append({'tag_name':module_reference,'draft':False,'prerelease':False})
    cache={}
    rejected=[]
    for module in releases:
        try:
            selected_module=source(api,MODULE_REPO,module['tag_name'],cache)
        except Incompatible as error:
            rejected.append({'module':module['tag_name'],'reason':str(error)})
            continue
        for tools in tools_releases:
            try:
                selected_tools=source(api,TOOLS_REPO,tools['tag_name'],cache)
                if selected_module['uapi']!=selected_tools['uapi']:
                    raise Incompatible('selected AWG module/tools required UAPI indices disagree')
            except Incompatible as error:
                rejected.append({'module':module['tag_name'],'tools':tools['tag_name'],'reason':str(error)})
                continue
            return selected_module,selected_tools,rejected
    raise Incompatible('no verified AWG 3.1 source/UAPI pair: '+str(rejected))


def decode_blob(blob, expected):
    if not re.fullmatch('[0-9a-f]{40}', expected or '') or blob.get('encoding') != 'base64':
        raise IntegrityError('official Git blob encoding or identity invalid')
    size = blob.get('size')
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= 1024 * 1024:
        raise IntegrityError('official Git blob bound invalid')
    try:
        data = base64.b64decode(''.join(blob['content'].split()), validate=True)
    except (ValueError, KeyError, AttributeError) as error:
        raise IntegrityError('official Git blob malformed') from error
    digest = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if len(data) != size or digest != expected or blob.get('sha') != digest:
        raise IntegrityError('official Git blob identity mismatch')
    return data
