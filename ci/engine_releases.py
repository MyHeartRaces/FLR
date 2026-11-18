"""Bounded official stable release selection; integrity errors never become fallback."""
import hashlib
import json
import re
import urllib.error
import urllib.request

MAX_CANDIDATES = 8
HISTORY_PAGE_SIZE = 2
MAX_HISTORY_PAGES = 16
MAX_DOWNLOAD = 128 * 1024 * 1024

class IntegrityError(RuntimeError):
    pass

class Incompatible(RuntimeError):
    pass


def version(tag):
    if not isinstance(tag, str) or len(tag) > 64 or not re.fullmatch(r'v?[0-9]+(?:\.[0-9]+){1,3}', tag):
        raise Incompatible('stable numeric release tag required')
    return tuple(int(x) for x in tag.lstrip('v').split('.'))


def stable(releases, limit=MAX_CANDIDATES):
    candidates = []
    for release in releases:
        if release.get('draft') or release.get('prerelease'):
            continue
        try:
            version(release.get('tag_name'))
        except Incompatible:
            continue
        candidates.append(release)
    return sorted(candidates, key=lambda r: version(r['tag_name']), reverse=True)[:limit] if limit is not None else sorted(candidates, key=lambda r: version(r['tag_name']), reverse=True)


def select_compatible(releases, check):
    rejected = []
    if len(releases) > MAX_CANDIDATES + 1:
        raise IntegrityError("candidate set exceeds bounded history plus reference build")
    for release in stable(releases, limit=None):
        try:
            check(release)
        except Incompatible as error:
            rejected.append({'tag': release['tag_name'], 'reason': str(error)})
            continue
        return release, rejected
    raise Incompatible('no verified compatible stable candidate: ' + json.dumps(rejected))


def validate_asset(asset, repository, tag):
    try:
        version(tag)
    except Incompatible as error:
        raise IntegrityError('unsafe official release tag') from error
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise IntegrityError('unsafe official repository')
    name = asset.get('name', '')
    if not isinstance(name, str) or name in ('.', '..') or len(name) > 200 or '/' in name or '\\' in name or not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
        raise IntegrityError('unsafe official asset name')
    expected = f'https://github.com/{repository}/releases/download/{tag}/{name}'
    if asset.get('browser_download_url') != expected:
        raise IntegrityError('asset does not belong to matching official release')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest') or ''):
        raise IntegrityError('official matching-release SHA256 digest missing')
    return asset['digest'].split(':', 1)[1]


def verify_bytes(data, asset):
    if hashlib.sha256(data).hexdigest() != (asset.get('digest') or '').removeprefix('sha256:'):
        raise IntegrityError('official asset SHA256 mismatch')


class OfficialAPI:
    def __init__(self, token=None):
        self.token = token

    def read(self, url, limit=MAX_DOWNLOAD):
        headers = {'User-Agent': 'tracegate-flr-compatible-build', 'Accept': 'application/vnd.github+json'}
        if self.token and url.startswith('https://api.github.com/'):
            headers['Authorization'] = 'Bearer ' + self.token
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
                data = response.read(limit + 1)
        except (urllib.error.URLError, TimeoutError) as error:
            raise IntegrityError('official fetch failed: ' + url) from error
        if len(data) > limit:
            raise IntegrityError('official response exceeds bounded size')
        return data

    def json(self, path):
        try:
            return json.loads(self.read('https://api.github.com/repos/' + path, 8 * 1024 * 1024))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise IntegrityError('invalid official API response') from error

    def releases(self, repository):
        latest = self.json(repository + '/releases/latest')
        if not isinstance(latest, dict) or not stable([latest]):
            raise IntegrityError('official latest stable metadata unavailable')
        releases = {latest['tag_name']: latest}
        # Full release objects include every architecture asset; thirty objects
        # exceeded the fixed JSON bound in CI. Keep small bounded pages instead.
        for page in range(1, MAX_HISTORY_PAGES + 1):
            history = self.json(repository + '/releases?per_page=' + str(HISTORY_PAGE_SIZE) + '&page=' + str(page))
            if not isinstance(history, list) or len(history) > HISTORY_PAGE_SIZE or any(not isinstance(item, dict) for item in history):
                raise IntegrityError('official release history page malformed or unbounded')
            for item in stable(history):
                releases[item['tag_name']] = item
            if len(releases) >= MAX_CANDIDATES or len(history) < HISTORY_PAGE_SIZE:
                break
        return stable(releases.values())

    def asset(self, release, repository, name):
        matches = [a for a in release.get('assets', []) if a.get('name') == name]
        if len(matches) != 1:
            raise Incompatible('matching architecture asset unavailable: ' + name)
        asset = matches[0]
        validate_asset(asset, repository, release['tag_name'])
        data = self.read(asset['browser_download_url'])
        verify_bytes(data, asset)
        return asset, data

REPOSITORIES = {'sing_box':'SagerNet/sing-box', 'xray':'XTLS/Xray-core', 'wstunnel':'erebe/wstunnel', 'zapret2':'bol-van/zapret2'}


def asset_names(component, number):
    version(number)
    if component == 'sing_box':
        return f'sing-box-{number}-linux-arm64-musl.tar.gz', f'sing-box-{number}-linux-amd64-musl.tar.gz'
    if component == 'xray':
        return 'Xray-linux-arm64-v8a.zip', 'Xray-linux-64.zip'
    if component == 'wstunnel':
        return f'wstunnel_{number}_linux_arm64.tar.gz', f'wstunnel_{number}_linux_amd64.tar.gz'
    if component == 'zapret2':
        name = f'zapret2-v{number}-openwrt-embedded.tar.gz'
        return name, name
    raise IntegrityError('unapproved engine component')


def validate_selection(component, item):
    if component == 'sing_box' and item.get('asset_kind') == 'source-build':
        from sing_box_source import validate_source_selection
        try:
            return validate_source_selection(item)
        except (ValueError, TypeError, KeyError) as error:
            raise IntegrityError('malformed pinned source build selection') from error
    try:
        number = item['version']
        tag = item['release_tag']
        version(number)
        version(tag)
        if number.startswith('v') or tag.removeprefix('v') != number:
            raise IntegrityError('selected version/tag mismatch')
        arm, host = asset_names(component, number)
        repo = REPOSITORIES[component]
        for name, record in [(arm, {'name':item['archive'], 'browser_download_url':item['url'], 'digest':'sha256:'+item['sha256']}),
                             (host, {'name':item['validation_asset']['name'], 'browser_download_url':item['validation_asset']['url'], 'digest':'sha256:'+item['validation_asset']['sha256']})]:
            if record['name'] != name:
                raise IntegrityError('selected architecture archive mismatch')
            validate_asset(record, repo, tag)
    except (KeyError, TypeError, Incompatible) as error:
        raise IntegrityError('malformed selected official asset record') from error
