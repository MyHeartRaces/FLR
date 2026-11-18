"""Shared, stdlib-only logic for applying the audited FLR sing-box patch.

Used by ci/sing_box_source.py (CI firmware/engine build) and by
client/sing-box-random-sni/build.py (offline local build) so both apply exactly
the same verified edits. Nothing here downloads, compiles or executes anything.
"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_MEMBER = 8 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_MEMBERS = 10000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tree_sha(root):
    """Digest of every regular file path+content under root; symlinks rejected."""
    root = Path(root)
    lines = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('source symlink rejected')
        if path.is_file():
            lines.append(sha(path.read_bytes()) + '  ' + path.relative_to(root).as_posix() + '\n')
    return sha(''.join(lines).encode())


def load_patch(patch_dir, source_commit):
    """Read patch.json and every payload; verify payload digests. No mutation."""
    patch_dir = Path(patch_dir)
    manifest_data = (patch_dir / 'patch.json').read_bytes()
    manifest = json.loads(manifest_data)
    if manifest['source_commit'] != source_commit:
        raise ValueError('patch source revision mismatch')
    payloads = {}
    for item in manifest['payloads']:
        content = (patch_dir / item['file']).read_bytes()
        if sha(content) != item['sha256']:
            raise ValueError('patch payload SHA256 mismatch')
        payloads[item['target']] = content
    return {'manifest': manifest, 'manifest_sha256': sha(manifest_data), 'payloads': payloads,
            'payload_sha256': {p['file']: p['sha256'] for p in manifest['payloads']}}


def extract_source(data, source_commit, workspace):
    """Validate the whole archive first, then extract it under workspace.

    Returns the source root (workspace/sing-box-<commit>). Callers verify the
    archive digest before calling this.
    """
    if len(data) > MAX_ARCHIVE:
        raise ValueError('source archive size bound')
    prefix = 'sing-box-' + source_commit
    workspace = Path(workspace)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as source:
        entries = source.getmembers()
        if len(entries) > MAX_MEMBERS:
            raise ValueError('source archive member bound')
        names = set()
        total = 0
        for entry in entries:
            path = PurePosixPath(entry.name)
            total += entry.size
            if (not path.parts or path.parts[0] != prefix or path.is_absolute()
                    or '..' in path.parts or '\\' in entry.name or entry.name in names
                    or not (entry.isdir() or entry.isfile()) or entry.size > MAX_MEMBER
                    or total > MAX_EXPANDED):
                raise ValueError('unsafe source archive')
            names.add(entry.name)
        workspace.mkdir(parents=True, exist_ok=True)
        for entry in entries:
            path = workspace / entry.name
            if entry.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as out:
                    out.write(source.extractfile(entry).read())
                path.chmod(0o600)
    return workspace / prefix


def apply_patch(root, patch):
    """Apply edits and payloads to an extracted tree; return the evidence chain."""
    root = Path(root)
    original_tree_sha = tree_sha(root)
    for edit in patch['manifest']['edits']:
        path = root / edit['file']
        if not path.is_file() or path.is_symlink():
            raise ValueError('patch target missing: ' + edit['file'])
        original = path.read_bytes()
        if sha(original) != edit['before_sha256']:
            raise ValueError('patch input digest mismatch: ' + edit['file'])
        text = original.decode()
        for replacement in edit['replacements']:
            if text.count(replacement['before']) != 1:
                raise ValueError('patch anchor is not unique')
            text = text.replace(replacement['before'], replacement['after'], 1)
        path.write_text(text)
    for target, content in patch['payloads'].items():
        path = root / target
        if path.exists():
            raise ValueError('patch payload collision')
        path.write_bytes(content)
    return {'manifest_sha256': patch['manifest_sha256'], 'payload_sha256': dict(patch['payload_sha256']),
            'original_tree_sha256': original_tree_sha, 'patched_tree_sha256': tree_sha(root)}
