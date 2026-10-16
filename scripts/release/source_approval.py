"""Checksummed approval and bounded, immutable Docker build-context bytes.

Only documented root development/evidence directories are outside source inventory.
They never enter the Docker context. The tar supplied on stdin contains approved
bytes, not paths that Docker can reopen after verification.
"""
import hashlib
import io
import os
from pathlib import Path
import stat
import tarfile
from types import MappingProxyType
from evidence_schema import strict_json
from private_metadata import read_metadata
from security import require

IGNORED_ROOTS = frozenset(('.git', 'node_modules', 'dist', 'artifacts', 'validation-results'))
MAX_BYTES = 128 * 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(name):
    return (type(name) is str and bool(name) and not name.startswith('/')
            and '\\' not in name and ':' not in name
            and all(p not in ('', '.', '..') for p in name.split('/')))


def permissions(path):
    # Host build/preflight separately require Linux. No mode fallback.
    return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)


class Approval:
    def __init__(self, archive, private, checksum):
        self.archive = Path(archive).absolute()
        self.private = Path(private).absolute()
        approved = read_metadata(self.private, checksum)
        require(not self.archive.is_symlink() and self.archive.is_file()
                and self.archive.stat().st_size <= MAX_BYTES,
                'APPROVAL_ARCHIVE', 'Approval requires a bounded regular source archive.')
        raw = self.archive.read_bytes()
        require(digest(raw) == approved['sourceArchiveSHA256'], 'APPROVAL_ARCHIVE', 'Approved archive checksum differs.')
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            require(len(names) == len(set(names)) and len(names) <= 4096
                    and sum(m.size for m in members) <= MAX_BYTES,
                    'SOURCE_INVENTORY', 'Ambiguous or excessive archive inventory.')
            require(all(safe_path(m.name) and m.isfile() and m.uid == m.gid == 0
                        and m.mode in (0o644, 0o755) for m in members),
                    'SOURCE_MEMBER', 'Unsafe source path/type/ownership/permissions.')
            manifest_raw = tar.extractfile('SOURCE-MANIFEST.json').read()
            require(digest(manifest_raw) == approved['sourceManifestSHA256'],
                    'APPROVAL_MANIFEST', 'Manifest differs from private approval.')
            manifest = strict_json(manifest_raw)
            require(type(manifest) is dict and set(manifest) == {'version', 'sourceCommit', 'fileCount', 'files'}
                    and manifest['version'] == approved['releaseVersion']
                    and manifest['sourceCommit'] == approved['sourceCommit']
                    and type(manifest['files']) is list and type(manifest['fileCount']) is int
                    and manifest['fileCount'] == len(manifest['files']),
                    'SOURCE_MANIFEST', 'Malformed or mismatched approved source manifest.')
            files = {}
            for entry in manifest['files']:
                require(type(entry) is dict and set(entry) == {'path', 'bytes', 'sha256', 'mode'},
                        'SOURCE_ENTRY', 'Invalid manifest entry.')
                name = entry['path']
                require(safe_path(name) and name.startswith('passwordforge/')
                        and type(entry['bytes']) is int and entry['bytes'] >= 0
                        and type(entry['sha256']) is str and len(entry['sha256']) == 64
                        and entry['mode'] in ('0644', '0755'), 'SOURCE_ENTRY', 'Invalid source identity.')
                relative = name[len('passwordforge/'):]
                require(relative.split('/')[0] not in IGNORED_ROOTS and relative not in files,
                        'SOURCE_ENTRY', 'Private/generated or duplicate source entry.')
                m = tar.getmember(name)
                data = tar.extractfile(m).read()
                require(len(data) == entry['bytes'] and digest(data) == entry['sha256']
                        and m.mode == int(entry['mode'], 8), 'SOURCE_CONTENT', 'Approved source bytes/mode differ.')
                files[relative] = (data, m.mode)
            require(set(names) == {'SOURCE-MANIFEST.json'} | {'passwordforge/' + p for p in files},
                    'SOURCE_INVENTORY', 'Archive inventory differs from approval.')
        for name in files:
            require(not any(name.startswith(other + '/') for other in files),
                    'SOURCE_PATH', 'Conflicting source paths.')
        require(strict_json(files['package.json'][0])['version'] == approved['releaseVersion'],
                'SOURCE_VERSION', 'Approved package version differs.')
        self.metadata = MappingProxyType(approved)
        self.identity = MappingProxyType({'metadataSHA256': checksum,
            'archiveSHA256': approved['sourceArchiveSHA256'], 'manifestSHA256': digest(manifest_raw),
            'sourceCommit': approved['sourceCommit'], 'version': approved['releaseVersion']})
        self.files = MappingProxyType(files)
        self.manifest = manifest_raw
        context = io.BytesIO()
        with tarfile.open(fileobj=context, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name, (data, mode) in sorted(files.items()):
                item = tarfile.TarInfo(name)
                item.mode, item.size = mode, len(data)
                tar.addfile(item, io.BytesIO(data))
        self.context = context.getvalue()
        self.fingerprint = digest(self.context)
        self.checksum = checksum

    def verify_tree(self, root):
        root = Path(root)
        require(not root.is_symlink() and root.is_dir(), 'SOURCE_ROOT', 'Unsafe staged source root.')
        found = set()
        def walk(directory):
            for p in directory.iterdir():
                require(not p.is_symlink(), 'SOURCE_LINK', 'Source links are forbidden.')
                relative = p.relative_to(root).as_posix()
                if directory == root and p.name in IGNORED_ROOTS:
                    require(p.is_dir(), 'SOURCE_ARTIFACT', 'Expected a development/evidence directory.')
                    continue
                # Python bytecode cache is never in context; no symlink shortcuts.
                if p.name == '__pycache__' and p.is_dir():
                    continue
                if p.is_dir():
                    require(any(n.startswith(relative + '/') for n in self.files),
                            'SOURCE_EXTRA', 'Unexpected source directory.')
                    walk(p)
                else:
                    require(p.is_file() and relative in self.files, 'SOURCE_EXTRA', 'Unexpected source file/type.')
                    data, mode = self.files[relative]
                    require(permissions(p) == mode and p.stat().st_size == len(data)
                            and p.read_bytes() == data, 'SOURCE_CHANGED', 'Staged source bytes/size/mode differ from approval.')
                    found.add(relative)
        walk(root)
        require(found == set(self.files), 'SOURCE_MISSING', 'Approved source files are missing.')

    def refresh(self, root):
        current = Approval(self.archive, self.private, self.checksum)
        require(dict(current.identity) == dict(self.identity) and current.context == self.context,
                'APPROVAL_CHANGED', 'Approval changed during the operation.')
        self.verify_tree(root)
