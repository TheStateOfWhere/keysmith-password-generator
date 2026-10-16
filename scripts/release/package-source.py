"""Deterministic committed-source package; stdlib only, no host/Docker operations."""
import gzip
import hashlib
import io
import json
import re
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[2]


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def package(output):
    if git('status', '--porcelain').strip():
        raise ValueError('STOP: commit reviewed source before packaging')
    commit = git('rev-parse', 'HEAD').decode().strip()
    inventory = json.loads(git('show', 'HEAD:RELEASE-INVENTORY.json'))
    version = json.loads(git('show', 'HEAD:package.json'))['version']
    if type(version) is not str or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is None:
        raise ValueError('Invalid release version')
    if inventory['version'] != version:
        raise ValueError('Inventory/package version mismatch')
    tracked = set(git('ls-files').decode().splitlines())
    entries = inventory['files']
    names = [e['path'] for e in entries]
    if len(names) != len(set(names)) or set(names) != tracked or inventory['fileCount'] != len(names):
        raise ValueError('Inventory must exactly cover committed source')
    blobs = {}
    manifest_files = []
    for entry in sorted(entries, key=lambda e: e['path']):
        name, mode = entry['path'], entry['mode']
        if not isinstance(name, str) or name.startswith('/') or '\\' in name or ':' in name or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('Unsafe source path')
        if any(p in ('node_modules', '.git', 'artifacts', 'validation-results', 'dist', '.ssh', 'private', 'private-evidence', 'handoffs', 'coverage') for p in PurePosixPath(name).parts):
            raise ValueError('Development/private path in inventory')
        if Path(name).name.startswith('.env') or Path(name).suffix in ('.pem', '.key', '.p12', '.zip', '.gz'):
            raise ValueError('Private configuration or previous archive in inventory')
        if mode not in ('0644', '0755'):
            raise ValueError('Unsupported source permissions')
        tree = git('ls-tree', 'HEAD', '--', name).decode().split()
        if len(tree) < 4 or tree[1] != 'blob' or tree[0] not in ('100644', '100755'):
            raise ValueError('Only regular committed source files are supported')
        if mode != ('0755' if tree[0] == '100755' else '0644'):
            raise ValueError('Inventory/Git permission mismatch')
        raw = git('show', 'HEAD:' + name)
        if (ROOT / name).is_symlink() or (ROOT / name).read_bytes() != raw:
            raise ValueError('Working source differs from committed bytes')
        archive_name = 'passwordforge/' + name
        blobs[archive_name] = (raw, int(mode, 8))
        manifest_files.append({'path': archive_name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode})
    manifest = json.dumps({'version': version, 'sourceCommit': commit, 'fileCount': len(names), 'files': manifest_files}, indent=2).encode() + b'\n'
    blobs['SOURCE-MANIFEST.json'] = (manifest, 0o644)
    output = Path(output).resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError('Release artifacts must be outside source workspace')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / ('PasswordForge-v' + version + '-source.tar.gz')
    if archive.exists() or (output / 'SOURCE-MANIFEST.json').exists():
        raise ValueError('Never overwrite existing release artifacts')
    with archive.open('xb') as target:
        with gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for name, (raw, mode) in sorted(blobs.items()):
                    item = tarfile.TarInfo(name)
                    item.size, item.mode, item.mtime = len(raw), mode, 0
                    item.uid = item.gid = 0
                    item.uname = item.gname = ''
                    tar.addfile(item, io.BytesIO(raw))
    (output / 'SOURCE-MANIFEST.json').write_bytes(manifest)
    print(str(archive))
    print(hashlib.sha256(archive.read_bytes()).hexdigest())


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('Usage: python3 -B scripts/release/package-source.py OUTPUT_DIRECTORY')
        package(sys.argv[1])
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
