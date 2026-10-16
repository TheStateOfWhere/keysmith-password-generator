"""Explicit operator-approved deployment baseline. Never discovers defaults."""
import hashlib
import json
import re
import sys
from pathlib import Path

FIELDS = frozenset(('releaseVersion', 'sourceCommit', 'sourceArchiveSHA256', 'sourceManifestSHA256', 'productionContainerId',
    'productionImageId', 'productionImageTag', 'productionStartedAt',
    'productionComposePath', 'productionComposeSHA256', 'composeProject',
    'composeService', 'productionContainerName', 'proxyNetwork', 'proxyNetworkId',
    'routerHost', 'httpsEntryPoint'))


def validate_metadata(data):
    if type(data) is not dict or set(data) != FIELDS:
        raise ValueError('Private metadata must contain exactly the documented fields')
    if any(type(v) is not str or not v or len(v) > 1024
           or any(ord(c) < 32 or ord(c) > 126 for c in v) for v in data.values()):
        raise ValueError('Private metadata fields must be bounded ASCII strings')
    patterns = {
        'releaseVersion': r'[0-9]+\.[0-9]+\.[0-9]+',
        'sourceCommit': r'[0-9a-f]{40}',
        'sourceArchiveSHA256': r'[0-9a-f]{64}',
        'sourceManifestSHA256': r'[0-9a-f]{64}',
        'productionContainerId': r'[0-9a-f]{64}',
        'productionImageId': r'sha256:[0-9a-f]{64}',
        'productionImageTag': r'passwordforge:[0-9]+\.[0-9]+\.[0-9]+',
        'productionStartedAt': r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',
        'productionComposeSHA256': r'[0-9a-f]{64}',
        'composeProject': r'[a-z0-9][a-z0-9_-]*',
        'composeService': r'passwordforge',
        'productionContainerName': r'passwordforge',
        'proxyNetwork': r'[a-zA-Z0-9][a-zA-Z0-9_.-]*',
        'proxyNetworkId': r'[0-9a-f]{64}',
        'routerHost': r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}',
        'httpsEntryPoint': r'[a-zA-Z0-9][a-zA-Z0-9_-]*',
    }
    for key, pattern in patterns.items():
        if re.fullmatch(pattern, data[key]) is None:
            raise ValueError('Invalid private metadata field: ' + key)
    compose = data['productionComposePath']
    if not compose.startswith('/') or '\\' in compose or any(x in ('', '.', '..') for x in compose.split('/')[1:]):
        raise ValueError('Use an absolute nontraversing private Compose path')
    if data['productionImageTag'] == 'passwordforge:' + data['releaseVersion']:
        raise ValueError('Candidate tag must differ from protected production tag')
    return dict(data)


def read_metadata(path, expected_sha256):
    if type(expected_sha256) is not str or re.fullmatch(r'[0-9a-f]{64}', expected_sha256) is None:
        raise ValueError('Missing valid trusted private-metadata checksum')
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError('Private metadata must be a bounded regular file')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('Private metadata checksum mismatch')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate private metadata field')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('Nonstandard private metadata JSON constant')
    return validate_metadata(json.loads(raw, object_pairs_hook=pairs, parse_constant=constant))


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4 or sys.argv[3] not in FIELDS:
            raise ValueError('Usage: private_metadata.py PRIVATE_JSON TRUSTED_SHA256 FIELD')
        print(read_metadata(sys.argv[1], sys.argv[2])[sys.argv[3]])
    except (ValueError, OSError, TypeError):
        print('STOP: invalid or missing approved private metadata', file=sys.stderr)
        sys.exit(2)
