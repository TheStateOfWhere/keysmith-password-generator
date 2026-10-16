"""Mandatory build proof; no legacy or partial-record success path."""
import hashlib
import re
from checks import load
from security import require, valid_digest

ARTIFACTS = ('approval.json', 'SOURCE-MANIFEST.json', 'build-context.tar',
    'example-compose.yaml', 'build-started.json', 'build.log', 'build.log.status.json', 'build.iid',
    'build-metadata.json', 'build-identity.tar')
FIELDS = frozenset(('schemaVersion', 'approval', 'image', 'imageId', 'sourceSHA256',
    'run', 'metadataSHA256', 'identityArchiveSHA256', 'configId', 'manifestId',
    'exportId', 'exportMediaType', 'imageIdKind', 'iidKind', 'artifacts'))


def hashes(out):
    result = {}
    for name in ARTIFACTS:
        p = out/name
        require(p.is_file() and not p.is_symlink(), 'BUILD_ARTIFACT', 'Required build artifact missing/unsafe: ' + name)
        result[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def validate(out, record, approved):
    require(type(record) is dict and set(record) == FIELDS and type(record['schemaVersion']) is int
            and record['schemaVersion'] == 1, 'BUILD_SCHEMA', 'Complete supported build-proof schema is mandatory.')
    require(record['approval'] == dict(approved.identity), 'APPROVAL_BINDING', 'Build belongs to another approval.')
    require(record['image'] == 'passwordforge:' + approved.identity['version']
            and record['sourceSHA256'] == approved.fingerprint,
            'SOURCE_BINDING', 'Build source/version differs from approval.')
    require(type(record['run']) is str and re.fullmatch(r'[0-9]{8}t[0-9]{6}z-[0-9a-f]{16}', record['run']),
            'RUN_NAME', 'Invalid build-attempt identity.')
    require(all(valid_digest(record[k]) for k in ('imageId', 'configId', 'manifestId', 'exportId')),
            'BUILD_DIGEST', 'Mandatory image/export identities are malformed.')
    roles = {'config': record['configId'], 'manifest': record['manifestId'], 'index': record['exportId']}
    require(record['imageIdKind'] in roles and record['iidKind'] in roles
            and record['imageId'] == roles[record['imageIdKind']], 'BUILD_ROLE', 'Image digest role differs.')
    require(record['exportMediaType'] in ('application/vnd.oci.image.index.v1+json',
            'application/vnd.oci.image.manifest.v1+json',
            'application/vnd.docker.distribution.manifest.v2+json',
            'application/vnd.docker.distribution.manifest.list.v2+json'), 'BUILD_MEDIA', 'Unsupported export media type.')
    require(type(record['artifacts']) is dict and record['artifacts'] == hashes(out),
            'BUILD_ARTIFACT_BINDING', 'Required build evidence changed or is incomplete.')
    require(record['metadataSHA256'] == record['artifacts']['build-metadata.json']
            and record['identityArchiveSHA256'] == record['artifacts']['build-identity.tar'],
            'BUILD_HASH', 'Original export/metadata hashes differ.')
    require((out/'build-context.tar').read_bytes() == approved.context
            and (out/'SOURCE-MANIFEST.json').read_bytes() == approved.manifest
            and (out/'example-compose.yaml').read_bytes() == approved.files['compose.yaml'][0]
            and load(out/'approval.json') == dict(approved.identity),
            'BUILD_SOURCE', 'Build snapshot/manifest/approval receipt differs.')
    require(load(out/'build-started.json') == {'schemaVersion': 1, 'image': record['image'],
            'run': record['run'], 'approval': record['approval'], 'sourceSHA256': record['sourceSHA256']},
            'BUILD_ATTEMPT', 'Mixed build-attempt evidence.')
    status = load(out/'build.log.status.json')
    require(type(status) is dict and set(status) == {'exitCode', 'timedOut'}
            and type(status['exitCode']) is int and status['exitCode'] == 0
            and type(status['timedOut']) is bool and not status['timedOut'],
            'BUILD_STATUS', 'Build did not complete successfully.')
    require((out/'build.iid').read_text().strip() == roles[record['iidKind']],
            'BUILD_IID', 'Builder IID belongs to another build.')
    p = out/'image.id'
    require(p.is_file() and not p.is_symlink() and p.read_text().strip() == record['imageId'],
            'IMAGE_ID_FILE', 'image.id differs from the authoritative build identity.')
    require(load(out/'build-identity.json') == record, 'BUILD_EVIDENCE_BINDING', 'Identity proof differs from build record.')


def continuity(record):
    # Each downstream receipt is bound to this exact approval AND build proof.
    return {'schemaVersion': 1, 'approval': record['approval'], 'run': record['run'],
            'buildSHA256': hashlib.sha256(__import__('json').dumps(record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def same_attempt(receipt, record):
    for k, v in continuity(record).items():
        require(type(receipt) is dict and type(receipt.get(k)) is type(v) and receipt[k] == v,
                'ATTEMPT_BINDING', 'Evidence belongs to another approval/build attempt.')
