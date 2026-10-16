"""Runtime-only version and protected production identity checks. No Docker calls."""
import re
import sys
from evidence_schema import field, strict_json
from security import require, valid_digest
from checks import load


def load_inputs(path):
    data = load(path)
    require(type(data) is dict and set(data) == {'version', 'production'},
            'RUNTIME_INPUTS', 'Missing or malformed runtime inputs.')
    version = field(data, 'version', str)
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is not None,
            'RUNTIME_VERSION', 'Expected runtime version is missing or invalid.')
    production = field(data, 'production', dict)
    keys = ('containerId', 'imageId', 'startedAt', 'name', 'project', 'service')
    require(set(production) == set(keys), 'PRODUCTION_SCHEMA', 'Incomplete approved production identity.')
    for key in keys:
        field(production, key, str)
    require(re.fullmatch(r'[0-9a-f]{64}', production['containerId']) is not None
            and valid_digest(production['imageId']) and production['name'] == '/passwordforge'
            and production['service'] == 'passwordforge'
            and re.fullmatch(r'[a-z0-9][a-z0-9_-]*', production['project']) is not None
            and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', production['startedAt']) is not None,
            'PRODUCTION_IDENTITY', 'Approved production identity is malformed.')
    return data


def prepare_inputs(ref, package, image, approved):
    version = field(approved, 'releaseVersion', str)
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is not None
            and ref == 'passwordforge:' + version and field(package, 'version', str) == version
            and field(field(field(image, 'Config', dict), 'Labels', dict),
                      'org.opencontainers.image.version', str) == version,
            'RUNTIME_VERSION', 'Approved, package, candidate tag and image versions must agree.')
    return {'version': version, 'production': {
        'containerId': field(approved, 'productionContainerId', str),
        'imageId': field(approved, 'productionImageId', str),
        'startedAt': field(approved, 'productionStartedAt', str),
        'name': '/' + field(approved, 'productionContainerName', str),
        'project': field(approved, 'composeProject', str),
        'service': field(approved, 'composeService', str)}}


def production_inspection(inputs, raw, target):
    require(valid_digest(target), 'RUNTIME_TARGET', 'Candidate image identity is malformed.')
    data = strict_json(raw)
    expected = dict(inputs['production'], status='running', health='healthy')
    require(type(data) is dict and set(data) == set(expected)
            and all(type(data[key]) is str for key in expected),
            'PRODUCTION_SCHEMA', 'Production inspection is incomplete or malformed.')
    require(data == expected and data['imageId'] != target,
            'PRODUCTION_IDENTITY', 'Production identity/state differs from the approved baseline.')


if __name__ == '__main__':
    try:
        operation, path, *args = sys.argv[1:]
        inputs = load_inputs(path)
        if operation == 'version' and not args:
            print(inputs['version'])
        elif operation == 'production' and len(args) == 1:
            raw = sys.stdin.read(16385)
            require(len(raw) <= 16384, 'PRODUCTION_SCHEMA', 'Production inspection exceeds the limit.')
            production_inspection(inputs, raw, args[0])
        else:
            raise ValueError('Invalid runtime input operation')
    except Exception:
        print('Runtime input validation failed; stop.', file=sys.stderr)
        sys.exit(2)
