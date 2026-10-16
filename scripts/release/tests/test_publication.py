"""Publication sanitization boundaries; no Docker/network or real private values."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_docker_release import ROOT, release
from private_metadata import read_metadata, validate_metadata


def approved():
    return {'releaseVersion':'0.6.0', 'sourceCommit':'c'*40, 'sourceArchiveSHA256':'e'*64, 'sourceManifestSHA256':'f'*64,
        'productionContainerId':'a'*64, 'productionImageId':'sha256:'+'b'*64,
        'productionImageTag':'passwordforge:0.5.0', 'productionStartedAt':'2026-01-01T00:00:00Z',
        'productionComposePath':'/private/compose.yaml', 'productionComposeSHA256':'c'*64,
        'composeProject':'passwordforge', 'composeService':'passwordforge',
        'productionContainerName':'passwordforge', 'proxyNetwork':'example-proxy',
        'proxyNetworkId':'d'*64, 'routerHost':'password.example.invalid', 'httpsEntryPoint':'websecure'}


class PublicationTests(unittest.TestCase):
    def test_explicit_complete_approval_and_detached_snapshot(self):
        data=approved(); result=validate_metadata(data); data['productionImageId']='changed'
        self.assertEqual(result['productionImageId'],'sha256:'+'b'*64)

    def test_every_required_field_is_mandatory(self):
        for key in approved():
            data=approved(); del data[key]
            with self.subTest(field=key),self.assertRaises(ValueError):validate_metadata(data)

    def test_exact_types_unknown_fields_and_malformed_identities_fail(self):
        for key,value in [('productionImageId','sha256'),('productionContainerId','short'),
                          ('productionComposeSHA256',False),('sourceCommit','x'*40),
                          ('proxyNetworkId',''),('routerHost','host`bad'),
                          ('productionComposePath','/private/../compose.yaml'),
                          ('releaseVersion',0.6),('unknown','value')]:
            data=approved();data[key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):validate_metadata(data)

    def test_candidate_and_production_tag_cannot_collide(self):
        data=approved();data['productionImageTag']='passwordforge:0.6.0'
        with self.assertRaises(ValueError):validate_metadata(data)

    def test_trusted_checksum_duplicate_json_and_missing_file_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'approval.json';p.write_text(json.dumps(approved()))
            digest=hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(read_metadata(p,digest),approved())
            with self.assertRaises(ValueError):read_metadata(p,'0'*64)
            p.write_text('{"releaseVersion":"0.6.0","releaseVersion":"0.6.0"}')
            with self.assertRaises(ValueError):read_metadata(p,hashlib.sha256(p.read_bytes()).hexdigest())
            p.write_text('false')
            with self.assertRaises(ValueError):read_metadata(p,hashlib.sha256(p.read_bytes()).hexdigest())
            p.write_bytes(b'A'*16385)
            with self.assertRaises(ValueError):read_metadata(p,hashlib.sha256(p.read_bytes()).hexdigest())
            with self.assertRaises(ValueError):read_metadata(Path(temp)/'missing','a'*64)

    def test_missing_cached_image_does_not_acquire(self):
        calls=[]
        def missing(args):
            calls.append(args);raise release.SecurityError('COMMAND_FAILED','Fixture cache miss')
        with patch.object(release,'command',side_effect=missing),self.assertRaises(release.SecurityError):
            release.cached_image(release.SCANNER)
        self.assertEqual(calls[0][3:6],['image','inspect','--platform'])
        self.assertFalse(any(x in ('pull','create','build') for c in calls for x in c))

    def test_no_automatic_pull_publish_prune_or_security_asserts(self):
        for name in ('docker-release.py','private_metadata.py'):
            tree=ast.parse((ROOT/name).read_text())
            self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(tree)))
        source=(ROOT/'docker-release.py').read_text()
        self.assertNotIn("DOCKER+['pull'",source)
        self.assertIn("'--pull=false'",source)
        self.assertIn("['create','--pull','never'",source)
        self.assertIn('run --pull never -d',(ROOT/'runtime-check.sh').read_text())
