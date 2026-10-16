"""Packaging regression fixtures use temporary local Git only; no Docker/network."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('package_source', Path(__file__).parents[1] / 'package-source.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackageTests(unittest.TestCase):
    def fixture(self, root, forbidden=False):
        root.mkdir()
        def git(*args):
            return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
        git('init');git('config', 'core.autocrlf', 'false')
        git('config', 'user.name', 'Packaging fixture');git('config', 'user.email', 'fixture@example.invalid')
        names = ['package.json', 'RELEASE-INVENTORY.json', '.env' if forbidden else 'script.sh']
        (root/'package.json').write_text('{"version":"0.6.0"}\n', encoding='utf-8')
        (root/names[2]).write_text('public fixture\n', encoding='utf-8')
        inventory = {'version':'0.6.0', 'fileCount':3, 'files':[{'path':n,'mode':'0644'} for n in names]}
        (root/'RELEASE-INVENTORY.json').write_text(json.dumps(inventory), encoding='utf-8')
        git('add', '.');git('commit', '-m', 'Public fixture')
        return root

    def test_two_archives_and_manifests_are_identical_and_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);root=self.fixture(base/'source')
            with patch.object(module, 'ROOT', root):
                module.package(base/'a');module.package(base/'b')
            archive='PasswordForge-v0.6.0-source.tar.gz'
            self.assertEqual((base/'a'/archive).read_bytes(),(base/'b'/archive).read_bytes())
            self.assertEqual((base/'a'/'SOURCE-MANIFEST.json').read_bytes(),(base/'b'/'SOURCE-MANIFEST.json').read_bytes())
            with tarfile.open(base/'a'/archive) as tar:
                for member in tar.getmembers():
                    self.assertTrue(member.isfile());self.assertEqual(member.uid,0);self.assertEqual(member.mtime,0)
                self.assertEqual(tar.extractfile('SOURCE-MANIFEST.json').read(),(base/'a'/'SOURCE-MANIFEST.json').read_bytes())

    def test_dirty_or_untracked_source_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);root=self.fixture(base/'source');(root/'unknown.txt').write_text('public fixture')
            with patch.object(module,'ROOT',root),self.assertRaisesRegex(ValueError,'commit reviewed'):
                module.package(base/'out')

    def test_private_configuration_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);root=self.fixture(base/'source',True)
            with patch.object(module,'ROOT',root),self.assertRaisesRegex(ValueError,'Private configuration'):
                module.package(base/'out')

    def test_existing_output_and_source_directory_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);root=self.fixture(base/'source')
            with patch.object(module,'ROOT',root):
                with self.assertRaisesRegex(ValueError,'outside'):module.package(root/'out')
                module.package(base/'out')
                with self.assertRaisesRegex(ValueError,'overwrite'):module.package(base/'out')
