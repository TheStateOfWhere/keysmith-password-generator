"""Observed Buildx compatibility and fail-closed plain inspection regressions."""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from test_docker_release import release, ROOT
from builder_contract import inspect_builder

GOOD="""Name:          default
Driver:        docker
Last Activity: 2026-10-11 00:00:00 +0000 UTC

Nodes:
Name:          default
Endpoint:      default
Status:        running
BuildKit version: v0.25.0
Platforms:     linux/amd64, linux/amd64/v2, linux/amd64/v3, linux/arm64
Labels:
 org.mobyproject.buildkit.worker.executor: oci
GC Policy rule#0:
 All: false
 Keep Bytes: 1GiB
"""

class BuilderCompatibilityTests(unittest.TestCase):
    def test_plain_inspect_default_context_resolves_local_socket(self):
        calls=[]
        def command(args):
            calls.append(args)
            if '--format' in args and 'buildx' in args:raise RuntimeError('unknown flag: --format')
            if 'version' in args:return 'linux/amd64'
            if 'buildx' in args:return GOOD
            return json.dumps([{'Endpoints':{'docker':{'Host':'unix:///var/run/docker.sock'}}}])
        with patch.object(release.os,'name','posix'),patch.object(release.os,'getuid',return_value=1000,create=True),patch.object(release,'command',side_effect=command):release.builder()
        self.assertIn(release.DOCKER+['buildx','inspect','default'],calls)
        self.assertFalse(any('--bootstrap' in c for c in calls))
    def test_direct_socket_and_forced_amd64_platform(self):
        self.assertEqual(inspect_builder(GOOD.replace('Endpoint:      default','Endpoint: unix:///var/run/docker.sock').replace('linux/amd64,','linux/amd64*,')),'unix:///var/run/docker.sock')
    def test_required_fields_and_exact_builder_identity(self):
        for old in ('Name:          default','Driver:        docker','Nodes:','Endpoint:      default','Status:        running','Platforms:     linux/amd64, linux/amd64/v2, linux/amd64/v3, linux/arm64'):
            with self.subTest(field=old),self.assertRaises(ValueError):inspect_builder(GOOD.replace(old,''))
    def test_unexpected_driver_node_endpoint_and_platform(self):
        for old,new in [('Driver:        docker','Driver: docker-container'),('Endpoint:      default','Endpoint: ssh://remote'),('Status:        running','Status: stopped'),('linux/amd64, linux/amd64/v2, linux/amd64/v3, linux/arm64','linux/arm64'),('Name:          default','Name: other')]:
            with self.subTest(value=new),self.assertRaises(ValueError):inspect_builder(GOOD.replace(old,new))
    def test_duplicate_headers_nodes_or_fields_rejected(self):
        for extra in ('Driver: docker\n','Nodes:\n','Name: default\nEndpoint: default\nStatus: running\nPlatforms: linux/amd64\n','Endpoint: default\n'):
            with self.assertRaises(ValueError):inspect_builder(GOOD+extra)
    def test_json_errors_ansi_and_malformed_output_rejected(self):
        for raw in ('','unknown flag: --format','{}',GOOD+'garbage',GOOD+'Error: failed',GOOD.replace('linux/amd64,','linux/amd64???,'),'\x1b[31m'+GOOD,None):
            with self.subTest(value=raw),self.assertRaises(ValueError):inspect_builder(raw)
    def test_remote_default_context_fails_closed(self):
        with patch.object(release.os,'name','posix'),patch.object(release.os,'getuid',return_value=1000,create=True),patch.object(release,'command',side_effect=['linux/amd64',GOOD,json.dumps([{'Endpoints':{'docker':{'Host':'ssh://remote'}}}])]):
            with self.assertRaises(Exception):release.builder()
    def test_failed_inspection_does_not_continue(self):
        with patch.object(release.os,'name','posix'),patch.object(release.os,'getuid',return_value=1000,create=True),patch.object(release,'command',side_effect=['linux/amd64',RuntimeError('unknown flag: --format')]) as command:
            with self.assertRaises(Exception):release.builder()
            self.assertEqual(command.call_count,2)
    def test_preflight_has_no_host_node_npm_or_buildx_format(self):
        source=(ROOT/'host-preflight.sh').read_text()
        self.assertNotIn("'node'",source);self.assertNotIn("'npm'",source)
        self.assertIn("inspect_builder(docker(['buildx','inspect','default']))",source)
        self.assertNotIn("['buildx','inspect','default','--format'",source)
        self.assertIn('EXPECTED=sys.argv[2]',source)
