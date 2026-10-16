"""Exercise the actual HTTP smoke block with synthetic curl; never invoke Docker."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest
from test_docker_release import ROOT

MODULES = ('theme', 'app', 'core', 'dictionary', 'profiles', 'policy', 'random-password', 'profile-output')

class RuntimeAssetTests(unittest.TestCase):
    def execute(self, failure='', module='profiles', version='0.6.0', expected='0.6.0', conditional=False):
        bash=shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'
        block=(ROOT/'runtime-check.sh').read_text().split('phase=runtime-http\n',1)[1].split('phase=runtime-hardening',1)[0]
        fixture=r'''
set -Eeuo pipefail
evidence=$PWD; port=18080; expected_version=$expected
note(){ :; }
curl(){
 local header='' body='' url='' code=200 mime='application/javascript'
 while (($#)); do
  case "$1" in -D) header=$2;shift 2;; -o) body=$2;shift 2;; http://*) url=$1;shift;; *) shift;; esac
 done
 local asset=${url#http://127.0.0.1:18080}
 case "$asset" in /) mime=text/html;; /styles.css) mime=text/css;; esac
 case "$asset" in /passwordforge-missing|/tests/browser-regeneration.mjs) code=404;; esac
 if [[ $failure == missing && $asset == /$module.js ]]; then code=404; fi
 if [[ $failure == mime && $asset == /$module.js ]]; then mime=text/plain; fi
 if [[ -n $header ]]; then
  printf 'Content-Type: %s\nCache-Control: no-store\nX-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer\nX-Frame-Options: DENY\nPermissions-Policy: camera=(), microphone=(), geolocation=()\n' "$mime" >"$header"
  if [[ $failure != headers || $asset != /$module.js ]]; then
   printf "Content-Security-Policy: default-src 'none'; connect-src 'none'; frame-ancestors 'none'\n" >>"$header"
  fi
 fi
 if [[ -n $body ]]; then
  if [[ $failure == old-version && $asset == / ]]; then printf '<span class="version">v0.5.0</span> Less squinting. More security.' >"$body"
  else printf '<span class="version">v%s</span> Less squinting. More security.' "$version" >"$body"; fi
 fi
 printf '%s' "$code"
}
'''
        with tempfile.TemporaryDirectory() as temp:
            script=Path(temp)/'smoke.sh'
            invocation='if runtime_http; then exit 0; else exit $?; fi\n' if conditional else 'runtime_http\n'
            script.write_text(fixture+'runtime_http(){\n'+block+'\n}\n'+invocation,encoding='utf-8',newline='\n')
            env=dict(os.environ,failure=failure,module=module,version=version,expected=expected)
            return subprocess.run([bash,str(script)],cwd=temp,env=env,capture_output=True).returncode

    def test_complete_current_assets_pass(self):self.assertEqual(self.execute(),0)
    def test_each_missing_module_fails_closed(self):
        for module in MODULES:
            with self.subTest(module=module):self.assertNotEqual(self.execute('missing',module),0)
    def test_each_wrong_module_mime_fails_closed(self):
        for module in MODULES:
            with self.subTest(module=module):self.assertNotEqual(self.execute('mime',module),0)
    def test_each_missing_security_header_fails_closed(self):
        for module in MODULES:
            with self.subTest(module=module):self.assertNotEqual(self.execute('headers',module),0)
    def test_old_version_banner_fails_closed(self):self.assertNotEqual(self.execute('old-version'),0)

    def test_future_versions_pass_without_historical_expectation(self):
        for version in ('1.0.0','1.2.3','2.0.0'):
            with self.subTest(version=version):self.assertEqual(self.execute(version=version,expected=version),0)
    def test_wrong_banner_version_fails(self):
        self.assertNotEqual(self.execute(version='0.6.0',expected='1.0.0'),0)
        self.assertNotEqual(self.execute(version='1.0.01',expected='1.0.0'),0)

    def test_wrong_banner_stops_even_under_outer_conditional(self):
        self.assertNotEqual(self.execute(version='0.6.0',expected='1.0.0',conditional=True),0)
