#!/usr/bin/env bash
# Sourced only by runtime.sh; task containers are registered with its cleanup trap.
runtime_check() {
local target=$1 check="$project-runtime" port=18080
[[ $target =~ ^sha256:[0-9a-f]{64}$ && $check =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 2
local inputs="$(dirname -- "$evidence")/runtime-inputs.json" expected_version production
expected_version=$(python3 -B "$root/runtime_inputs.py" version "$inputs") || return 2
if docker_cmd container inspect "$check" >/dev/null 2>&1; then note 'BLOCKER: runtime name collision.'; return 2; fi
test -z "$(ss -H -ltn "sport = :$port")" || return 2
production=$(docker_cmd inspect --format '{"containerId":{{json .Id}},"imageId":{{json .Image}},"startedAt":{{json .State.StartedAt}},"name":{{json .Name}},"status":{{json .State.Status}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}}}' passwordforge) || return 2
printf '%s' "$production" | python3 -B "$root/runtime_inputs.py" production "$inputs" "$target" || return 2
if docker_cmd run --pull never -d --name "$check" --label "org.passwordforge.scan-run=$run" --network bridge --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:rw,noexec,nosuid,size=16m,mode=1777 --pids-limit 128 --memory 128m --cpus 1 --restart no -p "127.0.0.1:$port:8080" "$target" >"$evidence/container-id.txt"; then
  container_id=$(cat "$evidence/container-id.txt")
  [[ $container_id =~ ^[0-9a-f]{64}$ ]] || { note 'BLOCKER: no captured container ID; manual ownership review required.'; return 2; }
  containers+=("$container_id")
  check=$container_id
else
  container_id=$(cat "$evidence/container-id.txt")
  if [[ $container_id =~ ^[0-9a-f]{64}$ ]]; then containers+=("$container_id"); fi
  note 'Startup FAILED. Only a container bearing this unique task label is eligible for cleanup.'; exit 1
fi
# With no package arguments, verbose info lists installed package-version pairs.
# Named arguments select descriptive detail output in some apk versions.
docker_cmd exec "$check" apk info -v >"$evidence/runtime-package-versions.txt"
for package in libexpat-2.8.5-r0 pcre2-10.49-r0 tiff-4.7.2-r0 libpng-1.6.59-r0 nghttp2-libs-1.70.0-r0 zlib-1.3.2-r1; do
  grep -Fxq "$package" "$evidence/runtime-package-versions.txt" || { note "BLOCKER: expected fixed package version missing: $package"; return 1; }
done
docker_cmd exec "$check" sh -c 'ldd /usr/sbin/nginx; ldd /usr/bin/curl' >"$evidence/runtime-linked-libraries.txt" 2>&1
docker_cmd exec "$check" nginx -V >"$evidence/nginx-version.txt" 2>&1
docker_cmd exec "$check" nginx -t >"$evidence/nginx-test.txt" 2>&1
for attempt in $(seq 1 30); do
  state=$(docker_cmd inspect --format '{{with index .State "Health"}}{{index . "Status"}}{{else}}none{{end}}' "$check")
  test "$state" = healthy && break
  test "$state" != unhealthy || break
  sleep 2
done
note "Startup health state: $state"
test "$state" = healthy
test "$(docker_cmd exec "$check" wget -q -O - http://127.0.0.1:8080/healthz)" = ok
test "$(curl --noproxy '*' --fail --silent --show-error --max-time 10 "http://127.0.0.1:$port/healthz")" = ok
note 'Container and loopback /healthz: PASS'
phase=runtime-http
for asset in / /theme.js /app.js /core.js /dictionary.js /profiles.js /policy.js /random-password.js /profile-output.js /styles.css /licenses/NOTICE.txt /licenses/CC-BY-4.0.txt /licenses/ESDB-Copyright.txt /licenses/esdb-provenance.json /healthz; do
  file=${asset//\//_}
  code=$(curl --noproxy '*' --silent --show-error --max-time 10 -D "$evidence/$file.headers" -o "$evidence/$file.body" -w '%{http_code}' "http://127.0.0.1:$port$asset")
  test "$code" = 200 || { note "BLOCKER: HTTP delivery failed for $asset"; return 1; }
  test -s "$evidence/$file.body" || { note "BLOCKER: empty response for $asset"; return 1; }
  for policy in "default-src 'none'" "connect-src 'none'" "frame-ancestors 'none'" 'camera=(), microphone=(), geolocation=()'; do grep -Fqi "$policy" "$evidence/$file.headers"; done
  for header in 'Cache-Control: *no-store' 'X-Content-Type-Options: *nosniff' 'Referrer-Policy: *no-referrer' 'X-Frame-Options: *DENY'; do grep -Eqi "^$header" "$evidence/$file.headers"; done
done
grep -Fq "class=\"version\">v${expected_version}</span>" "$evidence/_.body" || return 2
grep -Fq 'Less squinting. More security.' "$evidence/_.body"
for module in theme app core dictionary profiles policy random-password profile-output; do
  grep -Eqi '^Content-Type: *(text|application)/javascript' "$evidence/_$module.js.headers"
done
grep -Eqi '^Content-Type: *text/css' "$evidence/_styles.css.headers"
test "$(curl --noproxy '*' --silent --show-error --max-time 10 -D "$evidence/404.headers" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/passwordforge-missing")" = 404
grep -Eqi '^Cache-Control: *no-store' "$evidence/404.headers"
grep -Fqi "frame-ancestors 'none'" "$evidence/404.headers"
test "$(curl --noproxy '*' --silent --show-error --max-time 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/tests/browser-regeneration.mjs")" = 404
note 'Public static assets, bundled licenses, health/error headers, MIME types and test-fixture exclusion: PASS'
phase=runtime-hardening
test "$(docker_cmd exec "$check" id -u)" = 10001
test "$(docker_cmd exec "$check" id -g)" = 10001
test "$(docker_cmd inspect --format '{{index .Config.Labels "traefik.enable"}}' "$check")" != true
# Serialize only selected fields. Do not save full container inspection/environment.
docker_cmd inspect --format '{"User":{{json .Config.User}},"HostConfig":{"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"Privileged":{{json .HostConfig.Privileged}},"CapDrop":{{json .HostConfig.CapDrop}},"CapAdd":{{json .HostConfig.CapAdd}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"PidsLimit":{{json .HostConfig.PidsLimit}},"Memory":{{json .HostConfig.Memory}},"NanoCpus":{{json .HostConfig.NanoCpus}},"Tmpfs":{{json .HostConfig.Tmpfs}},"PortBindings":{{json .HostConfig.PortBindings}},"NetworkMode":{{json .HostConfig.NetworkMode}},"RestartPolicy":{{json .HostConfig.RestartPolicy}}},"Networks":{{json .NetworkSettings.Networks}},"Healthcheck":{{json .Config.Healthcheck}}}' "$check" >"$evidence/hardening.json"
python3 "$root/checks.py" hardening "$evidence/hardening.json" "$port"
note 'Non-root user, filesystem, capabilities, no-new-privileges, limits, loopback binding, bridge-only networking and health configuration: PASS'

test "$(docker_cmd inspect --format '{{.Image}}' "$check")" = "$target"
# Record linkage only after every runtime check passed. Never equate differing IDs.
python3 - "$target" "$evidence/runtime-validation.json" "$expected_version" <<'PY'
import json,sys
json.dump({'status':'passed','imageId':sys.argv[1],'version':sys.argv[3],'checks':['health','static-assets','headers','nonroot','hardening','loopback','bridge-only']},open(sys.argv[2],'x'),indent=2)
PY
}
