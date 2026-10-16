#!/usr/bin/env bash
# Called after the Python scan gate. Never starts the production service.
set -Eeuo pipefail
umask 077
root=$(cd -- "$(dirname -- "$0")" && pwd -P)
evidence=${1:?}; run=${2:?}; target=${3:?}; source_dir=${4:?}
[[ $run =~ ^[0-9]{8}t[0-9]{6}z-[0-9a-f]{16}$ && $target =~ ^sha256:[0-9a-f]{64}$ ]] || exit 2
[[ $(dirname -- "$(dirname -- "$(realpath -- "$evidence")")") == "$(realpath -- "$source_dir")/validation-results" ]] || exit 2
# One-use capability arrives only on the owning Python operation's stdin.
IFS= read -r boundary_token
printf '%s\n' "$boundary_token" | python3 -B "$root/docker-release.py" --source "$source_dir" runtime-guard "$target" "$(dirname -- "$evidence")"
unset boundary_token
project="pfcheck-$run"; containers=(); phase=runtime
docker_cmd() { command docker --host unix:///var/run/docker.sock "$@"; }
note() { printf '%s\n' "$*"; }
cleanup() {
  rc=$?; trap - EXIT; set +e
  for container_id in "${containers[@]}"; do
    if test "$(docker_cmd inspect --format '{{.Id}} {{index .Config.Labels "org.passwordforge.scan-run"}}' "$container_id" 2>/dev/null)" = "$container_id $run"; then
      docker_cmd rm -f "$container_id" >>"$evidence/cleanup.log" 2>&1 || rc=1
    else rc=1; fi
  done
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
source "$root/runtime-check.sh"
runtime_check "$target"
