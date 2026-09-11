#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose_file="$repo_root/.github/compose.e2e.yml"
project_name="ncg-e2e-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"

compose() {
  docker compose --project-name "$project_name" --project-directory "$repo_root" -f "$compose_file" "$@"
}

cleanup() {
  status=$?
  trap - EXIT
  if [[ $status -ne 0 ]]; then
    compose ps --all || true
    compose logs --no-color guard fake-upstream || true
  fi
  compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

docker version >/dev/null
docker compose version
compose config --quiet
compose build guard fake-upstream e2e
compose up --detach --wait --wait-timeout 90 fake-upstream guard
compose run --rm --no-deps e2e primary

compose restart guard
compose up --detach --wait --wait-timeout 90 guard
compose run --rm --no-deps e2e persistence

seed_digest="$(printf '%s' 'nocyber-guard-compose-e2e-v1' | sha256sum | awk '{print toupper($1)}')"
runtime_canary="NCG_E2E_${seed_digest}"
guard_logs="$(compose logs --no-color guard)"
if grep -Fq -- "$runtime_canary" <<<"$guard_logs"; then
  echo "Guard logs exposed the runtime plaintext canary" >&2
  exit 1
fi

echo "Compose E2E completed successfully"
