#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NOCYBER_INSTALLER_LIBRARY=1
# Resolved from the repository root at runtime.
# shellcheck disable=SC1091
source "$repo_root/install.sh"

fail() {
  printf 'installer test failed: %s\n' "$*" >&2
  exit 1
}

expect_success() {
  "$@" || fail "expected success: $*"
}

expect_failure() {
  if "$@"; then
    fail "expected failure: $*"
  fi
}

expect_success validate_release_version v0.8.0
expect_success validate_release_version v1.2.3-rc.1
expect_failure validate_release_version 0.8.0
expect_failure validate_release_version 'v1.2'

expect_success validate_http_url http://sub2api:8080
expect_success validate_http_url https://api.example.com/backend
expect_failure validate_http_url http://user:pass@example.com
expect_failure validate_http_url 'https://api.example.com/?token=secret'
expect_failure validate_http_url 'file:///etc/passwd'

expect_success validate_safe_name nocyber-guard
expect_failure validate_safe_name '../escape'
expect_success validate_domain api.example.com
expect_failure validate_domain localhost
expect_success validate_port 18086
expect_failure validate_port 0
expect_failure validate_port 65536
expect_success validate_install_dir /opt/nocyber-guard
expect_failure validate_install_dir /
expect_failure validate_install_dir '/opt/with space'
expect_failure validate_install_dir '/opt/../etc/nocyber-guard'
expect_failure validate_install_dir '/opt/./nocyber-guard'
expect_failure validate_install_dir '/opt//nocyber-guard'
expect_success validate_secret 'a-long-password'
expect_failure validate_secret short

test_dir="$(mktemp -d)"
trap 'rm -rf -- "$test_dir"' EXIT
mkdir -p "$test_dir/data" "$test_dir/secrets"
printf master >"$test_dir/secrets/master_key"
printf password >"$test_dir/secrets/admin_password"

env_file="$test_dir/.env"
write_env_file "$env_file" \
  'ghcr.io/abingooo/nocyber-guard@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  nocyber-guard http://sub2api:8080 nocyber-guard 18086 19090 \
  "$test_dir/data" "$test_dir/secrets" 172.20.0.1/32
grep -Fq 'NCG_UPSTREAM_URL=http://sub2api:8080' "$env_file" || fail 'missing upstream URL'
grep -Fq 'NCG_TRUSTED_PROXY_CIDRS=172.20.0.1/32' "$env_file" || fail 'missing trusted proxy'
if grep -Eq 'PASSWORD|MASTER_KEY=' "$env_file"; then
  fail 'secret material leaked into .env'
fi

override_without="$test_dir/without-updater.yml"
override_with="$test_dir/with-updater.yml"
write_compose_override "$override_without" 0
write_compose_override "$override_with" 1
[[ "$(grep -c '^    environment:' "$override_with")" == "1" ]] || fail 'duplicate environment mapping'
grep -Fq 'NCG_MASTER_KEY_FILE=/run/secrets/ncg_master_key' "$override_with" || fail 'missing master key file mode'
grep -Fq 'NCG_UPDATER_SOCKET=/run/nocyber-updater/updater.sock' "$override_with" || fail 'missing updater socket'
expect_failure grep -Fq 'NCG_UPDATER_SOCKET=' "$override_without"

write_proxy_examples "$test_dir/proxy" api.example.com 18086
grep -Fq 'api.example.com {' "$test_dir/proxy/nocyber-guard.caddy" || fail 'invalid Caddy domain'
grep -Fq 'upstream nocyber_guard_18086' "$test_dir/proxy/nocyber-guard-nginx.conf" || fail 'invalid Nginx upstream'
# Match the literal Nginx variable.
# shellcheck disable=SC2016
grep -Fq 'proxy_set_header Host $host;' "$test_dir/proxy/nocyber-guard-nginx.conf" || fail 'Nginx variables were expanded'

if docker compose version >/dev/null 2>&1; then
  NCG_UPSTREAM_URL=http://sub2api:8080 \
  docker compose -f "$repo_root/docker-compose.yml" -f "$override_with" \
    --env-file "$env_file" config --quiet
fi

printf 'installer contract tests passed\n'
