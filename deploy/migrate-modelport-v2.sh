#!/bin/sh
set -eu

# This helper never accepts or prints a database password, API key,
# ciphertext, prompt content, or administrator password. Source access uses a
# local docker exec; target access uses an administrator cookie created
# outside this script.

usage() {
    cat >&2 <<'EOF'
Usage:
  migrate-modelport-v2.sh export --output FILE [--source-container NAME] [--source-db DB] [--source-user USER]
  migrate-modelport-v2.sh validate --input FILE
  migrate-modelport-v2.sh import --input FILE --guard-url URL [--cookie-file FILE] [--dry-run]

Environment:
  NCG_ADMIN_COOKIE_FILE       Netscape-format curl cookie jar (alternative to --cookie-file)
  NCG_ADMIN_CSRF_TOKEN_FILE   Optional file containing the ncg_csrf value

Export is repeatable-read and read-only. It includes only global active
trusted hashes, all active risk hashes, the three enabled Codex profiles, and
the highest-priority enabled synchronous AI-node metadata. Scoped trusted
rules are counted but skipped. Prompt evidence, users, events, and all AI
credentials are excluded.
EOF
    exit 2
}

die() { printf '%s\n' "migrate-modelport-v2: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

validate_export() {
    jq -e '
      def hash_row:
        ((.kind == "trusted" or .kind == "risk") and
         (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
         (.label | type == "string"));
      def matcher:
        ((.type == "prefix" or .type == "exact" or .type == "regex") and
         (.value | type == "string" and length > 0));
      def profile_row:
        (.kind == "client_profile" and
         (.profile_key == "codex_vscode" or .profile_key == "codex_cli" or .profile_key == "codex_desktop") and
         (.name | type == "string" and length > 0) and
         (.description | type == "string") and
         (.priority | type == "number") and .enabled == true and
         (.matchers | type == "array" and length > 0 and all(.[]; matcher)));
      def ai_row:
        (.kind == "ai_endpoint" and
         (.name | type == "string" and length > 0) and
         (.base_url | type == "string" and test("^https?://")) and
         (.model | type == "string" and length > 0) and
         (.timeout_ms | type == "number" and . > 0) and
         (.max_concurrency | type == "number" and . > 0) and
         (.source_had_api_key | type == "boolean"));
      ([.[] | select(.kind == "_meta")][0]) as $meta |
      type == "array" and
      (map(select(.kind == "_meta")) | length) == 1 and
      all(.[]; (.kind == "_meta") or hash_row or profile_row or ai_row) and
      ([.[] | select(.kind == "client_profile") | .profile_key] | sort) ==
        ["codex_cli", "codex_desktop", "codex_vscode"] and
      ([.[] | select(.kind == "ai_endpoint")] | length) == 1 and
      ([.[] | select(.kind == "trusted") | .sha256] | length) ==
        ([.[] | select(.kind == "trusted") | .sha256] | unique | length) and
      ([.[] | select(.kind == "risk") | .sha256] | length) ==
        ([.[] | select(.kind == "risk") | .sha256] | unique | length) and
      ([.[] | .. | objects |
        select(has("api_key") or has("api_key_ciphertext") or
               has("raw_ciphertext") or has("raw") or has("content"))] | length) == 0 and
      $meta.trusted_count == ([.[] | select(.kind == "trusted")] | length) and
      $meta.risk_count == ([.[] | select(.kind == "risk")] | length) and
      $meta.client_profile_count == 3 and
      $meta.sync_ai_node_count >= 1
    ' "$1" >/dev/null
}

mode=${1:-}
[ -n "$mode" ] || usage
shift

input=
output=
guard_url=
cookie_file=${NCG_ADMIN_COOKIE_FILE:-}
source_container=modelport-standalone-postgres
source_db=modelport
source_user=modelport
dry_run=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) [ "$#" -ge 2 ] || usage; output=$2; shift 2 ;;
        --input) [ "$#" -ge 2 ] || usage; input=$2; shift 2 ;;
        --guard-url) [ "$#" -ge 2 ] || usage; guard_url=$2; shift 2 ;;
        --cookie-file) [ "$#" -ge 2 ] || usage; cookie_file=$2; shift 2 ;;
        --source-container) [ "$#" -ge 2 ] || usage; source_container=$2; shift 2 ;;
        --source-db) [ "$#" -ge 2 ] || usage; source_db=$2; shift 2 ;;
        --source-user) [ "$#" -ge 2 ] || usage; source_user=$2; shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        *) usage ;;
    esac
done

case "$mode" in
    export)
        need docker
        need jq
        [ -n "$output" ] || usage
        [ "$dry_run" = false ] || usage
        [ ! -e "$output" ] || die "output already exists; choose a new path"
        umask 077
        work_dir=$(mktemp -d)
        trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
        raw_file=$work_dir/export.jsonl

        docker exec -i "$source_container" \
            psql -U "$source_user" -d "$source_db" -X -v ON_ERROR_STOP=1 -qAt \
            >"$raw_file" <<'SQL'
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '30s';
SELECT json_build_object(
  'kind','_meta',
  'source','ModelPort instruction audit V2',
  'skipped_non_global_trusted',(SELECT count(*) FROM instruction_audit_v2_hashes WHERE status='active' AND NOT global_trust),
  'skipped_hash_scopes',(SELECT count(*) FROM instruction_audit_v2_hash_scopes WHERE status='active'),
  'trusted_count',(SELECT count(*) FROM instruction_audit_v2_hashes WHERE status='active' AND global_trust),
  'risk_count',(SELECT count(*) FROM instruction_audit_v2_risk_hashes WHERE status='active'),
  'client_profile_count',(SELECT count(*) FROM instruction_audit_v2_client_profiles WHERE enabled AND profile_key IN ('codex_vscode','codex_cli','codex_desktop')),
  'sync_ai_node_count',(SELECT count(*) FROM instruction_audit_v2_ai_nodes WHERE enabled AND slot='sync')
);
SELECT json_build_object(
  'kind','trusted','sha256',lower(sha256),
  'label',coalesce(nullif(name,''),nullif(note,''),'Imported ModelPort trusted rule'))
FROM instruction_audit_v2_hashes
WHERE status='active' AND global_trust
ORDER BY id;
SELECT json_build_object(
  'kind','risk','sha256',lower(sha256),
  'label','Imported ModelPort risk rule')
FROM instruction_audit_v2_risk_hashes
WHERE status='active'
ORDER BY id;
SELECT json_build_object(
  'kind','client_profile','profile_key',profile_key,'name',name,
  'description',description,'matchers',matchers,'priority',priority,'enabled',enabled)
FROM instruction_audit_v2_client_profiles
WHERE enabled AND profile_key IN ('codex_vscode','codex_cli','codex_desktop')
ORDER BY priority,id;
SELECT json_build_object(
  'kind','ai_endpoint','name',name,'base_url',base_url,'model',model,
  'timeout_ms',timeout_ms,'max_concurrency',max_concurrency,
  'source_had_api_key',(btrim(api_key_ciphertext)<>''))
FROM instruction_audit_v2_ai_nodes
WHERE enabled AND slot='sync'
ORDER BY priority,id
LIMIT 1;
COMMIT;
SQL

        normalized_file=$work_dir/export.json
        jq -s '.' "$raw_file" >"$normalized_file"
        validate_export "$normalized_file" || die "export did not match the supported migration contract"
        trusted=$(jq '[.[] | select(.kind == "trusted")] | length' "$normalized_file")
        risk=$(jq '[.[] | select(.kind == "risk")] | length' "$normalized_file")
        skipped_rules=$(jq -r 'map(select(.kind == "_meta"))[0].skipped_non_global_trusted' "$normalized_file")
        skipped_scopes=$(jq -r 'map(select(.kind == "_meta"))[0].skipped_hash_scopes' "$normalized_file")
        mv "$normalized_file" "$output"
        printf 'Export complete: trusted=%s risk=%s profiles=3 ai_nodes=1 skipped_scoped_rules=%s skipped_scope_rows=%s. No content or credentials were copied.\n' \
            "$trusted" "$risk" "$skipped_rules" "$skipped_scopes"
        ;;
    validate)
        need jq
        [ -n "$input" ] || usage
        [ -r "$input" ] || die "input file is not readable"
        [ "$dry_run" = false ] || usage
        validate_export "$input" || die "input file does not match the supported migration contract"
        printf 'Validation complete: migration file is structurally valid and contains no secret fields.\n'
        ;;
    import)
        need curl
        need jq
        [ -n "$input" ] && [ -n "$guard_url" ] && [ -n "$cookie_file" ] || usage
        [ -r "$input" ] || die "input file is not readable"
        [ -r "$cookie_file" ] || die "cookie file is not readable"
        case "$guard_url" in http://*|https://*) ;; *) die "guard URL must use http:// or https://" ;; esac
        guard_url=${guard_url%/}
        validate_export "$input" || die "input file does not match the supported migration contract"

        umask 077
        work_dir=$(mktemp -d)
        trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
        response_file=$work_dir/response.json
        curl_config=$work_dir/curl.conf

        if [ "$dry_run" = false ]; then
            if [ -n "${NCG_ADMIN_CSRF_TOKEN_FILE:-}" ]; then
                [ -r "$NCG_ADMIN_CSRF_TOKEN_FILE" ] || die "CSRF token file is not readable"
                csrf_token=$(tr -d '\r\n' <"$NCG_ADMIN_CSRF_TOKEN_FILE")
            else
                csrf_token=$(awk '$6 == "ncg_csrf" { value=$7 } END { print value }' "$cookie_file")
            fi
            [ -n "$csrf_token" ] || die "ncg_csrf was not found in the cookie jar"
            case "$csrf_token" in *[!A-Za-z0-9._~-]*) die "invalid CSRF token format" ;; esac
            printf 'header = "X-CSRF-Token: %s"\n' "$csrf_token" >"$curl_config"
        fi

        fetch_json() {
            fetch_path=$1
            fetch_output=$2
            fetch_status=$(curl --silent --show-error --output "$fetch_output" --write-out '%{http_code}' \
                --cookie "$cookie_file" --header 'Accept: application/json' "$guard_url$fetch_path")
            [ "$fetch_status" = 200 ] || die "Guard rejected GET $fetch_path with HTTP $fetch_status"
        }
        write_json() {
            write_method=$1
            write_path=$2
            write_body=$3
            write_status=$(printf '%s' "$write_body" | curl --silent --show-error \
                --output "$response_file" --write-out '%{http_code}' --config "$curl_config" \
                --cookie "$cookie_file" --request "$write_method" \
                --header 'Content-Type: application/json' --header 'Accept: application/json' \
                --data-binary @- "$guard_url$write_path")
            case "$write_status" in 200|201|204) ;; *) die "Guard rejected $write_method $write_path with HTTP $write_status" ;; esac
        }

        trusted_file=$work_dir/trusted.json
        risk_file=$work_dir/risk.json
        profiles_file=$work_dir/profiles.json
        config_file=$work_dir/config.json
        fetch_json /api/v1/trusted-hashes "$trusted_file"
        fetch_json /api/v1/risk-hashes "$risk_file"
        fetch_json /api/v1/client-profiles "$profiles_file"
        fetch_json /api/v1/config "$config_file"
        jq -s -e 'all(.[]; type == "array")' "$trusted_file" "$risk_file" "$profiles_file" >/dev/null || die "Guard returned an invalid collection"
        jq -e 'type == "object" and (.ai_endpoint | type == "object")' "$config_file" >/dev/null || die "Guard returned an invalid config"

        rules_created=0
        rules_skipped=0
        rules_file=$work_dir/rules.jsonl
        jq -c '.[] | select(.kind == "trusted" or .kind == "risk")' "$input" >"$rules_file"
        while IFS= read -r item; do
            kind=$(printf '%s' "$item" | jq -r '.kind')
            sha=$(printf '%s' "$item" | jq -r '.sha256')
            body=$(printf '%s' "$item" | jq -c '{sha256:.sha256,label:.label}')
            existing_file=$trusted_file
            [ "$kind" = trusted ] || existing_file=$risk_file
            if jq -e --arg sha "$sha" 'any(.[]; .sha256 == $sha)' "$existing_file" >/dev/null; then
                rules_skipped=$((rules_skipped + 1))
            else
                rules_created=$((rules_created + 1))
                if [ "$dry_run" = false ]; then
                    write_json POST "/api/v1/$kind-hashes" "$body"
                fi
            fi
        done <"$rules_file"

        profiles_created=0
        profiles_updated=0
        profiles_skipped=0
        profile_rows=$work_dir/profiles.jsonl
        jq -c '.[] | select(.kind == "client_profile")' "$input" >"$profile_rows"
        while IFS= read -r item; do
            name=$(printf '%s' "$item" | jq -r '.name')
            body=$(printf '%s' "$item" | jq -Sc '
              {name,description,enabled,priority,
               matchers:(.matchers | map({
                 type,
                 value,
                 case_sensitive:(.case_sensitive // false)
               }))}
            ')
            profile_id=$(jq -r --arg name "$name" 'first(.[] | select(.name == $name) | .id) // empty' "$profiles_file")
            if [ -z "$profile_id" ]; then
                profiles_created=$((profiles_created + 1))
                if [ "$dry_run" = false ]; then
                    write_json POST /api/v1/client-profiles "$body"
                fi
                continue
            fi
            case "$profile_id" in *[!0-9]*) die "Guard returned an invalid client profile ID" ;; esac
            current=$(jq -Sc --arg name "$name" '
              first(.[] | select(.name == $name)) |
              {name,description,enabled,priority,
               matchers:(.matchers | map({
                 type,
                 value,
                 case_sensitive:(.case_sensitive // false)
               }))}
            ' "$profiles_file")
            if [ "$current" = "$body" ]; then
                profiles_skipped=$((profiles_skipped + 1))
            else
                profiles_updated=$((profiles_updated + 1))
                if [ "$dry_run" = false ]; then
                    write_json PUT "/api/v1/client-profiles/$profile_id" "$body"
                fi
            fi
        done <"$profile_rows"

        ai_item=$(jq -c 'first(.[] | select(.kind == "ai_endpoint"))' "$input")
        ai_body=$(printf '%s' "$ai_item" | jq -Sc '{base_url,model,api_key:"",timeout_ms,max_concurrency}')
        ai_desired=$(printf '%s' "$ai_item" | jq -Sc '{base_url,model,timeout_ms,max_concurrency}')
        ai_current=$(jq -Sc '.ai_endpoint | {base_url,model,timeout_ms,max_concurrency}' "$config_file")
        ai_updated=0
        ai_skipped=0
        if [ "$ai_current" = "$ai_desired" ]; then
            ai_skipped=1
        else
            ai_updated=1
            if [ "$dry_run" = false ]; then
                write_json PUT /api/v1/ai-endpoint "$ai_body"
            fi
        fi

        if [ "$dry_run" = true ]; then
            prefix='Dry run complete'
        else
            prefix='Import complete'
        fi
        printf '%s: rules_create=%s rules_skip=%s profiles_create=%s profiles_update=%s profiles_skip=%s ai_update=%s ai_skip=%s. AI credentials were not imported; enter the key in Guard before enabling AI review.\n' \
            "$prefix" "$rules_created" "$rules_skipped" "$profiles_created" "$profiles_updated" "$profiles_skipped" "$ai_updated" "$ai_skipped"
        ;;
    *) usage ;;
esac
