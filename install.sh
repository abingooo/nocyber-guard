#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly NCG_REPOSITORY="abingooo/nocyber-guard"
readonly NCG_IMAGE_REPOSITORY="ghcr.io/abingooo/nocyber-guard"
readonly NCG_INSTALLER_SCHEMA="1"

NON_INTERACTIVE=0
AUTO_YES=0
RELEASE_VERSION="${NCG_INSTALL_VERSION:-}"
INSTALL_DIR="${NCG_INSTALL_DIR:-/opt/nocyber-guard}"
WITH_UPDATER="${NCG_INSTALL_WITH_UPDATER:-}"
PROXY_MODE="${NCG_INSTALL_PROXY_MODE:-}"
DOMAIN="${NCG_INSTALL_DOMAIN:-}"
TTY_DEVICE="/dev/tty"
TEMP_DIR=""

if [[ -t 1 ]]; then
  COLOR_CYAN=$'\033[36m'
  COLOR_GREEN=$'\033[32m'
  COLOR_YELLOW=$'\033[33m'
  COLOR_RED=$'\033[31m'
  COLOR_RESET=$'\033[0m'
else
  COLOR_CYAN=""
  COLOR_GREEN=""
  COLOR_YELLOW=""
  COLOR_RED=""
  COLOR_RESET=""
fi

log() { printf '%s[NoCyber]%s %s\n' "$COLOR_CYAN" "$COLOR_RESET" "$*"; }
success() { printf '%s[完成]%s %s\n' "$COLOR_GREEN" "$COLOR_RESET" "$*"; }
warn() { printf '%s[注意]%s %s\n' "$COLOR_YELLOW" "$COLOR_RESET" "$*" >&2; }
die() { printf '%s[失败]%s %s\n' "$COLOR_RED" "$COLOR_RESET" "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
NoCyber Guard 交互式安装器

用法：
  sudo bash install.sh [选项]

选项：
  --version vX.Y.Z       安装指定正式版本；默认读取 GitHub Latest Release
  --install-dir PATH     安装目录，默认 /opt/nocyber-guard
  --non-interactive      使用 NCG_INSTALL_* 环境变量，无交互安装
  --yes                  自动确认软件包安装和 Docker 网络连接
  --with-updater         安装网页一键更新/回滚服务
  --without-updater      不安装网页一键更新/回滚服务
  --proxy MODE           reverse proxy：none、generate、nginx 或 caddy
  -h, --help             显示帮助

无交互模式至少需要：
  NCG_INSTALL_UPSTREAM_URL=http://可从容器访问的地址:端口
  NCG_INSTALL_ADMIN_PASSWORD=长度至少 12 位的管理员密码

可选环境变量：
  NCG_INSTALL_VERSION、NCG_INSTALL_DIR、NCG_INSTALL_NETWORK_NAME
  NCG_INSTALL_PROXY_PORT、NCG_INSTALL_ADMIN_PORT、NCG_INSTALL_DOMAIN
  NCG_INSTALL_PROXY_MODE、NCG_INSTALL_WITH_UPDATER
EOF
}

while (($# > 0)); do
  case "$1" in
    --version)
      (($# >= 2)) || die "--version 缺少参数"
      RELEASE_VERSION="$2"
      shift 2
      ;;
    --install-dir)
      (($# >= 2)) || die "--install-dir 缺少参数"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --yes)
      AUTO_YES=1
      shift
      ;;
    --with-updater)
      WITH_UPDATER=1
      shift
      ;;
    --without-updater)
      WITH_UPDATER=0
      shift
      ;;
    --proxy)
      (($# >= 2)) || die "--proxy 缺少参数"
      PROXY_MODE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "未知参数：$1" ;;
  esac
done

validate_release_version() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]
}

validate_http_url() {
  [[ "$1" =~ ^https?://[A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._~%+/@-]*)?/?$ ]]
}

validate_safe_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]]
}

validate_domain() {
  [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

validate_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

validate_install_dir() {
  [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] &&
    [[ "$1" != "/" ]] &&
    [[ "$1" != "/opt" ]] &&
    [[ "/$1/" != *"/../"* ]] &&
    [[ "/$1/" != *"/./"* ]] &&
    [[ "$1" != *"//"* ]]
}

validate_secret() {
  [[ ${#1} -ge 12 ]] && [[ "$1" != *$'\n'* ]] && [[ "$1" != *$'\r'* ]]
}

validate_proxy_mode() {
  [[ "$1" == "none" || "$1" == "generate" || "$1" == "nginx" || "$1" == "caddy" ]]
}

prompt_value() {
  local variable="$1" message="$2" default="${3:-}" value=""
  if ((NON_INTERACTIVE)); then
    printf -v "$variable" '%s' "$default"
    return
  fi
  [[ -r "$TTY_DEVICE" ]] || die "当前没有可用终端；请使用 --non-interactive"
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$message" "$default" >"$TTY_DEVICE"
  else
    printf '%s: ' "$message" >"$TTY_DEVICE"
  fi
  IFS= read -r value <"$TTY_DEVICE" || die "无法读取输入"
  printf -v "$variable" '%s' "${value:-$default}"
}

prompt_secret_twice() {
  local variable="$1" first="" second=""
  [[ -r "$TTY_DEVICE" ]] || die "当前没有可用终端"
  printf '设置管理员密码（至少 12 位）: ' >"$TTY_DEVICE"
  IFS= read -r -s first <"$TTY_DEVICE" || die "无法读取密码"
  printf '\n再次输入管理员密码: ' >"$TTY_DEVICE"
  IFS= read -r -s second <"$TTY_DEVICE" || die "无法读取密码"
  printf '\n' >"$TTY_DEVICE"
  [[ "$first" == "$second" ]] || die "两次密码不一致"
  validate_secret "$first" || die "管理员密码至少需要 12 位且不能包含换行"
  printf -v "$variable" '%s' "$first"
}

confirm() {
  local message="$1" default_yes="${2:-1}" answer=""
  if ((AUTO_YES)); then
    return 0
  fi
  if ((NON_INTERACTIVE)); then
    return 1
  fi
  if ((default_yes)); then
    prompt_value answer "$message (Y/n)" "Y"
  else
    prompt_value answer "$message (y/N)" "N"
  fi
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

download() {
  local url="$1" destination="$2"
  curl --fail --silent --show-error --location --retry 3 \
    --proto '=https' --tlsv1.2 "$url" --output "$destination"
}

read_env_value() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 1
  sed -n "s/^${key}=//p" "$file" | tail -n 1
}

write_env_file() {
  local path="$1" image="$2" container="$3" upstream="$4" network="$5"
  local proxy_port="$6" admin_port="$7" data_path="$8" secret_path="$9"
  local trusted_proxy="${10:-}"
  cat >"$path" <<EOF
NCG_IMAGE=$image
NCG_CONTAINER_NAME=$container
NCG_UPSTREAM_URL=$upstream
NCG_NETWORK_NAME=$network
NCG_NETWORK_EXTERNAL=true
NCG_BIND_HOST=127.0.0.1
NCG_PROXY_PORT=$proxy_port
NCG_ADMIN_BIND_HOST=127.0.0.1
NCG_ADMIN_PORT=$admin_port
NCG_DATA_PATH=$data_path
NCG_SECRET_PATH=$secret_path
NCG_TRUSTED_PROXY_CIDRS=$trusted_proxy
NCG_AUDIT_BODY_LIMIT=4194304
NCG_AI_CONCURRENCY=16
NCG_AI_TIMEOUT=15s
NCG_AI_QUEUE_TIMEOUT=2s
NCG_ADMIN_COOKIE_SECURE=false
TZ=Asia/Shanghai
EOF
  chmod 0600 "$path"
}

write_compose_override() {
  local path="$1" with_updater="$2"
  cat >"$path" <<'EOF'
services:
  guard:
    environment:
      - NCG_MASTER_KEY_FILE=/run/secrets/ncg_master_key
      - NCG_INITIAL_ADMIN_PASSWORD_FILE=/run/secrets/ncg_initial_admin_password
EOF
  if [[ "$with_updater" == "1" ]]; then
    cat >>"$path" <<'EOF'
      - NCG_UPDATER_SOCKET=/run/nocyber-updater/updater.sock
EOF
  fi
  cat >>"$path" <<'EOF'
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ${NCG_SECRET_PATH:?NCG_SECRET_PATH is required}/master_key:/run/secrets/ncg_master_key:ro
      - ${NCG_SECRET_PATH:?NCG_SECRET_PATH is required}/admin_password:/run/secrets/ncg_initial_admin_password:ro
EOF
  if [[ "$with_updater" == "1" ]]; then
    cat >>"$path" <<'EOF'
      - /run/nocyber-updater:/run/nocyber-updater:ro
EOF
  fi
  chmod 0644 "$path"
}

write_proxy_examples() {
  local directory="$1" domain="$2" proxy_port="$3"
  mkdir -p "$directory"
  cat >"$directory/nocyber-guard.caddy" <<EOF
$domain {
    reverse_proxy 127.0.0.1:$proxy_port {
        flush_interval -1
        transport http {
            read_timeout 3600s
            write_timeout 3600s
        }
    }
}
EOF
  cat >"$directory/nocyber-guard-nginx-map.conf" <<'EOF'
map $http_upgrade $nocyber_connection_upgrade {
    default upgrade;
    '' close;
}
EOF
  cat >"$directory/nocyber-guard-nginx.conf" <<EOF
upstream nocyber_guard_$proxy_port {
    server 127.0.0.1:$proxy_port max_fails=2 fail_timeout=10s;
}

server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    client_max_body_size 256m;

    location / {
        proxy_pass http://nocyber_guard_$proxy_port;
        proxy_next_upstream off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$nocyber_connection_upgrade;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_connect_timeout 60s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
}

if [[ "${NOCYBER_INSTALLER_LIBRARY:-0}" == "1" ]]; then
  if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
  fi
  exit 0
fi

[[ "$(uname -s)" == "Linux" ]] || die "安装器目前仅支持 Linux"
((EUID == 0)) || die "请使用 root 运行，例如：sudo bash install.sh"
validate_install_dir "$INSTALL_DIR" || die "安装目录必须是安全的绝对路径，且不能是 / 或 /opt"
[[ ! -L "$INSTALL_DIR" ]] || die "安装目录不能是符号链接：$INSTALL_DIR"

for required in curl openssl sed awk grep; do
  command -v "$required" >/dev/null 2>&1 || die "缺少命令：$required"
done

printf '\n%sNoCyber Guard 安装向导%s\n' "$COLOR_CYAN" "$COLOR_RESET"
printf '透明接入 Sub2API、NewAPI 或其他 OpenAI-compatible 网关。\n\n'

install_docker_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl openssl docker.io
    if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
      apt-get install -y docker-compose-v2
    elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
      apt-get install -y docker-compose-plugin
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl openssl docker docker-compose-plugin
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl openssl docker docker-compose-plugin
  else
    die "无法识别包管理器，请先安装 Docker Engine 与 Compose v2"
  fi
  command -v systemctl >/dev/null 2>&1 && systemctl enable --now docker
}

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  confirm "未检测到 Docker Engine + Compose v2，是否安装" 1 || die "请先安装 Docker Engine 与 Compose v2"
  install_docker_packages
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 不可用"
docker info >/dev/null 2>&1 || die "Docker 服务不可用"

if [[ -z "$RELEASE_VERSION" ]]; then
  log "读取最新正式版本"
  TEMP_DIR="$(mktemp -d)"
  release_json="$TEMP_DIR/release.json"
  download "https://api.github.com/repos/$NCG_REPOSITORY/releases/latest" "$release_json"
  RELEASE_VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$release_json" | head -n 1)"
fi
validate_release_version "$RELEASE_VERSION" || die "正式版本号无效：$RELEASE_VERSION"
[[ -n "$TEMP_DIR" ]] || TEMP_DIR="$(mktemp -d)"
log "准备安装 $RELEASE_VERSION"

if [[ -e "$INSTALL_DIR/.env" || -e "$INSTALL_DIR/.nocyber-managed" ]]; then
  die "$INSTALL_DIR 已存在 NoCyber Guard 配置；为保护数据，安装器不会覆盖现有实例"
fi
if [[ -d "$INSTALL_DIR" ]] && find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  die "$INSTALL_DIR 非空；请选择新的安装目录"
fi

CONTAINER_NAME="${NCG_INSTALL_CONTAINER_NAME:-nocyber-guard}"
PROXY_PORT="${NCG_INSTALL_PROXY_PORT:-18086}"
ADMIN_PORT="${NCG_INSTALL_ADMIN_PORT:-19090}"
validate_safe_name "$CONTAINER_NAME" || die "容器名称无效"
validate_port "$PROXY_PORT" || die "代理端口无效"
validate_port "$ADMIN_PORT" || die "管理端口无效"
[[ "$PROXY_PORT" != "$ADMIN_PORT" ]] || die "代理端口和管理端口不能相同"

port_is_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH | awk '{print $4}' | grep -Eq ":${port}$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn | awk 'NR>2 {print $4}' | grep -Eq ":${port}$"
  else
    return 1
  fi
}

port_is_listening "$PROXY_PORT" && die "端口 $PROXY_PORT 已被占用"
port_is_listening "$ADMIN_PORT" && die "端口 $ADMIN_PORT 已被占用"
docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME" && die "容器 $CONTAINER_NAME 已存在"

UPSTREAM_URL="${NCG_INSTALL_UPSTREAM_URL:-}"
NETWORK_NAME="${NCG_INSTALL_NETWORK_NAME:-}"
UPSTREAM_CONTAINER="${NCG_INSTALL_UPSTREAM_CONTAINER:-}"

if ((NON_INTERACTIVE)); then
  [[ -n "$UPSTREAM_URL" ]] || die "无交互模式必须设置 NCG_INSTALL_UPSTREAM_URL"
  NETWORK_NAME="${NETWORK_NAME:-nocyber-guard}"
else
  printf '上游连接方式：\n  1) 已运行的 Docker 容器（推荐）\n  2) 可从容器访问的 HTTP/HTTPS 地址\n'
  connection_choice=""
  prompt_value connection_choice "请选择" "1"
  case "$connection_choice" in
    1)
      prompt_value UPSTREAM_CONTAINER "上游容器名称，例如 sub2api" ""
      validate_safe_name "$UPSTREAM_CONTAINER" || die "上游容器名称无效"
      docker inspect "$UPSTREAM_CONTAINER" >/dev/null 2>&1 || die "找不到上游容器 $UPSTREAM_CONTAINER"
      attached_networks="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$UPSTREAM_CONTAINER")"
      if [[ -n "$attached_networks" ]]; then
        printf '上游当前网络：\n%s\n' "$attached_networks"
      fi
      default_network="$(printf '%s\n' "$attached_networks" | grep -Ev '^(bridge|host|none)$' | head -n 1 || true)"
      default_network="${default_network:-nocyber-guard}"
      prompt_value NETWORK_NAME "Guard 与上游共用的 Docker 网络" "$default_network"
      validate_safe_name "$NETWORK_NAME" || die "Docker 网络名称无效"
      [[ "$NETWORK_NAME" != "bridge" && "$NETWORK_NAME" != "host" && "$NETWORK_NAME" != "none" ]] || die "请选择用户自定义 bridge 网络"
      upstream_port=""
      prompt_value upstream_port "上游容器端口" "8080"
      validate_port "$upstream_port" || die "上游端口无效"
      upstream_alias="${NCG_INSTALL_UPSTREAM_ALIAS:-$UPSTREAM_CONTAINER}"
      validate_safe_name "$upstream_alias" || die "上游网络别名无效"
      UPSTREAM_URL="http://$upstream_alias:$upstream_port"
      ;;
    2)
      prompt_value UPSTREAM_URL "上游完整地址" "http://host.docker.internal:8080"
      NETWORK_NAME="${NETWORK_NAME:-nocyber-guard}"
      ;;
    *) die "连接方式无效" ;;
  esac
fi

validate_http_url "$UPSTREAM_URL" || die "上游地址必须是无凭据、无 fragment 的 HTTP/HTTPS URL"
validate_safe_name "$NETWORK_NAME" || die "Docker 网络名称无效"
[[ "$NETWORK_NAME" != "bridge" && "$NETWORK_NAME" != "host" && "$NETWORK_NAME" != "none" ]] || \
  die "请使用用户自定义 Docker bridge 网络"
if [[ "$UPSTREAM_URL" =~ ^https?://(127\.0\.0\.1|localhost)(:|/) ]]; then
  die "容器内的 localhost 不是宿主机；请改用 host.docker.internal"
fi

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  log "创建 Docker 网络 $NETWORK_NAME"
  docker network create "$NETWORK_NAME" >/dev/null
fi

if [[ -n "$UPSTREAM_CONTAINER" ]]; then
  if ! docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$UPSTREAM_CONTAINER" | grep -Fxq "$NETWORK_NAME"; then
    confirm "将 $UPSTREAM_CONTAINER 连接到网络 $NETWORK_NAME" 1 || die "Guard 必须与上游共享网络"
    docker network connect "$NETWORK_NAME" "$UPSTREAM_CONTAINER"
  fi
fi

NETWORK_GATEWAY="$(docker network inspect -f '{{range .IPAM.Config}}{{println .Gateway}}{{end}}' "$NETWORK_NAME" | head -n 1)"
TRUSTED_PROXY_CIDRS=""
if [[ "$NETWORK_GATEWAY" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  TRUSTED_PROXY_CIDRS="$NETWORK_GATEWAY/32"
fi

ADMIN_PASSWORD="${NCG_INSTALL_ADMIN_PASSWORD:-}"
GENERATED_PASSWORD=0
if [[ -z "$ADMIN_PASSWORD" ]]; then
  if ((NON_INTERACTIVE)); then
    die "无交互模式必须设置 NCG_INSTALL_ADMIN_PASSWORD"
  fi
  if confirm "是否自动生成管理员密码" 1; then
    ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '\r\n')"
    GENERATED_PASSWORD=1
  else
    prompt_secret_twice ADMIN_PASSWORD
  fi
fi
validate_secret "$ADMIN_PASSWORD" || die "管理员密码至少需要 12 位且不能包含换行"
MASTER_KEY="$(openssl rand -hex 32)"

if [[ -z "$WITH_UPDATER" ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    confirm "是否安装后台一键更新/回滚服务" 1 && WITH_UPDATER=1 || WITH_UPDATER=0
  else
    WITH_UPDATER=0
  fi
fi
[[ "$WITH_UPDATER" == "0" || "$WITH_UPDATER" == "1" ]] || die "NCG_INSTALL_WITH_UPDATER 必须为 0 或 1"
if [[ "$WITH_UPDATER" == "1" ]] && ! command -v systemctl >/dev/null 2>&1; then
  die "一键更新服务需要 systemd"
fi

if [[ -z "$DOMAIN" ]] && ((NON_INTERACTIVE == 0)); then
  prompt_value DOMAIN "业务域名（留空则只生成本机部署）" ""
fi
if [[ -n "$DOMAIN" ]]; then
  validate_domain "$DOMAIN" || die "域名格式无效"
  if [[ -z "$PROXY_MODE" ]]; then
    printf '反向代理方式：\n  1) 只生成配置文件（推荐）\n'
    command -v caddy >/dev/null 2>&1 && printf '  2) 安装到现有 Caddy（自动 HTTPS）\n'
    command -v nginx >/dev/null 2>&1 && printf '  3) 安装到现有 Nginx（HTTP，之后可运行 certbot）\n'
    proxy_choice=""
    prompt_value proxy_choice "请选择" "1"
    case "$proxy_choice" in
      1) PROXY_MODE="generate" ;;
      2) command -v caddy >/dev/null 2>&1 || die "Caddy 未安装"; PROXY_MODE="caddy" ;;
      3) command -v nginx >/dev/null 2>&1 || die "Nginx 未安装"; PROXY_MODE="nginx" ;;
      *) die "反向代理方式无效" ;;
    esac
  fi
else
  PROXY_MODE="${PROXY_MODE:-none}"
fi
validate_proxy_mode "$PROXY_MODE" || die "反向代理模式无效"
[[ "$PROXY_MODE" == "none" || -n "$DOMAIN" ]] || die "配置反向代理时必须提供域名"

log "下载正式版 Compose 文件并固定镜像摘要"
download "https://raw.githubusercontent.com/$NCG_REPOSITORY/$RELEASE_VERSION/docker-compose.yml" "$TEMP_DIR/docker-compose.yml"
grep -Fq 'NCG_UPSTREAM_URL' "$TEMP_DIR/docker-compose.yml" || die "下载的 Compose 文件校验失败"
IMAGE_TAG="$NCG_IMAGE_REPOSITORY:${RELEASE_VERSION#v}"
docker pull "$IMAGE_TAG" >/dev/null
PINNED_IMAGE="$(docker image inspect "$IMAGE_TAG" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep -E '^ghcr\.io/abingooo/nocyber-guard@sha256:[a-f0-9]{64}$' | head -n 1)"
[[ "$PINNED_IMAGE" =~ ^ghcr\.io/abingooo/nocyber-guard@sha256:[a-f0-9]{64}$ ]] || die "无法解析官方镜像摘要"

DATA_DIR="$INSTALL_DIR/data"
SECRET_DIR="$INSTALL_DIR/secrets"
OVERRIDE_FILE="$INSTALL_DIR/docker-compose.installer.yml"
ENV_FILE="$INSTALL_DIR/.env"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/reverse-proxy" "$INSTALL_DIR/backups"
install -d -m 0700 -o 65532 -g 65532 "$DATA_DIR"
install -d -m 0711 -o root -g root "$SECRET_DIR"
printf '%s' "$MASTER_KEY" >"$SECRET_DIR/master_key"
printf '%s' "$ADMIN_PASSWORD" >"$SECRET_DIR/admin_password"
chown 65532:65532 "$SECRET_DIR/master_key" "$SECRET_DIR/admin_password"
chmod 0400 "$SECRET_DIR/master_key" "$SECRET_DIR/admin_password"
install -m 0644 "$TEMP_DIR/docker-compose.yml" "$INSTALL_DIR/docker-compose.yml"
write_env_file "$ENV_FILE" "$PINNED_IMAGE" "$CONTAINER_NAME" "$UPSTREAM_URL" "$NETWORK_NAME" \
  "$PROXY_PORT" "$ADMIN_PORT" "$DATA_DIR" "$SECRET_DIR" "$TRUSTED_PROXY_CIDRS"
write_compose_override "$OVERRIDE_FILE" "$WITH_UPDATER"

install_updater() {
  local machine asset checksum_file existing_dir
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) asset="nocyber-updater-linux-amd64" ;;
    aarch64|arm64) asset="nocyber-updater-linux-arm64" ;;
    *) die "更新器暂不支持架构：$machine" ;;
  esac
  if [[ -f /etc/nocyber-updater.env ]]; then
    existing_dir="$(read_env_value /etc/nocyber-updater.env NCG_UPDATER_COMPOSE_DIR || true)"
    [[ -z "$existing_dir" || "$existing_dir" == "$INSTALL_DIR" ]] || \
      die "主机已有另一个 NoCyber 更新器实例：$existing_dir"
  fi
  download "https://github.com/$NCG_REPOSITORY/releases/download/$RELEASE_VERSION/$asset" "$TEMP_DIR/$asset"
  download "https://github.com/$NCG_REPOSITORY/releases/download/$RELEASE_VERSION/SHA256SUMS" "$TEMP_DIR/SHA256SUMS"
  checksum_file="$TEMP_DIR/$asset.sha256"
  grep -E "^[a-f0-9]{64}  $asset$" "$TEMP_DIR/SHA256SUMS" >"$checksum_file" || die "Release 缺少更新器校验和"
  (cd "$TEMP_DIR" && sha256sum -c "$(basename "$checksum_file")") >/dev/null || die "更新器校验失败"
  install -m 0755 "$TEMP_DIR/$asset" /usr/local/bin/nocyber-updater
  cat >/etc/nocyber-updater.env <<EOF
NCG_UPDATER_SOCKET=/run/nocyber-updater/updater.sock
NCG_UPDATER_SOCKET_GID=65532
NCG_UPDATER_COMPOSE_DIR=$INSTALL_DIR
NCG_UPDATER_COMPOSE_FILE=$INSTALL_DIR/docker-compose.yml
NCG_UPDATER_COMPOSE_OVERRIDE=$OVERRIDE_FILE
NCG_UPDATER_ENV_FILE=$ENV_FILE
NCG_UPDATER_SERVICE=guard
NCG_UPDATER_HEALTH_URL=http://127.0.0.1:$PROXY_PORT/_nocyber/readyz
NCG_UPDATER_STATE_FILE=/var/lib/nocyber-updater/state.json
COMPOSE_PROJECT_NAME=nocyber-guard
EOF
  chmod 0600 /etc/nocyber-updater.env
  cat >/etc/systemd/system/nocyber-updater.service <<EOF
[Unit]
Description=NoCyber Guard restricted update agent
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/nocyber-updater.env
ExecStart=/usr/local/bin/nocyber-updater
Restart=on-failure
RestartSec=3s
RuntimeDirectory=nocyber-updater
RuntimeDirectoryMode=0755
StateDirectory=nocyber-updater
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$INSTALL_DIR /run/nocyber-updater /var/lib/nocyber-updater

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now nocyber-updater
  for _ in $(seq 1 20); do
    [[ -S /run/nocyber-updater/updater.sock ]] && return 0
    sleep 0.5
  done
  systemctl status nocyber-updater --no-pager >&2 || true
  die "更新器未能创建受限 Unix socket"
}

if [[ "$WITH_UPDATER" == "1" ]]; then
  log "安装受限的一键更新/回滚服务"
  install_updater
fi

COMPOSE=(docker compose -f "$INSTALL_DIR/docker-compose.yml" -f "$OVERRIDE_FILE" --env-file "$ENV_FILE")
log "验证并启动 NoCyber Guard"
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" pull
"${COMPOSE[@]}" up -d

READY_URL="http://127.0.0.1:$PROXY_PORT/_nocyber/readyz"
ADMIN_READY_URL="http://127.0.0.1:$ADMIN_PORT/_nocyber/readyz"
ready=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 3 "$READY_URL" >/dev/null 2>&1 && \
     curl -fsS --max-time 3 "$ADMIN_READY_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if ((ready == 0)); then
  "${COMPOSE[@]}" ps >&2 || true
  "${COMPOSE[@]}" logs --tail 80 guard >&2 || true
  die "容器未在 60 秒内就绪；配置和数据已保留在 $INSTALL_DIR"
fi

if ! curl -sS --max-time 15 -o /dev/null "http://127.0.0.1:$PROXY_PORT/"; then
  warn "Guard 已就绪，但当前无法通过 Guard 连接上游：$UPSTREAM_URL"
fi

if [[ -n "$DOMAIN" ]]; then
  write_proxy_examples "$INSTALL_DIR/reverse-proxy" "$DOMAIN" "$PROXY_PORT"
fi

apply_caddy() {
  local caddyfile="/etc/caddy/Caddyfile" config_dir="/etc/caddy/conf.d"
  local target backup
  target="$config_dir/nocyber-guard-$DOMAIN.caddy"
  backup="$INSTALL_DIR/backups/Caddyfile.$(date +%Y%m%d%H%M%S)"
  if [[ ! -f "$caddyfile" ]]; then
    warn "找不到 $caddyfile"
    return 1
  fi
  if [[ -e "$target" ]]; then
    warn "$target 已存在；安装器不会覆盖它"
    return 1
  fi
  if grep -R -Fq --exclude="$(basename "$target")" "$DOMAIN" /etc/caddy 2>/dev/null; then
    warn "Caddy 中已经存在域名 $DOMAIN；已生成配置，但不会覆盖现有站点"
    return 1
  fi
  mkdir -p "$config_dir"
  cp -a "$caddyfile" "$backup"
  install -m 0644 "$INSTALL_DIR/reverse-proxy/nocyber-guard.caddy" "$target"
  if ! grep -Fq 'import /etc/caddy/conf.d/*.caddy' "$caddyfile"; then
    printf '\n# NoCyber Guard managed site imports\nimport /etc/caddy/conf.d/*.caddy\n' >>"$caddyfile"
  fi
  if ! caddy validate --config "$caddyfile"; then
    cp -a "$backup" "$caddyfile"
    rm -f -- "$target"
    warn "Caddy 配置验证失败，已恢复原配置"
    return 1
  fi
  if ! systemctl reload caddy; then
    cp -a "$backup" "$caddyfile"
    rm -f -- "$target"
    systemctl reload caddy >/dev/null 2>&1 || true
    warn "Caddy 重载失败，已恢复原配置"
    return 1
  fi
}

apply_nginx() {
  local target="/etc/nginx/conf.d/nocyber-guard-$DOMAIN.conf"
  local map_target="/etc/nginx/conf.d/00-nocyber-guard-map.conf"
  local installed_map=0
  if [[ -e "$target" ]]; then
    warn "$target 已存在；安装器不会覆盖它"
    return 1
  fi
  if grep -R -Fq --exclude="$(basename "$target")" "$DOMAIN" /etc/nginx 2>/dev/null; then
    warn "Nginx 中已经存在域名 $DOMAIN；已生成配置，但不会覆盖现有站点"
    return 1
  fi
  install -m 0644 "$INSTALL_DIR/reverse-proxy/nocyber-guard-nginx.conf" "$target"
  # Match literal Nginx variables.
  # shellcheck disable=SC2016
  if ! grep -R -Fq --exclude="$(basename "$map_target")" 'map $http_upgrade $nocyber_connection_upgrade' /etc/nginx 2>/dev/null; then
    install -m 0644 "$INSTALL_DIR/reverse-proxy/nocyber-guard-nginx-map.conf" "$map_target"
    installed_map=1
  fi
  if ! nginx -t; then
    rm -f -- "$target"
    ((installed_map == 0)) || rm -f -- "$map_target"
    nginx -t >/dev/null 2>&1 || true
    warn "Nginx 配置验证失败，已撤销新增站点"
    return 1
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl reload nginx; then
      rm -f -- "$target"
      ((installed_map == 0)) || rm -f -- "$map_target"
      systemctl reload nginx >/dev/null 2>&1 || true
      warn "Nginx 重载失败，已撤销新增站点"
      return 1
    fi
  else
    if ! nginx -s reload; then
      rm -f -- "$target"
      ((installed_map == 0)) || rm -f -- "$map_target"
      nginx -s reload >/dev/null 2>&1 || true
      warn "Nginx 重载失败，已撤销新增站点"
      return 1
    fi
  fi
}

case "$PROXY_MODE" in
  caddy)
    log "安装并验证 Caddy 站点"
    apply_caddy || warn "Guard 已正常运行，请使用生成的 Caddy 配置手工接入"
    ;;
  nginx)
    log "安装并验证 Nginx 站点"
    apply_nginx || warn "Guard 已正常运行，请使用生成的 Nginx 配置手工接入"
    ;;
  generate) log "反向代理配置已生成，未修改系统代理" ;;
  none) ;;
esac

cat >"$INSTALL_DIR/.nocyber-managed" <<EOF
installer_schema=$NCG_INSTALLER_SCHEMA
installed_version=$RELEASE_VERSION
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod 0600 "$INSTALL_DIR/.nocyber-managed"

printf '\n%sNoCyber Guard 已安装成功%s\n' "$COLOR_GREEN" "$COLOR_RESET"
printf '  版本：       %s\n' "$RELEASE_VERSION"
printf '  上游：       %s\n' "$UPSTREAM_URL"
printf '  代理入口：   http://127.0.0.1:%s\n' "$PROXY_PORT"
printf '  管理后台：   http://127.0.0.1:%s\n' "$ADMIN_PORT"
printf '  管理员账号： admin\n'
if ((GENERATED_PASSWORD)); then
  printf '  管理员密码： %s\n' "$ADMIN_PASSWORD"
  warn "请立即保存上面的管理员密码；安装器不会再次显示它"
else
  printf '  管理员密码： 使用你刚才设置的密码\n'
fi
printf '  安装目录：   %s\n' "$INSTALL_DIR"
printf '  数据目录：   %s\n' "$DATA_DIR"
if [[ -n "$DOMAIN" ]]; then
  printf '  业务域名：   %s\n' "$DOMAIN"
  printf '  代理配置：   %s/reverse-proxy\n' "$INSTALL_DIR"
fi
if [[ "$PROXY_MODE" == "nginx" ]]; then
  warn "Nginx 当前生成的是 HTTP 站点；请使用 certbot 或现有证书流程启用 HTTPS"
fi
printf '\n远程打开后台：\n  ssh -L %s:127.0.0.1:%s root@服务器地址\n' "$ADMIN_PORT" "$ADMIN_PORT"
printf '然后在本机访问：http://127.0.0.1:%s\n' "$ADMIN_PORT"
