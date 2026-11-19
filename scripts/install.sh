#!/usr/bin/env bash
# Install VPSHub on a Linux server. Generates secrets once. Does not change the firewall.
set -euo pipefail
umask 077

pick_port() {
  local port try
  for try in 1 2 3 4 5 6 7 8 9 10; do
    port=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 30000))
    if command -v ss >/dev/null 2>&1 && ss -lnt | awk '{print $4}' | grep -q ":${port}$"; then
      continue
    fi
    echo "$port"
    return 0
  done
  echo "no free port" >&2
  return 1
}

PUBLIC=0
for arg in "$@"; do
  case "$arg" in
    --public) PUBLIC=1 ;;
    -h|--help)
      echo "usage: sudo bash scripts/install.sh [--public]"
      echo "  default   listen on 127.0.0.1; reach it with an SSH tunnel or Tailscale"
      echo "  --public  listen on 0.0.0.0 with a self-signed certificate"
      echo "The installer does not open ports or change nftables."
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo bash scripts/install.sh" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG=/etc/vpshub/config.yaml
BIN=/usr/local/bin/vpshub
DATA=/var/lib/vpshub
CERT_DIR="$DATA/certs"
UNIT_SRC="$ROOT/deploy/vpshub.service"
UNIT_DST=/etc/systemd/system/vpshub.service

if ! id vpshub >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA" --create-home --shell /usr/sbin/nologin --user-group vpshub
fi
install -d -o vpshub -g vpshub -m 0700 "$DATA"
install -d -o root -g vpshub -m 0750 /etc/vpshub
install -d -m 0755 /usr/lib/vpshub/migrations /usr/lib/vpshub/fingerprints

if [[ ! -x "$BIN" ]]; then
  if [[ -x "$ROOT/bin/vpshub" ]]; then
    install -m 0755 "$ROOT/bin/vpshub" "$BIN"
  elif [[ -x "$ROOT/vpshub" ]]; then
    install -m 0755 "$ROOT/vpshub" "$BIN"
  elif command -v go >/dev/null 2>&1 && [[ -f "$ROOT/go.mod" ]]; then
    (cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN" ./cmd/vpshub)
    chmod 0755 "$BIN"
  else
    echo "No vpshub binary and no Go toolchain." >&2
    echo "Build on a machine with Go: CGO_ENABLED=0 go build -o vpshub ./cmd/vpshub" >&2
    echo "Copy that file to $BIN and run this script again. This installer does not download a payload." >&2
    exit 1
  fi
fi

if [[ -d "$ROOT/migrations" ]]; then
  cp -a "$ROOT/migrations/." /usr/lib/vpshub/migrations/
fi
if [[ -f "$ROOT/fingerprints/default.yaml" ]]; then
  install -m 0644 "$ROOT/fingerprints/default.yaml" /usr/lib/vpshub/fingerprints/default.yaml
fi
if [[ ! -f /usr/lib/vpshub/migrations/001_init.sql ]]; then
  echo "Migrations are missing. Run this script from the VPSHub repository, or copy migrations to /usr/lib/vpshub/migrations." >&2
  exit 1
fi

if [[ -f "$UNIT_SRC" ]]; then
  install -m 0644 "$UNIT_SRC" "$UNIT_DST"
else
  echo "missing $UNIT_SRC" >&2
  exit 1
fi

tls_cert=""
tls_key=""
if [[ "$PUBLIC" -eq 1 ]]; then
  install -d -o vpshub -g vpshub -m 0700 "$CERT_DIR"
  tls_cert="$CERT_DIR/cert.pem"
  tls_key="$CERT_DIR/key.pem"
  if [[ ! -f "$tls_cert" || ! -f "$tls_key" ]]; then
    openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
      -keyout "$tls_key" -out "$tls_cert" -subj "/CN=vpshub.local" >/dev/null 2>&1
    chown vpshub:vpshub "$tls_cert" "$tls_key"
    chmod 0640 "$tls_cert"
    chmod 0600 "$tls_key"
  fi
fi

if [[ ! -f "$CFG" ]]; then
  port="$(pick_port)"
  token="$(openssl rand -hex 8)"
  if [[ "$PUBLIC" -eq 1 ]]; then
    listen="0.0.0.0:${port}"
    secure="true"
  else
    listen="127.0.0.1:${port}"
    secure="false"
  fi
  cat >"$CFG" <<EOF
listen: "${listen}"
data_dir: "${DATA}"
session_ttl: 8h
vault_lock_ttl: 30m
secure_cookie: ${secure}
login_max_fails: 5
login_lock_minutes: 15
ssh_dial_timeout: 15s
ssh_cmd_timeout: 5m
ssh_max_output: 2097152
ssh_max_per_host: 2
task_max_concurrency: 5
task_prod_concurrency: 1
webssh_enabled: false
sftp_enabled: false
base_path: "/h/${token}"
trusted_proxies: []
probe_interval: 5m
basic_auth_user: ""
basic_auth_hash: ""
tls_cert: "${tls_cert}"
tls_key: "${tls_key}"
EOF
fi
chown root:vpshub "$CFG"
chmod 0640 "$CFG"

boot_out="$("$BIN" bootstrap -config "$CFG")"
chown root:vpshub "$CFG"
chmod 0640 "$CFG"

created=0
listen=""
base_path=""
scheme="http"
basic_user=""
basic_password=""
panel_user=""
panel_password=""
totp_url=""
while IFS= read -r line; do
  key="${line%%=*}"
  val="${line#*=}"
  case "$key" in
    created) created="$val" ;;
    listen) listen="$val" ;;
    base_path) base_path="$val" ;;
    scheme) scheme="$val" ;;
    basic_user) basic_user="$val" ;;
    basic_password) basic_password="$val" ;;
    panel_user) panel_user="$val" ;;
    panel_password) panel_password="$val" ;;
    totp_url) totp_url="$val" ;;
  esac
done <<<"$boot_out"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable vpshub >/dev/null 2>&1 || true
  systemctl restart vpshub >/dev/null 2>&1 || true
  run_state="$(systemctl is-active vpshub 2>/dev/null || true)"
else
  run_state="unknown"
fi
if [[ "$run_state" == "active" ]]; then
  run_label="运行中"
else
  run_label="未运行"
fi

if [[ "$created" != "1" ]]; then
  echo "VPSHub 已经安装。这次没有重新生成密码。"
  "$BIN" status -config "$CFG" || true
  exit 0
fi

port="${listen##*:}"
if [[ "$scheme" == "https" ]]; then
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ -z "${host_ip}" ]]; then
    host_ip="服务器地址"
  fi
  panel_url="${scheme}://${host_ip}:${port}${base_path}/"
else
  panel_url="${scheme}://127.0.0.1:${port}${base_path}/"
fi

if [[ -n "$basic_password" ]]; then
  layer1_block=$(cat <<EOF
第 1 层 — 浏览器访问校验
用户名: ${basic_user}
密码: ${basic_password}
EOF
)
else
  layer1_block="第 1 层 — 浏览器访问校验
用户名已写入配置。密码不会再次显示。"
fi

if [[ "$scheme" == "https" ]]; then
  access_note=$(cat <<EOF
当前证书是安装时在本机生成的自签证书，浏览器会提示连接不受信任。
确认地址无误后，可以临时继续访问。
之后建议在前面加 Caddy，或只通过 Tailscale 访问，不要长期把自签证书暴露在公网上。
安装程序没有修改防火墙，也没有自动放行端口。请在云安全组里只对需要的来源地址放行 ${port}/tcp。
EOF
)
else
  access_note=$(cat <<EOF
面板只监听 127.0.0.1。请用 SSH 隧道或 Tailscale 访问，不要把这个端口直接暴露到公网。
SSH 隧道示例（在你自己的电脑上执行，把用户和主机换成这台机器的登录账号）:
  ssh -L ${port}:127.0.0.1:${port} <user>@<this-host>
然后在浏览器打开上面的面板地址。
安装程序没有修改防火墙。
EOF
)
fi

summary=$(cat <<EOF
VPSHub 安装完成

面板地址: ${panel_url}
运行状态: ${run_label}
监听端口: ${port}

${layer1_block}

第 2 层 — 面板登录
用户名: ${panel_user}
初始密码: ${panel_password}
TOTP: ${totp_url}

登录步骤:
1. 用浏览器打开面板地址。如果弹出访问校验，输入第 1 层的用户名和密码。
2. 在面板登录页输入第 2 层用户名、初始密码，以及验证器里的动态码。
3. 按页面提示更换初始密码。
4. 设置保险库主密码，并把恢复密钥抄到离线的地方。安装时保险库是空的，需要你自己初始化。

${access_note}

打不开时请检查:
1. 云安全组或安全组规则是否放行 TCP ${port}（只有 --public 才需要对来源地址放行）
2. 本机防火墙: nft list ruleset
3. 服务日志: journalctl -u vpshub -n 80 --no-pager

安装路径:
程序: ${BIN}
配置: ${CFG}
数据: ${DATA}
证书: ${CERT_DIR}
迁移: /usr/lib/vpshub/migrations
服务: ${UNIT_DST}

命令:
vpshub status     查看监听端口、入口路径和服务是否在运行
vpshub password   重置面板密码，新密码只打印一次
vpshub restart    root 会重启服务；其他用户只会看到需要执行的命令

请立刻把以上内容抄到离线介质。同一份内容已写入 /root/vpshub-install.txt（权限 0600）。
保存之后删除该文件。不要把这段输出重定向到共享日志。
EOF
)

printf '%s\n' "$summary"
printf '%s\n' "$summary" > /root/vpshub-install.txt
chmod 0600 /root/vpshub-install.txt
