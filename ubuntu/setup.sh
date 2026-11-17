#!/usr/bin/env bash
# =============================================================================
#  ubuntu-hardening — первичная настройка безопасности Ubuntu-сервера
#  Ubuntu 22.04 / 24.04 / 26.04 LTS, systemd. Не для LXC.
#
#  curl -fsSL https://raw.githubusercontent.com/yyxa/vps/main/ubuntu/setup.sh | sudo bash
#
#  Админ всегда: drama
#  Дефолты: ssh 2222 (только ключи), ufw deny in/routed, fail2ban, endlessh на 22,
#           unattended-upgrades + reboot 04:30, auditd, apparmor, форвардинг off,
#           docker daemon.json (ротация логов + no-new-privileges).
#  Флаги: --key/--key-file --gh-keys --ssh-port --http --no-auto-reboot --no-tarpit
#         --lynis --yes --dry-run --rollback [DIR] --help
# =============================================================================
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a LC_ALL=C

ADMIN_USER="drama"
ADMIN_SSH_KEY="${ADMIN_SSH_KEY:-}"; GH_KEYS="${GH_KEYS:-}"
SSH_PORT="${SSH_PORT:-2222}"
ALLOW_HTTP="${ALLOW_HTTP:-0}"; AUTO_REBOOT="${AUTO_REBOOT:-1}"; TARPIT="${TARPIT:-1}"
RUN_LYNIS="${RUN_LYNIS:-0}"; ASSUME_YES="${ASSUME_YES:-0}"
DRY_RUN=0; ROLLBACK=0; ROLLBACK_DIR=""

usage(){ cat <<'EOF'
ubuntu-hardening (main) — базовая безопасность сервера

Админ всегда: drama
Docker daemon.json кладётся всегда (ротация логов + no-new-privileges).

  --key "ssh-ed25519 ..."      публичный ключ строкой
  --key-file F                 или файлом .pub
  --gh-keys NICK               взять ключи с github.com/NICK.keys
  --ssh-port N                 порт SSH (22 -> тарпит отключится сам)
  --http                       открыть 80/443 в мир
  --no-auto-reboot             не ребутить ночью
  --no-tarpit                  без endlessh
  --lynis                      аудит в конце
  --yes / --dry-run            без подтверждения / только план
  --rollback [DIR]             откатить конфиги из бэкапа
  --help
EOF
}
G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'
log(){ printf '%s[+]%s %s\n' "$G" "$N" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$Y" "$N" "$*"; }
die(){ trap - ERR; printf '%s[x]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
on_err(){ local rc=$1 line=$2 cmd=$3
  (( BASH_SUBSHELL > 0 )) && return 0
  die "строка $line: «$cmd» вернула $rc (см. $LOG)"
}
have(){ command -v "$1" >/dev/null 2>&1; }
pkg(){ apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"; }
unit_exists(){ systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q "^$1"; }
bak(){ local p="$1"; [[ -e "$p" ]] || return 0; mkdir -p "$BACKUP_DIR$(dirname "$p")"; cp -a "$p" "$BACKUP_DIR$p"; }
put(){ local p="$1" m="${2:-0644}"; mkdir -p "$(dirname "$p")"
  if [[ -e "$p" ]]; then bak "$p"; else printf '%s\n' "$p" >>"$BACKUP_DIR/created.txt"; fi
  cat >"$p"; chmod "$m" "$p"; log "→ $p"; }
kill_unit(){ local u; for u in "$@"; do if unit_exists "$u"; then
  printf '%s\n' "$u" >>"$BACKUP_DIR/masked.txt"
  systemctl disable --now "$u" >/dev/null 2>&1 || true; systemctl mask "$u" >/dev/null 2>&1 || true
  log "выключен $u"; fi; done; }
setkv(){ local f="$1" k="$2" v="$3"; bak "$f"
  if grep -qE "^[#[:space:]]*$k\b" "$f"; then sed -i -E "s|^[#[:space:]]*$k\b.*|$k $v|" "$f"
  else printf '%s %s\n' "$k" "$v" >>"$f"; fi; }

parse_args(){
  while [[ $# -gt 0 ]]; do case "$1" in
    --key|--key-file) ADMIN_SSH_KEY="$2"; shift 2;;
    --gh-keys) GH_KEYS="$2"; shift 2;;
    --ssh-port) SSH_PORT="$2"; shift 2;;
    --http) ALLOW_HTTP=1; shift;;
    --auto-reboot) AUTO_REBOOT=1; shift;; --no-auto-reboot) AUTO_REBOOT=0; shift;;
    --tarpit) TARPIT=1; shift;; --no-tarpit) TARPIT=0; shift;;
    --lynis) RUN_LYNIS=1; shift;;
    -y|--yes) ASSUME_YES=1; shift;; --dry-run) DRY_RUN=1; shift;;
    --rollback) ROLLBACK=1; shift
      if [[ -n "${1:-}" && "${1:0:2}" != -- ]]; then ROLLBACK_DIR="$1"; shift; fi;;
    -h|--help) usage; exit 0;;
    *) die "неизвестный флаг: $1 (--help)";;
  esac; done
  return 0
}

detect(){
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) \
    || die "--ssh-port должен быть числом 1..65535"
  if id "$ADMIN_USER" &>/dev/null; then AHOME="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
  else AHOME="/home/$ADMIN_USER"; fi
  AK="$AHOME/.ssh/authorized_keys"
  # privsep-каталог: без него sshd -t/-T падают, даже если конфиг валиден
  mkdir -p /run/sshd; chmod 0755 /run/sshd
  # определение порта не фатально: sshd может быть не запущен или не установлен
  OLD_PORT="$(sshd -T 2>>"$LOG" | awk '/^port /{print $2; exit}' || true)"
  if [[ ! "$OLD_PORT" =~ ^[0-9]+$ ]]; then
    OLD_PORT="$(awk 'tolower($1)=="port"{print $2; exit}' \
      /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>>"$LOG" || true)"
  fi
  [[ "$OLD_PORT" =~ ^[0-9]+$ ]] || OLD_PORT=22
  SOCK_MODE=0; systemctl is-active --quiet ssh.socket && SOCK_MODE=1
  ALLOW_USERS="$ADMIN_USER"
  return 0
}
collect_keys(){
  local raw v tmp line shome sak
  raw="$(mktemp)"; v="$(mktemp)"; tmp="$(mktemp)"; : >"$raw"
  if [[ -n "$GH_KEYS" ]]; then
    log "ключи с github.com/$GH_KEYS.keys"
    curl -fsSL --max-time 15 "https://github.com/${GH_KEYS}.keys" >>"$raw" \
      || die "не получил ключи GitHub (ник/сеть?)"
  fi
  if [[ -n "$ADMIN_SSH_KEY" ]]; then
    if [[ -f "$ADMIN_SSH_KEY" ]]; then cat "$ADMIN_SSH_KEY" >>"$raw"
    else printf '%s\n' "$ADMIN_SSH_KEY" >>"$raw"; fi
  fi
  [[ -s "$AK" ]] && cat "$AK" >>"$raw"
  [[ -s /root/.ssh/authorized_keys ]] && cat /root/.ssh/authorized_keys >>"$raw"
  # если запустили из-под другого пользователя — забрать его ключ для drama,
  # но SSH-доступ всё равно будет только у drama
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "$ADMIN_USER" && "$SUDO_USER" != root ]]; then
    shome="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    sak="$shome/.ssh/authorized_keys"
    [[ -s "$sak" ]] && cat "$sak" >>"$raw"
  fi
  while IFS= read -r line; do
    [[ "$line" =~ ^(ssh-|ecdsa-|sk-) ]] || continue
    printf '%s\n' "$line" >"$v"
    if ssh-keygen -l -f "$v" >/dev/null 2>&1; then
      grep -qxF "$line" "$tmp" || printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$raw"
  KEYS_DATA="$(cat "$tmp")"; KEY_COUNT="$(grep -c . "$tmp" || true)"
  rm -f "$raw" "$v" "$tmp"
  [[ -n "$KEYS_DATA" ]] || die "нет валидных ключей. Добавь --key 'ssh-ed25519 ...' или --gh-keys yyxa. Парольный вход отключать нельзя."
  log "ключей найдено: $KEY_COUNT"
}
ensure_admin(){
  id "$ADMIN_USER" &>/dev/null || { adduser --disabled-password --gecos "" "$ADMIN_USER"; log "создан $ADMIN_USER"; }
  usermod -aG sudo "$ADMIN_USER"

  # .ssh обязан быть обычным каталогом. Если там файл/симлинк/дичь — бэкапим и пересоздаём.
  if [[ -L "$AHOME/.ssh" || ( -e "$AHOME/.ssh" && ! -d "$AHOME/.ssh" ) ]]; then
    bak "$AHOME/.ssh"
    rm -rf "$AHOME/.ssh"
  fi
  mkdir -p "$AHOME/.ssh"

  # authorized_keys обязан быть обычным файлом.
  if [[ -L "$AK" || ( -e "$AK" && ! -f "$AK" ) ]]; then
    bak "$AK"
    rm -rf "$AK"
  fi

  printf '%s\n' "$KEYS_DATA" >"$AK"
  chown -R "$ADMIN_USER:$(id -gn "$ADMIN_USER")" "$AHOME/.ssh"
  chmod 700 "$AHOME/.ssh"
  chmod 600 "$AK"

  [[ -s "$AK" ]] || die "ключи не записались в $AK"
  log "ключи записаны в $AK: $(wc -l <"$AK") шт."

  if [[ "$(passwd -S "$ADMIN_USER" | awk '{print $2}')" != P ]]; then
    local pass; pass="$(head -c 24 /dev/urandom | base64)"
    printf '%s:%s\n' "$ADMIN_USER" "$pass" | chpasswd
    put "/root/.admin-password-$TS" 0600 <<<"$pass"
    warn "пароль sudo → /root/.admin-password-$TS (перенести в gopass, файл удалить)"
  fi
}
write_rollback_helper(){
  put /usr/local/sbin/hardening-rollback 0700 <<'EOF'
#!/bin/bash
set -euo pipefail
D="${1:-$(ls -1dt /root/hardening-backup-* 2>/dev/null | head -1)}"
[[ -d "$D" ]] || { echo "бэкап не найден"; exit 1; }
systemctl stop ssh-rollback.timer 2>/dev/null || true
if [[ -f "$D/created.txt" ]]; then
  while read -r f; do
    [[ -n "$f" ]] || continue
    case "$f" in
      /usr/local/sbin/hardening-rollback|/root/.admin-password-*) continue;;
    esac
    rm -f "$f"
  done <"$D/created.txt"
fi
if [[ -f "$D/masked.txt" ]]; then
  while read -r u; do systemctl unmask "$u" 2>/dev/null || true; done <"$D/masked.txt"
fi
( cd "$D" && find . -type f ! -name created.txt ! -name masked.txt -print0 \
  | while IFS= read -r -d '' f; do install -D -m "$(stat -c %a "$f")" "$f" "/${f#./}"; done )
mkdir -p /run/sshd
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
sysctl --system >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true
echo "откачено из $D (пакеты и пароли не откатываются)"
EOF
}

s_updates(){
  log "1/11 apt upgrade + пакеты"
  apt-get update -y
  apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade
  grep -rqs universe /etc/apt/sources.list /etc/apt/sources.list.d/ || {
    pkg software-properties-common; add-apt-repository -y universe; apt-get update -y; }
  pkg openssh-server ufw fail2ban python3-systemd unattended-upgrades needrestart \
      libpam-pwquality auditd apparmor apparmor-utils apparmor-profiles \
      etckeeper ca-certificates curl git jq htop ncdu unzip
  apt-get -y autoremove --purge
}
s_autoupdate(){
  log "2/11 unattended-upgrades"
  put /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  put /etc/apt/apt.conf.d/52unattended-upgrades-local <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
    "\${distro_id}:\${distro_codename}-updates";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$([[ $AUTO_REBOOT == 1 ]] && echo true || echo false)";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
Unattended-Upgrade::SyslogEnable "true";
EOF
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  if [[ -d /etc/needrestart/conf.d ]]; then
    put /etc/needrestart/conf.d/99-hardening.conf <<'EOF'
$nrconf{restart} = 'a';
EOF
  fi
}
s_ssh(){
  log "3/11 sshd"
  mkdir -p /run/sshd; chmod 0755 /run/sshd
  # 00-, не 99-: sshd берёт ПЕРВОЕ значение, cloud-init кладёт yes в 50-/60-*.conf
  put /etc/ssh/sshd_config.d/00-hardening.conf 0600 <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
GSSAPIAuthentication no
IgnoreRhosts yes
StrictModes yes
PubkeyAuthentication yes
AuthenticationMethods publickey
UsePAM yes
AllowUsers $ALLOW_USERS
MaxAuthTries 3
MaxStartups 10:30:60
LoginGraceTime 20
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
TCPKeepAlive no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
EOF
  grep -qE '^Include /etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config || {
    bak /etc/ssh/sshd_config; sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config; }
  if [[ -d /etc/cloud/cloud.cfg.d ]]; then
    put /etc/cloud/cloud.cfg.d/99-no-ssh-pwauth.cfg <<'EOF'
ssh_pwauth: false
EOF
  fi
  if [[ -f /etc/ssh/moduli ]]; then
    awk '$5 >= 3071' /etc/ssh/moduli >/tmp/moduli.new
    if [[ -s /tmp/moduli.new ]]; then bak /etc/ssh/moduli; cat /tmp/moduli.new >/etc/ssh/moduli; fi
    rm -f /tmp/moduli.new
  fi
  put /usr/local/sbin/ssh-rollback 0700 <<EOF
#!/bin/bash
exec >>/var/log/ssh-rollback.log 2>&1
set -x
rm -f /etc/ssh/sshd_config.d/00-hardening.conf /etc/systemd/system/ssh.socket.d/override.conf
[[ -d "$BACKUP_DIR/etc/ssh/sshd_config.d" ]] && cp -a "$BACKUP_DIR/etc/ssh/sshd_config.d/." /etc/ssh/sshd_config.d/
mkdir -p /run/sshd
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
ufw allow $OLD_PORT/tcp || true
command -v fail2ban-client >/dev/null && fail2ban-client unban --all || true
EOF
  systemctl stop ssh-rollback.timer >/dev/null 2>&1 || true
  systemctl reset-failed ssh-rollback.timer ssh-rollback.service >/dev/null 2>&1 || true
  if ! sshd -t 2>>"$LOG"; then
    rm -f /etc/ssh/sshd_config.d/00-hardening.conf
    die "sshd -t не прошёл, конфиг откачен (подробности в $LOG)"
  fi
  systemd-run --unit=ssh-rollback --on-active=15min /usr/local/sbin/ssh-rollback >/dev/null
  if [[ "$SOCK_MODE" == 1 && "$SSH_PORT" != "$OLD_PORT" ]]; then
    put /etc/systemd/system/ssh.socket.d/override.conf <<EOF
[Socket]
ListenStream=
ListenStream=$SSH_PORT
EOF
    systemctl daemon-reload; systemctl restart ssh.socket
  else
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null \
      || systemctl start ssh 2>/dev/null \
      || warn "sshd не перезапущен — проверь: systemctl status ssh"
  fi
}
s_ufw(){
  log "4/11 ufw"
  local f
  for f in /etc/ufw/user.rules /etc/ufw/user6.rules; do bak "$f"; done

  # /etc/default/ufw sourced ufw-init'ом. Формат строго IPV6=yes.
  if [[ ! -f /etc/default/ufw ]]; then
    put /etc/default/ufw <<'EOF'
IPV6=yes
EOF
  else
    bak /etc/default/ufw
    sed -i -E 's/^IPV6[[:space:]]*=.*/IPV6=yes/; s/^IPV6[[:space:]].*/IPV6=yes/' /etc/default/ufw
    grep -q '^IPV6=' /etc/default/ufw || printf 'IPV6=yes\n' >>/etc/default/ufw
  fi

  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw default deny routed >/dev/null
  ufw limit "$SSH_PORT/tcp" comment 'ssh' >/dev/null
  if [[ "$SSH_PORT" != "$OLD_PORT" ]]; then
    ufw allow "$OLD_PORT/tcp" comment 'ssh old, удалить после проверки' >/dev/null
  fi
  if [[ "$ALLOW_HTTP" == 1 ]]; then
    ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw allow 443/udp >/dev/null
  fi
  ufw --force enable >/dev/null   # ICMP не трогаем: иначе ломается PMTUD
}
s_f2b(){
  log "5/11 fail2ban"
  put /etc/fail2ban/jail.d/99-hardening.local <<EOF
[DEFAULT]
backend = systemd
banaction = ufw
banaction_allports = ufw
bantime = 1h
findtime = 10m
maxretry = 4
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 2w
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
mode = aggressive
port = $SSH_PORT

[recidive]
enabled = true
bantime = 4w
findtime = 1d
maxretry = 3
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban; sleep 2
  fail2ban-client status sshd || warn "fail2ban ещё поднимается"
}
s_sysctl(){
  log "6/11 sysctl"
  put /etc/sysctl.d/99-hardening.conf <<'EOF'
# --- анти-спуфинг и сетевой мусор (rp_filter=2 — loose)
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_rfc1337 = 1
# --- сервер не роутер (Docker сам включит ip_forward при старте — это ожидаемо)
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
# --- ядро
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
vm.mmap_min_addr = 65536
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
# --- производительность/устойчивость TCP
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
EOF
  sysctl --system >/dev/null 2>&1 || warn "часть sysctl не применилась"
}
s_services(){
  log "7/11 лишние сервисы"
  kill_unit avahi-daemon.service avahi-daemon.socket cups.service cups.socket cups-browsed.service \
            bluetooth.service rpcbind.service rpcbind.socket nfs-server.service ModemManager.service \
            apport.service whoopsie.service telnet.socket xinetd.service ctrl-alt-del.target
  put /etc/systemd/coredump.conf.d/99-hardening.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
  put /etc/security/limits.d/99-hardening.conf <<'EOF'
* hard core 0
EOF
}
s_logs(){
  log "8/11 journald + auditd"
  put /etc/systemd/journald.conf.d/99-hardening.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=1month
ForwardToSyslog=no
EOF
  mkdir -p /var/log/journal; systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
  systemctl restart systemd-journald || warn "journald не перезапущен"
  put /etc/audit/rules.d/99-hardening.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/docker/ -p wa -k docker
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k rootcmd
-e 1
EOF
  systemctl enable auditd >/dev/null 2>&1 || true
  augenrules --load >/dev/null 2>&1 || warn "auditd: правила не загружены"
}
s_auth(){
  log "9/11 пароли / sudo / apparmor / ntp"
  put /etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
enforce_for_root
EOF
  put /etc/sudoers.d/99-hardening 0440 <<'EOF'
Defaults	use_pty
Defaults	logfile="/var/log/sudo.log"
Defaults	timestamp_timeout=10
Defaults	!visiblepw
Defaults	env_reset
EOF
  visudo -cf /etc/sudoers.d/99-hardening >/dev/null || { rm -f /etc/sudoers.d/99-hardening; warn "sudoers drop-in невалиден"; }
  passwd -l root >/dev/null 2>&1 || true
  local u
  while read -r u; do
    [[ -n "$u" ]] && { passwd -l "$u" >/dev/null; warn "залочен пустой пароль: $u"; }
  done < <(awk -F: '($2==""){print $1}' /etc/shadow)
  awk -F: '($3==0 && $1!="root"){print "[!] лишний UID 0: "$1}' /etc/passwd
  setkv /etc/login.defs UMASK 027; setkv /etc/login.defs LOGIN_RETRIES 3; setkv /etc/login.defs LOGIN_TIMEOUT 30
  put /etc/profile.d/99-hardening.sh <<'EOF'
if [ -n "${SSH_CONNECTION:-}" ] && [ -z "${TMOUT:-}" ]; then TMOUT=900; export TMOUT; fi
[ "$(id -u)" = 0 ] && umask 027
EOF
  systemctl enable --now apparmor >/dev/null 2>&1 || true
  if unit_exists systemd-timesyncd.service; then
    systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
    timedatectl set-ntp true || true
  fi
  if have etckeeper; then
    [[ -d /etc/.git ]] || etckeeper init >/dev/null 2>&1 || true
    if [[ -d /etc/skel/.nvm/.git ]]; then
      printf 'skel/.nvm/\n' >>/etc/.gitignore
    fi
    etckeeper commit "hardening $TS" >/dev/null 2>&1 || warn "etckeeper commit не прошёл"
  fi
}
s_tarpit(){
  if [[ "$TARPIT" != 1 || "$SSH_PORT" == 22 ]]; then log "10/11 тарпит пропущен"; return 0; fi
  log "10/11 endlessh"
  pkg endlessh || { warn "нет пакета endlessh"; return 0; }
  put /etc/endlessh/config <<'EOF'
Port 22
Delay 10000
MaxLines 1
MaxClients 4096
EOF
  ufw allow 22/tcp comment 'tarpit' >/dev/null
  systemctl enable --now endlessh >/dev/null 2>&1 || true
}
s_final(){
  log "11/11 проверки"
  local def='{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"live-restore":true,"no-new-privileges":true}'
  mkdir -p /etc/docker
  if [[ -f /etc/docker/daemon.json ]]; then
    bak /etc/docker/daemon.json
    jq -s '.[0] * .[1]' /etc/docker/daemon.json <(echo "$def") >/etc/docker/d.new \
      && mv /etc/docker/d.new /etc/docker/daemon.json
    if have docker; then
      warn "docker: перезапусти сам — systemctl restart docker"
    fi
  else
    put /etc/docker/daemon.json 0644 <<<"$def"
  fi
  warn "docker обходит UFW: публикуй порты как -p 127.0.0.1:8080:80, не -p 8080:80"

  if [[ "$RUN_LYNIS" == 1 ]]; then
    have lynis || pkg lynis || true
    have lynis && lynis audit system --quick --no-colors | tail -30 || true
  fi
  echo; ss -tulpn | sed 's/^/    /'; echo; ufw status numbered
  cat <<DONE

${G}ГОТОВО.${N} Бэкап: $BACKUP_DIR   Лог: $LOG

${Y}не закрывая эту сессию:${N}
 1) новый терминал: ssh -p $SSH_PORT $ADMIN_USER@<ip>
 2) зашёл → systemctl stop ssh-rollback.timer   (иначе через 15 мин откат)
 3) ufw delete allow $OLD_PORT/tcp
 4) полный откат: sudo hardening-rollback $BACKUP_DIR
 5) сервисы биндить на 127.0.0.1, доступ: ssh -p $SSH_PORT -L 8080:127.0.0.1:8080 $ADMIN_USER@<ip>
$([[ -f /var/run/reboot-required ]] && echo " 6) новое ядро → reboot")
DONE
}

main(){
  parse_args "$@"
  [[ $EUID -eq 0 ]] || die "нужен root: curl ... | sudo bash -s -- --flags"
  if [[ $ROLLBACK == 1 ]]; then
    [[ -x /usr/local/sbin/hardening-rollback ]] || die "хелпер отката не найден"
    exec /usr/local/sbin/hardening-rollback ${ROLLBACK_DIR:+"$ROLLBACK_DIR"}
  fi
  have systemctl || die "нужен systemd (не LXC-контейнер)"
  . /etc/os-release; [[ "${ID:-}" == ubuntu ]] || warn "не Ubuntu: ${PRETTY_NAME:-?}"
  TS="$(date +%Y%m%d-%H%M%S)"; BACKUP_DIR="/root/hardening-backup-$TS"; LOG="/var/log/hardening-$TS.log"
  mkdir -p "$BACKUP_DIR"; touch "$LOG"; chmod 600 "$LOG"
  exec > >(tee -a "$LOG") 2>&1
  trap 'on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
  detect; collect_keys
  cat <<PLAN

 ubuntu-hardening (main) — базовая безопасность, без VPN
 админ: $ADMIN_USER (ssh: $ALLOW_USERS), ключей: $KEY_COUNT
 ssh:   $OLD_PORT → $SSH_PORT, только ключи, root no
 ufw:   deny in / deny routed$( [[ $ALLOW_HTTP == 1 ]] && echo ", открыты 80/443" )
 форвардинг: off   авто-ребут: $AUTO_REBOOT   тарпит: $TARPIT   docker-hardening: on
 бэкап: $BACKUP_DIR

PLAN
  if [[ $DRY_RUN == 1 ]]; then log "dry-run: ничего не меняю"; exit 0; fi
  if [[ "$ASSUME_YES" != 1 ]]; then
    [[ -e /dev/tty ]] || die "нет TTY (пайп/cron) → добавь --yes"
    read -r -p "продолжить? [y/N] " a </dev/tty; [[ "$a" == y* ]] || exit 0
  fi
  ensure_admin; write_rollback_helper
  s_updates; s_autoupdate; s_ssh; s_ufw; s_f2b; s_sysctl; s_services; s_logs; s_auth; s_tarpit; s_final
}
main "$@"