# ubuntu-hardening

Первичная настройка безопасности Ubuntu-сервера: закрыть вход от ботов, включить
автопатчи, аудит и логи — дальше настраиваешь свои дела сам.
Ubuntu 22.04 / 24.04 / 26.04 LTS, systemd. **Не для LXC-контейнеров.**

## Запуск

```bash
curl -fsSL https://raw.githubusercontent.com/yyxa/vps/main/ubuntu/setup.sh | sudo bash
```

Админ = `$SUDO_USER`, ключи = его `authorized_keys`. План без изменений:

```bash
curl -fsSL https://raw.githubusercontent.com/yyxa/vps/main/ubuntu/setup.sh | sudo bash -s -- --dry-run
```

Чистая машина, ключи прямо с GitHub-профиля:

```bash
curl -fsSL https://raw.githubusercontent.com/yyxa/vps/main/ubuntu/setup.sh \
  | sudo bash -s -- --user ivan --gh-keys yyxa --yes
```

## Что делает

| | |
|---|---|
| SSH | порт **2222**, только ключи, root no, `AllowUsers`, `MaxAuthTries 3`, `sshd -t` перед рестартом |
| Страховка | авто-откат SSH-конфига через 15 мин, если не отменить таймер |
| Firewall | ufw: deny incoming, deny routed, наружу только SSH; ICMP не трогается (иначе ломается PMTUD) |
| Боты | fail2ban (sshd aggressive + recidive, баны растут до 2 недель) + endlessh-тарпит на 22 |
| Патчи | unattended-upgrades (security + updates), авто-ребут 04:30 при новом ядре |
| Сеть/ядро | sysctl: анти-спуфинг, syncookies, **форвардинг выключен**, kptr/dmesg restrict, BBR + fq |
| Поверхность | выключены avahi, cups/cups-browsed, bluetooth, rpcbind/nfs, apport/whoopsie; кордампы в ноль |
| Логи | journald persistent (500M / месяц), auditd: identity, sudoers, sshd, модули ядра, sudo-команды |
| Доступ | pwquality (14+ символов), sudo `use_pty` + журнал, root-пароль залочен, AppArmor, timesyncd, etckeeper |

VPN **не ставится** — это базовый слой, поверх него ставишь что нужно.

## Флаги

| Флаг | Эффект |
|---|---|
| `--user U` | админ с sudo |
| `--key "ssh-ed25519 ..."` / `--key-file F` / `--gh-keys NICK` | источник публичных ключей |
| `--ssh-port N` | `22` → тарпит отключится сам |
| `--trusted-ip IP` | IP вне банов fail2ban |
| `--allow-users "deploy git"` | кому ещё можно SSH |
| `--http` | открыть 80/443 (для личных проектов обычно не нужно) |
| `--no-auto-reboot` | не ребутить ночью |
| `--no-tarpit` | без endlessh |
| `--docker-prep` | заранее положить `/etc/docker/daemon.json` (ротация логов, `no-new-privileges`) |
| `--lynis` | аудит в конце |
| `--yes` / `--dry-run` | без подтверждения / только план |
| `--rollback [DIR]` | откат конфигов |

Флаги требуют `bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/yyxa/vps/main/ubuntu/setup.sh \
  | sudo bash -s -- --ssh-port 22 --no-auto-reboot --docker-prep
```

## После запуска (текущую сессию не закрывать)

```bash
ssh -p 2222 ivan@SERVER                    # 1. проверка из НОВОГО терминала
sudo systemctl stop ssh-rollback.timer     # 2. зашёл — отменить авто-откат
sudo ufw delete allow 22/tcp               # 3. закрыть старый порт (если не тарпит)
sudo ss -tulpn                             # 4. что реально слушает
```

Откат: `sudo hardening-rollback [DIR]`
Бэкапы: `/root/hardening-backup-*`, лог: `/var/log/hardening-*.log` (без ключей и паролей).
Пароль sudo, если сгенерирован: `/root/.admin-password-*` → в менеджер паролей, файл удалить.

## Как жить с закрытым firewall

Сервисы биндишь на localhost, наружу ничего не открывается:

```bash
python -m http.server 8000 --bind 127.0.0.1
docker run -p 127.0.0.1:8080:8080 ...        # -p 8080:80 ОБХОДИТ UFW!
```

Доступ с ноутбука — SSH-туннель (разрешён, `AllowTcpForwarding local`):

```bash
ssh -p 2222 -L 8080:127.0.0.1:8080 ivan@SERVER   # один сервис
ssh -p 2222 -D 1080 ivan@SERVER                  # SOCKS-прокси на всё
```

Понадобится доступ с телефона или UDP — ставь VPN отдельно, скрипт ему не мешает.

## Проверка

```bash
sudo sshd -T | grep -Ei 'permitroot|passwordauth|port|allowusers'
sudo ufw status numbered && sudo fail2ban-client status sshd
grep ip_forward /etc/sysctl.d/99-hardening.conf
sudo lynis audit system
```

---

Всё берётся из ветки `main`, без версий и тегов. Каждый пуш прогоняется CI
на эфемерной VM: shellcheck, dry-run, полная установка + откат.