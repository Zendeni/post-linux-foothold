#!/usr/bin/env bash

# Read-only Linux post-foothold enumeration for authorized labs.
# The script writes only to its report directory and never attempts escalation.

set -u
umask 077
export LC_ALL=C

VERSION="1.2.0"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
DEFAULT_TIMEOUT=60
DEEP_TIMEOUT=240
MODE="standard"
OUTPUT_DIR=""
START_EPOCH=0

usage() {
    cat <<'EOF'
Usage: post-linux-foothold.sh [options]

Read-only Linux enumeration for an authorized post-foothold shell.

Options:
  --quick              Skip slower filesystem/content searches
  --deep               Add bounded whole-filesystem searches
  -o, --output DIR     Report directory (default: ./post-linux-foothold-*)
  --timeout SECONDS    Per-section timeout (default: 60)
  --deep-timeout SEC   Deep-section timeout (default: 240)
  -h, --help           Show this help

Examples:
  ./post-linux-foothold.sh
  ./post-linux-foothold.sh --quick
  ./post-linux-foothold.sh --deep -o /tmp/foothold-report
EOF
}

have() {
    command -v "$1" >/dev/null 2>&1
}

heading() {
    printf '\n===== %s =====\n' "$1"
}

run() {
    printf '\n$'
    printf ' %q' "$@"
    printf '\n'
    "$@" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '[exit %d]\n' "$rc"
    fi
    return 0
}

run_if() {
    local tool="$1"
    shift
    if have "$tool"; then
        run "$tool" "$@"
    else
        printf '\n[missing] %s\n' "$tool"
    fi
}

run_shell() {
    printf '\n$ %s\n' "$1"
    bash -c "$1" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '[exit %d]\n' "$rc"
    fi
    return 0
}

section_identity() {
    heading "Identity and session"
    run date -Is
    run whoami
    run id
    run groups
    run hostname
    run hostname -f
    run pwd
    run tty
    run umask
    run_if w
    run_if who -a
    run_if last -n 30
    run_if lastlog
    run_shell 'printf "shell=%s\nparent=%s\n" "${SHELL:-unknown}" "$(ps -p "$PPID" -o comm= 2>/dev/null)"'
    run_shell 'grep -E "^(Name|Umask|State|Pid|PPid|Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):" /proc/self/status 2>/dev/null'
}

section_os_kernel() {
    heading "Operating system and kernel"
    run uname -a
    run uname -r
    run_if hostnamectl
    run_shell 'cat /etc/os-release 2>/dev/null; cat /etc/*release 2>/dev/null | sort -u'
    run_if lsb_release -a
    run_if uptime
    run_if arch
    run_if lscpu
    run_shell 'printf "Kernel command line: "; cat /proc/cmdline 2>/dev/null'
    run_shell 'printf "Clock: "; date; printf "Timezone: "; cat /etc/timezone 2>/dev/null'
    run_shell 'ldd --version 2>&1 | head -n 3; getconf GNU_LIBC_VERSION 2>/dev/null'
    run_shell 'for f in /proc/version /proc/sys/kernel/osrelease /proc/sys/kernel/randomize_va_space /proc/sys/kernel/yama/ptrace_scope /proc/sys/kernel/unprivileged_userns_clone /proc/sys/fs/protected_hardlinks /proc/sys/fs/protected_symlinks; do [ -r "$f" ] && printf "%s: " "$f" && cat "$f"; done'
    run_shell 'dmesg 2>/dev/null | tail -n 100'
}

section_users_groups() {
    heading "Users, groups and authentication files"
    run_shell 'getent passwd 2>/dev/null || cat /etc/passwd'
    run_shell 'getent group 2>/dev/null || cat /etc/group'
    run_shell 'awk -F: "\$3 == 0 || \$7 !~ /(nologin|false)$/ {print}" /etc/passwd 2>/dev/null'
    run_shell 'for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid; do ls -l "$f" 2>/dev/null; [ -r "$f" ] && { echo "--- readable: $f"; cat "$f"; }; done'
    run_shell 'for d in /home /root; do [ -d "$d" ] && find "$d" -mindepth 1 -maxdepth 1 -printf "%M %u:%g %p\n" 2>/dev/null; done'
    run_shell 'getent passwd | while IFS=: read -r name _ uid gid gecos home shell; do [ -d "$home" ] && printf "%s uid=%s gid=%s home=%s shell=%s\n" "$name" "$uid" "$gid" "$home" "$shell"; done'
    run_shell 'for f in /etc/security/access.conf /etc/login.defs /etc/pam.d/common-auth /etc/pam.d/system-auth; do [ -r "$f" ] && { echo "--- $f"; sed -n "1,220p" "$f"; }; done'
}

section_environment_path() {
    heading "Environment, PATH and shell"
    run_shell 'env | sort'
    run_shell 'printf "%s\n" "$PATH" | tr ":" "\n" | while read -r d; do [ -n "$d" ] || d=.; ls -ld "$d" 2>/dev/null; [ -w "$d" ] && echo "WRITABLE_PATH_DIRECTORY $d"; done'
    run_shell 'for f in /etc/profile /etc/bash.bashrc /etc/zsh/zshrc "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do [ -r "$f" ] && { echo "--- $f"; sed -n "1,220p" "$f"; }; done'
    run_shell 'compgen -a 2>/dev/null | sort -u | head -n 500'
    run_shell 'ulimit -a 2>/dev/null'
}

section_filesystems() {
    heading "Filesystems, disks and mounts"
    run_if df -hT
    run_if mount
    run_if findmnt -A
    run_if lsblk -a -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINTS,UUID,MODEL
    run_shell 'for f in /etc/fstab /etc/exports /etc/auto.master /etc/auto.*; do [ -r "$f" ] && { echo "--- $f"; cat "$f"; }; done'
    run_shell 'findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | grep -E "(^|,)(rw|no_root_squash|user|users|exec)(,|$)|/(var|opt|srv|home|tmp)"'
    run_shell 'find / -xdev -maxdepth 3 -type d \( -name backups -o -name backup -o -name old -o -name archive -o -name snapshots \) -print 2>/dev/null | head -n 300'
    run_shell 'ls -la / /tmp /var/tmp /dev/shm /opt /srv /var/backups 2>/dev/null'
}

section_processes() {
    heading "Processes and exposed process data"
    run ps auxww
    run_if pstree -ap
    run_shell 'for p in /proc/[0-9]*; do [ -r "$p/cmdline" ] || continue; printf "%s " "${p##*/}"; tr "\0" " " < "$p/cmdline"; echo; done | head -n 1000'
    run_shell 'for p in /proc/[0-9]*; do [ -r "$p/environ" ] || continue; hit=$(tr "\0" "\n" < "$p/environ" 2>/dev/null | grep -Ei "pass(word)?|secret|token|api.?key|credential|auth|cookie|session|database|jdbc|aws_|azure_|gcp_|private" | head -n 30); [ -n "$hit" ] && { echo "--- PID ${p##*/}"; printf "%s\n" "$hit"; }; done'
    run_shell 'for p in /proc/[0-9]*; do [ -r "$p/status" ] || continue; awk -v p="${p##*/}" "/^(Name|Uid|Gid|CapEff|NoNewPrivs|Seccomp):/ {printf \"%s %s\\n\", p, \$0}" "$p/status"; done | head -n 1500'
    run_if lsof -nP
}

section_network() {
    heading "Network configuration and listeners"
    run_if ip -br address
    run_if ip route show table all
    run_if ip neigh
    run_if ss -lntup
    run_if ss -anp
    run_if netstat -lntup
    run_if route -n
    run_if arp -an
    run_if lsof -nP -i
    run_shell 'for f in /etc/hosts /etc/resolv.conf /etc/hostname /etc/network/interfaces /etc/netplan/*.yaml; do [ -r "$f" ] && { echo "--- $f"; cat "$f"; }; done'
    run_if nft list ruleset
    run_if iptables -S
    run_if iptables -t nat -S
}

section_services() {
    heading "Services and unit definitions"
    run_if systemctl --no-pager --type=service --state=running
    run_if systemctl --no-pager list-unit-files --type=service
    run_if service --status-all
    run_shell 'for d in /etc/systemd/system /usr/local/lib/systemd/system /lib/systemd/system /usr/lib/systemd/system; do [ -d "$d" ] && find "$d" -maxdepth 2 -type f -name "*.service" -writable -printf "WRITABLE_UNIT %M %u:%g %p\n" 2>/dev/null; done'
    run_shell 'grep -RhsE "^(User|Group|ExecStart|ExecStartPre|ExecStartPost|Environment|EnvironmentFile|WorkingDirectory)=" /etc/systemd/system /usr/local/lib/systemd/system /lib/systemd/system 2>/dev/null | head -n 1500'
    run_shell 'for f in /etc/init.d/*; do [ -f "$f" ] || continue; [ -w "$f" ] && ls -l "$f"; done'
    run_shell 'ls -la /run /run/lock /var/run 2>/dev/null | head -n 500'
}

section_schedules() {
    heading "Scheduled jobs and recurring execution"
    run_if crontab -l
    run_shell 'for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do [ -r "$f" ] && { echo "--- $f"; ls -l "$f"; cat "$f"; }; done'
    run_shell 'find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d -maxdepth 2 -type f -printf "%M %u:%g %p\n" 2>/dev/null'
    run_shell 'find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d -maxdepth 2 -type f -writable -printf "WRITABLE_CRON %M %u:%g %p\n" 2>/dev/null'
    run_if systemctl --no-pager list-timers --all
    run_if atq
    run_shell 'find /var/spool/at /var/spool/cron -maxdepth 3 -type f -readable -printf "%M %u:%g %p\n" 2>/dev/null'
}

section_suid_caps() {
    heading "SUID, SGID and file capabilities"
    run_shell 'find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf "%M %u:%g %p\n" 2>/dev/null | sort'
    run_shell 'if command -v getcap >/dev/null 2>&1; then getcap -r / 2>/dev/null; else echo "getcap missing"; fi'
    run_shell 'find / -xdev -type f -perm -0002 -printf "WORLD_WRITABLE_FILE %M %u:%g %p\n" 2>/dev/null | head -n 1000'
    run_shell 'find / -xdev -type f -user root -writable -printf "ROOT_OWNED_WRITABLE %M %u:%g %p\n" 2>/dev/null | head -n 1000'
}

section_writable() {
    heading "Writable escalation surfaces"
    run_shell 'for d in /etc /opt /srv /usr/local /var/www /var/lib /var/backups; do [ -d "$d" ] || continue; find "$d" -xdev -type f -writable -printf "%M %u:%g %p\n" 2>/dev/null; done | head -n 2500'
    run_shell 'for d in /etc /opt /srv /usr/local /var/www /var/lib; do [ -d "$d" ] || continue; find "$d" -xdev -type d -writable -printf "%M %u:%g %p\n" 2>/dev/null; done | head -n 1500'
    run_shell 'find / -xdev -type d -perm -0002 -printf "WORLD_WRITABLE_DIR %M %u:%g %p\n" 2>/dev/null | head -n 1200'
    run_shell 'find /tmp /var/tmp /dev/shm -maxdepth 3 -printf "%M %u:%g %TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null | head -n 1500'
    run_shell 'for f in /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d/*; do ls -l "$f" 2>/dev/null; [ -r "$f" ] && cat "$f"; done'
}

section_apps_configs() {
    heading "Applications, web roots and configuration files"
    run_shell 'for d in /var/www /srv /opt /usr/local /var/lib; do [ -d "$d" ] && { echo "--- $d"; find "$d" -maxdepth 4 -printf "%M %u:%g %p\n" 2>/dev/null | head -n 1200; }; done'
    run_shell 'find /var/www /srv /opt /home -xdev -type f -size -2M \( -name ".env" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.xml" -o -name "*.properties" -o -name "*.cnf" -o -name "wp-config.php" -o -name "settings.php" -o -name "config.php" -o -name "database.php" \) -readable -printf "%M %u:%g %p\n" 2>/dev/null | head -n 2000'
    run_shell 'find /var/www /srv /opt /home -xdev -type f -size -2M -readable \( -name ".env" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.properties" -o -name "*.php" \) -exec grep -IniE "pass(word)?|passwd|secret|token|api.?key|credential|database(_url)?|db_(user|pass|host)|jdbc|private.?key|aws_(access|secret)|connectionstring" {} + 2>/dev/null | head -n 2500'
    run_shell 'find / -xdev -type s -printf "%M %u:%g %p\n" 2>/dev/null | grep -Ei "mysql|maria|postgres|redis|docker|containerd|podman|lxd|snapd" | head -n 500'
}

section_credentials() {
    heading "Credential and user artifact discovery"
    run_shell 'for f in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history" "$HOME/.python_history" "$HOME/.mysql_history" "$HOME/.psql_history"; do [ -r "$f" ] && { echo "--- $f"; tail -n 1000 "$f"; }; done'
    run_shell 'find /home /root /var/www /opt /srv -xdev -type f -size -2M \( -name "id_*" -o -name "authorized_keys" -o -name "known_hosts" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.kdbx" -o -name ".netrc" -o -name ".git-credentials" -o -name ".npmrc" -o -name ".pypirc" -o -name "credentials" -o -name "credentials.xml" \) -readable -printf "%M %u:%g %p\n" 2>/dev/null | head -n 2000'
    run_shell 'find /home /root /var/www /opt /srv /var/backups -xdev -type f -size -5M \( -iname "*pass*" -o -iname "*secret*" -o -iname "*credential*" -o -iname "*token*" -o -iname "*.bak" -o -iname "*.old" -o -iname "*.save" -o -iname "*.backup" -o -iname "*.swp" -o -iname "*.sql" \) -readable -printf "%M %u:%g %p\n" 2>/dev/null | head -n 2500'
    run_shell 'for d in "$HOME/.ssh" "$HOME/.gnupg" "$HOME/.aws" "$HOME/.azure" "$HOME/.config/gcloud" "$HOME/.kube" "$HOME/.docker"; do [ -d "$d" ] && { echo "--- $d"; find "$d" -maxdepth 3 -printf "%M %u:%g %p\n" 2>/dev/null; }; done'
    run_shell 'for f in /var/mail/* /var/spool/mail/*; do [ -r "$f" ] && { echo "--- $f"; sed -n "1,500p" "$f"; }; done'
}

section_containers() {
    heading "Containers and virtualization"
    run_shell 'test -e /.dockerenv && echo DOCKERENV_PRESENT; test -e /run/.containerenv && echo CONTAINERENV_PRESENT; cat /proc/1/cgroup 2>/dev/null; cat /proc/self/cgroup 2>/dev/null'
    run_if systemd-detect-virt --all
    run_if virt-what
    run_shell 'ls -l /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock /var/snap/lxd/common/lxd/unix.socket 2>/dev/null'
    run_shell 'id | grep -E "docker|lxd|libvirt|incus|podman|disk" || true'
    run_if docker version
    run_if docker ps -a
    run_if podman ps -a
    run_if lxc list
    run_if incus list
    run_if kubectl config view --raw
    run_shell 'find / -xdev -maxdepth 4 -type f \( -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" -o -name "config.json" \) -readable -printf "%M %u:%g %p\n" 2>/dev/null | head -n 1000'
}

section_security_controls() {
    heading "Security controls and privileged helpers"
    run_if getenforce
    run_if sestatus
    run_if aa-status
    run_if apparmor_status
    run_shell 'for f in /proc/sys/kernel/yama/ptrace_scope /proc/sys/kernel/randomize_va_space /proc/sys/kernel/unprivileged_userns_clone /proc/sys/user/max_user_namespaces /proc/sys/fs/suid_dumpable /proc/sys/kernel/core_pattern; do [ -r "$f" ] && printf "%s: %s\n" "$f" "$(cat "$f")"; done'
    run_shell 'p=$(command -v pkexec 2>/dev/null); if [ -n "$p" ]; then printf "pkexec: %s\n" "$p"; ls -l "$p"; file "$p" 2>/dev/null; dpkg-query -S "$p" 2>/dev/null || rpm -qf "$p" 2>/dev/null; fi'
    run_shell 'for f in /etc/doas.conf /etc/polkit-1/rules.d/* /usr/share/polkit-1/rules.d/*; do [ -r "$f" ] && { echo "--- $f"; sed -n "1,240p" "$f"; }; done'
    run_shell 'env | grep -E "^(LD_|PYTHONPATH|PYTHONINSPECT|PERL5OPT|RUBYOPT|GCONV_PATH|BASH_ENV|ENV=)"'
    run_shell 'ls -l /etc/ld.so.preload /etc/passwd /etc/shadow /etc/group /etc/crontab /etc/profile /etc/environment 2>/dev/null'
}

section_packages_tools() {
    heading "Installed packages and useful tooling"
    run_shell 'if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f="\${Package}\t\${Version}\n"; elif command -v rpm >/dev/null 2>&1; then rpm -qa; elif command -v apk >/dev/null 2>&1; then apk info -vv; elif command -v pacman >/dev/null 2>&1; then pacman -Q; fi'
    run_shell 'for t in bash sh dash zsh python python2 python3 perl ruby php node java gcc cc g++ make cmake git curl wget nc ncat socat openssl ssh scp rsync tar base64 busybox find awk sed grep rg jq gdb strace ltrace tcpdump nmap mysql psql redis-cli sqlite3 screen tmux script pkexec doas docker podman lxc incus kubectl; do p=$(command -v "$t" 2>/dev/null) && printf "%-14s %s\n" "$t" "$p"; done'
    run_shell 'python3 --version 2>&1; php -v 2>&1 | head -n 3; perl -v 2>&1 | head -n 3; gcc --version 2>&1 | head -n 2; openssl version -a 2>&1 | head -n 8'
    run_shell 'find /usr/local/bin /usr/local/sbin /opt -xdev -maxdepth 4 -type f -executable -printf "%M %u:%g %p\n" 2>/dev/null | head -n 1500'
}

section_sessions_logs() {
    heading "Sessions, logs and IPC"
    run_if screen -ls
    run_if tmux list-sessions
    run_shell 'find /tmp /var/tmp /run /dev/shm -maxdepth 3 \( -type s -o -name "*tmux*" -o -name "*screen*" -o -name "*agent*" \) -printf "%M %u:%g %p\n" 2>/dev/null | head -n 1000'
    run_shell 'find /var/log -xdev -type f -readable -printf "%M %u:%g %s %p\n" 2>/dev/null | head -n 1500'
    run_shell 'for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do [ -r "$f" ] && { echo "--- $f"; tail -n 500 "$f"; }; done'
    run_if journalctl --no-pager -n 500
    run_if ipcs -a
}

section_custom_code() {
    heading "Custom scripts, binaries and ownership anomalies"
    run_shell 'for root in /home /opt /srv /usr/local /var/www; do [ -d "$root" ] || continue; find "$root" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null; done | while IFS= read -r -d "" f; do echo "--- NONSTANDARD_PRIVILEGED_EXECUTABLE $f"; stat "$f" 2>/dev/null; file "$f" 2>/dev/null; sha256sum "$f" 2>/dev/null; if command -v readelf >/dev/null 2>&1; then readelf -h -l "$f" 2>/dev/null | head -n 120; fi; if command -v strings >/dev/null 2>&1; then echo "--- notable strings"; strings -a "$f" 2>/dev/null | grep -Ei "python|perl|ruby|php|pyinstaller|input|eval|exec|system|subprocess|shell|/bin/|/usr/bin/|home/|tmp/" | head -n 160; fi; done'
    run_shell 'find /opt /srv /usr/local /var/www -xdev -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o -name "*.php" -o -perm -111 \) -printf "%M %u:%g %TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null | head -n 2500'
    run_shell 'find /opt /srv /usr/local /var/www -xdev -type f -user root -writable -printf "ROOT_OWNED_WRITABLE %M %u:%g %p\n" 2>/dev/null | head -n 1000'
    run_shell 'find / -xdev -type f -mtime -7 -printf "%M %u:%g %TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null | grep -Ev "^.* /(proc|sys|run|tmp)/" | head -n 2000'
    run_shell 'find / -xdev -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" -o -name "*.path" \) -writable -printf "%M %u:%g %p\n" 2>/dev/null | head -n 1000'
}

section_deep_search() {
    heading "Deep whole-filesystem search"
    run_shell 'skip=${ENUM_OUTPUT_DIR:-/__post_enum_no_match__}; find / -xdev \( -path "$skip" -o -path "$skip/*" \) -prune -o -type f -writable -printf "%M %u:%g %s %p\n" 2>/dev/null | head -n 5000'
    run_shell 'skip=${ENUM_OUTPUT_DIR:-/__post_enum_no_match__}; find / -xdev \( -path "$skip" -o -path "$skip/*" \) -prune -o -type d -writable -printf "%M %u:%g %p\n" 2>/dev/null | head -n 5000'
    run_shell 'skip=${ENUM_OUTPUT_DIR:-/__post_enum_no_match__}; find / -xdev \( -path "$skip" -o -path "$skip/*" \) -prune -o -type f -size -5M -readable \( -iname "*.bak" -o -iname "*.old" -o -iname "*.backup" -o -iname "*.save" -o -iname "*.swp" -o -iname "*.orig" -o -iname "*password*" -o -iname "*secret*" -o -iname "*credential*" -o -iname "*token*" -o -name ".env" -o -name "id_*" -o -name "*.pem" -o -name "*.key" -o -name "*.kdbx" \) -printf "%M %u:%g %s %p\n" 2>/dev/null | head -n 5000'
    run_shell 'skip=${ENUM_OUTPUT_DIR:-/__post_enum_no_match__}; find / -xdev \( -path "$skip" -o -path "$skip/*" \) -prune -o -type f -size -2M -readable \( -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.yml" -o -name "*.yaml" -o -name "*.properties" -o -name ".env" \) -exec grep -IniE "pass(word)?|passwd|secret|token|api.?key|credential|private.?key|connectionstring" {} + 2>/dev/null | head -n 5000'
}

if [ "${1:-}" = "--internal-section" ]; then
    if [ "$#" -ne 2 ] || ! declare -F "$2" >/dev/null 2>&1; then
        echo "Invalid internal section" >&2
        exit 2
    fi
    "$2"
    exit 0
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --quick)
            MODE="quick"
            shift
            ;;
        --deep)
            MODE="deep"
            shift
            ;;
        -o|--output)
            [ "$#" -ge 2 ] || { echo "Missing output directory" >&2; exit 2; }
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --timeout)
            [ "$#" -ge 2 ] || { echo "Missing timeout value" >&2; exit 2; }
            DEFAULT_TIMEOUT="$2"
            shift 2
            ;;
        --deep-timeout)
            [ "$#" -ge 2 ] || { echo "Missing deep timeout value" >&2; exit 2; }
            DEEP_TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! [[ "$DEFAULT_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || ! [[ "$DEEP_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    echo "Timeout values must be positive integers" >&2
    exit 2
fi

HOST_LABEL="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-80)"
[ -n "$HOST_LABEL" ] || HOST_LABEL="host"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$PWD/post-linux-foothold-${HOST_LABEL}-${TIMESTAMP}"
fi

if [ -e "$OUTPUT_DIR" ] && [ -n "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]; then
    echo "Output directory exists and is not empty: $OUTPUT_DIR" >&2
    exit 2
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
export ENUM_OUTPUT_DIR="$OUTPUT_DIR"

SECTION_FUNCS=(
    section_identity
    section_os_kernel
    section_users_groups
    section_environment_path
    section_filesystems
    section_processes
    section_network
    section_services
    section_schedules
    section_security_controls
    section_packages_tools
    section_sessions_logs
)
SECTION_FILES=(
    01-identity.txt
    02-os-kernel.txt
    03-users-groups.txt
    04-environment-path.txt
    05-filesystems.txt
    06-processes.txt
    07-network.txt
    08-services.txt
    09-schedules.txt
    10-security-controls.txt
    11-packages-tools.txt
    12-sessions-logs.txt
)
SECTION_TITLES=(
    "Identity and session"
    "OS and kernel"
    "Users and groups"
    "Environment and PATH"
    "Filesystems"
    "Processes"
    "Network"
    "Services"
    "Scheduled jobs"
    "Security controls"
    "Packages and tools"
    "Sessions and logs"
)

if [ "$MODE" != "quick" ]; then
    SECTION_FUNCS+=(section_suid_caps section_writable section_apps_configs section_credentials section_containers section_custom_code)
    SECTION_FILES+=(13-suid-sgid-capabilities.txt 14-writable-surfaces.txt 15-apps-configs.txt 16-credentials-artifacts.txt 17-containers.txt 18-custom-code.txt)
    SECTION_TITLES+=("SUID, SGID and capabilities" "Writable surfaces" "Applications and configs" "Credentials and artifacts" "Containers" "Custom code")
fi

if [ "$MODE" = "deep" ]; then
    SECTION_FUNCS+=(section_deep_search)
    SECTION_FILES+=(19-deep-search.txt)
    SECTION_TITLES+=("Deep filesystem search")
fi

TOTAL="${#SECTION_FUNCS[@]}"
START_EPOCH="$(date +%s)"

cat > "$OUTPUT_DIR/metadata.txt" <<EOF
post-linux-foothold version: $VERSION
mode: $MODE
started: $(date -Is)
host: $(hostname 2>/dev/null)
user: $(id 2>/dev/null)
working_directory: $PWD
per_section_timeout: $DEFAULT_TIMEOUT
deep_section_timeout: $DEEP_TIMEOUT
EOF

printf 'section\tstatus\tseconds\tfile\n' > "$OUTPUT_DIR/status.tsv"

run_section() {
    local number="$1" function_name="$2" file_name="$3" title="$4" limit="$5"
    local before after elapsed rc percent
    before="$(date +%s)"
    percent="$(((number - 1) * 100 / TOTAL))"
    printf '[%3d%%] [%d/%d] %s\n' "$percent" "$number" "$TOTAL" "$title"

    if have timeout; then
        if timeout --help 2>&1 | grep -q -- '--kill-after'; then
            timeout --signal=TERM --kill-after=5 "$limit" bash "$SCRIPT_PATH" --internal-section "$function_name" > "$OUTPUT_DIR/$file_name" 2>&1
        else
            timeout "$limit" bash "$SCRIPT_PATH" --internal-section "$function_name" > "$OUTPUT_DIR/$file_name" 2>&1
        fi
        rc=$?
    elif have setsid; then
        # Minimal-system fallback: isolate the section in a process group and
        # have a watchdog terminate that entire group at the time limit.
        setsid bash "$SCRIPT_PATH" --internal-section "$function_name" > "$OUTPUT_DIR/$file_name" 2>&1 &
        local section_pid=$!
        (
            sleep "$limit"
            kill -TERM -- "-$section_pid" 2>/dev/null || exit 0
            sleep 5
            kill -KILL -- "-$section_pid" 2>/dev/null || true
        ) &
        local watchdog_pid=$!
        wait "$section_pid"
        rc=$?
        kill "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
        if [ "$rc" -eq 143 ] || [ "$rc" -eq 137 ]; then
            rc=124
        fi
    else
        printf '[warning] timeout and setsid are unavailable; this section cannot be bounded\n' >> "$OUTPUT_DIR/$file_name"
        bash "$SCRIPT_PATH" --internal-section "$function_name" > "$OUTPUT_DIR/$file_name" 2>&1
        rc=$?
    fi

    after="$(date +%s)"
    elapsed="$((after - before))"
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        printf '%s\ttimed-out\t%s\t%s\n' "$title" "$elapsed" "$file_name" >> "$OUTPUT_DIR/status.tsv"
        printf '        timed out after %ss; continuing\n' "$limit"
    elif [ "$rc" -eq 0 ]; then
        printf '%s\tcomplete\t%s\t%s\n' "$title" "$elapsed" "$file_name" >> "$OUTPUT_DIR/status.tsv"
    else
        printf '%s\texit-%s\t%s\t%s\n' "$title" "$rc" "$elapsed" "$file_name" >> "$OUTPUT_DIR/status.tsv"
        printf '        exited %s; continuing\n' "$rc"
    fi
}

for index in "${!SECTION_FUNCS[@]}"; do
    section_number="$((index + 1))"
    section_limit="$DEFAULT_TIMEOUT"
    if [ "${SECTION_FUNCS[$index]}" = "section_deep_search" ]; then
        section_limit="$DEEP_TIMEOUT"
    fi
    run_section "$section_number" "${SECTION_FUNCS[$index]}" "${SECTION_FILES[$index]}" "${SECTION_TITLES[$index]}" "$section_limit"
done

END_EPOCH="$(date +%s)"
ELAPSED="$((END_EPOCH - START_EPOCH))"

FINDINGS_FILE="$OUTPUT_DIR/findings.tsv"
printf 'priority\tfinding\tevidence\tnext_step\n' > "$FINDINGS_FILE"

add_finding() {
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$FINDINGS_FILE"
}

has_line() {
    [ -f "$1" ] && grep -Eq "$2" "$1" 2>/dev/null
}

has_data_line() {
    [ -f "$1" ] && grep -Ev '^\$' "$1" 2>/dev/null | grep -Eq "$2"
}

# Rules are ordered by likely impact and reliability. They only match result
# lines, not the echoed command text at the start of each raw check.
if has_line "$OUTPUT_DIR/01-identity.txt" '^uid=0\('; then
    add_finding "INFO" "The current shell is already uid 0" "01-identity.txt" "Verify access and collect the intended lab proof; no local escalation is required."
fi

if has_line "$OUTPUT_DIR/08-services.txt" '^WRITABLE_UNIT ';
then
    add_finding "CRITICAL" "Writable service unit discovered" "08-services.txt" "Inspect the unit, its activation conditions and every referenced executable before choosing the least disruptive validation."
fi

if has_line "$OUTPUT_DIR/09-schedules.txt" '^WRITABLE_CRON ';
then
    add_finding "CRITICAL" "Writable scheduled-job file discovered" "09-schedules.txt" "Identify its owner, execution user and next run time, then inspect the command and parent directories."
fi

if has_line "$OUTPUT_DIR/14-writable-surfaces.txt" '^ROOT_OWNED_WRITABLE ' || has_line "$OUTPUT_DIR/18-custom-code.txt" '^ROOT_OWNED_WRITABLE ';
then
    add_finding "CRITICAL" "Root-owned file is writable by the foothold user" "14-writable-surfaces.txt; 18-custom-code.txt" "Determine whether a privileged service or scheduled job consumes the file and validate that execution path."
fi

if has_line "$OUTPUT_DIR/01-identity.txt" '^uid=.*groups=.*(docker|lxd|incus|libvirt|podman|disk)([, )]|$)'; then
    add_finding "CRITICAL" "Current user belongs to a high-impact local group" "01-identity.txt; 17-containers.txt" "Inspect the matching socket or device access and enumerate resources available through that group."
fi

if has_line "$OUTPUT_DIR/17-containers.txt" '^srw.rw.rw.*(docker|containerd|podman|lxd|incus).*sock'; then
    add_finding "CRITICAL" "A container-management socket appears broadly writable" "17-containers.txt" "Confirm effective access and inspect available images, mounts and running containers."
fi

custom_privileged_line="$(grep -E '^-[^[:space:]]*[sS][^[:space:]]*[[:space:]][^[:space:]]+:[^[:space:]]+[[:space:]]+/(home|opt|srv|usr/local|var/www|tmp|var/tmp)/' "$OUTPUT_DIR/13-suid-sgid-capabilities.txt" 2>/dev/null | head -n 1 || true)"
if [ -n "$custom_privileged_line" ]; then
    custom_privileged_path="${custom_privileged_line##* }"
    add_finding "HIGH" "Nonstandard privileged executable: $custom_privileged_path" "13-suid-sgid-capabilities.txt; 18-custom-code.txt" "Inspect its ownership, file type and notable strings in the custom-code report, then trace how it handles user-controlled input."
fi

if has_line "$OUTPUT_DIR/13-suid-sgid-capabilities.txt" 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|chown|fowner)([,=+]|$)'; then
    add_finding "HIGH" "High-impact Linux file capability discovered" "13-suid-sgid-capabilities.txt" "Map the capable executable to its documented behavior and test whether the capability crosses the current privilege boundary."
fi

if has_line "$OUTPUT_DIR/13-suid-sgid-capabilities.txt" '^-[^[:space:]]*[sS][^[:space:]]*[[:space:]].*/(bash|dash|sh|find|vim|vi|less|more|awk|python[0-9.]*|perl|ruby|php|node|env|tar|zip|nmap|gdb|strace)([[:space:]]|$)'; then
    add_finding "HIGH" "Potentially abusable SUID/SGID interpreter or utility discovered" "13-suid-sgid-capabilities.txt" "Verify the exact binary, ownership and mode, then compare its supported features with an authoritative technique reference."
fi

if has_data_line "$OUTPUT_DIR/05-filesystems.txt" 'no_root_squash'; then
    add_finding "HIGH" "NFS export uses no_root_squash" "05-filesystems.txt" "Confirm that the export is reachable and writable, and inspect how files created through it are interpreted on the host."
fi

if has_line "$OUTPUT_DIR/03-users-groups.txt" '^--- readable: /etc/(shadow|gshadow)$'; then
    add_finding "HIGH" "Protected authentication database is readable" "03-users-groups.txt" "Review the exposed hashes or group secrets and test authorized credential reuse offline."
fi

if has_line "$OUTPUT_DIR/06-processes.txt" '^[A-Za-z_][A-Za-z0-9_]*(PASS(WORD)?|SECRET|TOKEN|API_?KEY|CREDENTIAL|DATABASE_URL|AWS_ACCESS|AWS_SECRET)[A-Za-z0-9_]*='; then
    add_finding "HIGH" "A process exposes credential-like environment data" "06-processes.txt" "Identify the owning process and validate the credential only against services within this lab."
fi

if has_line "$OUTPUT_DIR/16-credentials-artifacts.txt" '^-[^[:space:]]+[[:space:]]+[^[:space:]]+:[^[:space:]]+[[:space:]]+/(home|root|var/www|opt|srv)/.*(id_[^/ ]+|\.pem|\.key|\.p12|\.pfx|\.kdbx|\.netrc|\.git-credentials|credentials)'; then
    add_finding "HIGH" "Readable credential or private-key artifact discovered" "16-credentials-artifacts.txt" "Inspect ownership and intended service, then test authorized authentication or credential reuse."
fi

if has_line "$OUTPUT_DIR/15-apps-configs.txt" '^/[^:]+:[0-9]+:.*(pass(word)?|passwd|secret|token|api.?key|credential|db_(user|pass)|database_url|private.?key|connectionstring)'; then
    add_finding "MEDIUM" "Application configuration contains credential-like data" "15-apps-configs.txt" "Review the matching configuration lines and map each credential to local services and users."
fi

if has_line "$OUTPUT_DIR/04-environment-path.txt" '^WRITABLE_PATH_DIRECTORY ';
then
    add_finding "MEDIUM" "The current command PATH contains a writable directory" "04-environment-path.txt" "Check whether a privileged script or service invokes an unqualified command after inheriting this PATH."
fi

if has_line "$OUTPUT_DIR/13-suid-sgid-capabilities.txt" '^WORLD_WRITABLE_FILE ';
then
    add_finding "MEDIUM" "World-writable regular files exist on the system filesystem" "13-suid-sgid-capabilities.txt" "Prioritize files referenced by privileged services, scheduled jobs, libraries or scripts."
fi

if ! tail -n +2 "$FINDINGS_FILE" | grep -q .; then
    add_finding "BASELINE" "No decisive high-confidence path was identified automatically" "All numbered reports" "Review application secrets, scheduled execution, custom code and unusual privileged binaries manually; automated ranking is intentionally conservative."
fi

{
    echo "# Linux Foothold Enumeration Summary"
    echo
    echo "- Host: \`$(hostname 2>/dev/null)\`"
    echo "- User: \`$(whoami 2>/dev/null)\`"
    echo "- Mode: \`$MODE\`"
    echo "- Completed: \`$(date -Is)\`"
    echo "- Elapsed seconds: \`$ELAPSED\`"
    echo
    echo "## Start Here"
    echo
    if [ "$MODE" = "quick" ]; then
        echo "1. \`09-schedules.txt\` — recurring jobs and writable scheduled scripts."
        echo "2. \`08-services.txt\` — service definitions and writable units."
        echo "3. \`10-security-controls.txt\` — security controls and privileged helpers."
        echo "4. \`06-processes.txt\` — process commands and exposed environment data."
        echo "5. Re-run without \`--quick\` for filesystem, credential, capability and container checks."
    else
        echo "1. \`13-suid-sgid-capabilities.txt\` — unusual privileged executables and capabilities."
        echo "2. \`14-writable-surfaces.txt\` — writable service, application and system paths."
        echo "3. \`09-schedules.txt\` — recurring jobs and writable scheduled scripts."
        echo "4. \`15-apps-configs.txt\` and \`16-credentials-artifacts.txt\` — credentials and application configuration."
        echo "5. \`17-containers.txt\` — privileged groups and container sockets."
    fi
    echo
    echo "## Recommended Next Steps"
    echo
    finding_number=0
    while IFS=$'\t' read -r priority finding evidence next_step; do
        [ "$priority" = "priority" ] && continue
        finding_number="$((finding_number + 1))"
        if [ "$finding_number" -eq 1 ]; then
            echo "**Best initial lead: $finding**"
            echo
        fi
        printf '%d. **%s — %s**  \n' "$finding_number" "$priority" "$finding"
        printf '   Evidence: `%s`  \n' "$evidence"
        printf '   Proceed: %s\n' "$next_step"
    done < "$FINDINGS_FILE"
    echo
    echo "## Identity"
    echo
    grep -E '^\$ (whoami|id|groups)|^uid=|^[A-Za-z0-9_.-]+$' "$OUTPUT_DIR/01-identity.txt" 2>/dev/null | head -n 20 || true
    echo
    echo "## Evidence Highlights"
    echo
    grep -hE '^(uid=|WRITABLE_|ROOT_OWNED_WRITABLE|WORLD_WRITABLE_(FILE|DIR)|--- readable: /etc/(shadow|gshadow)|--- NONSTANDARD_PRIVILEGED_EXECUTABLE|-[^[:space:]]*[sS][^[:space:]]*[[:space:]]|/[^[:space:]]+[[:space:]]+cap_[a-z_]+|/[^:]+:[0-9]+:.*(pass(word)?|secret|token|api.?key|credential|private.?key)|.*no_root_squash)' \
        "$OUTPUT_DIR/01-identity.txt" \
        "$OUTPUT_DIR/03-users-groups.txt" \
        "$OUTPUT_DIR/04-environment-path.txt" \
        "$OUTPUT_DIR/05-filesystems.txt" \
        "$OUTPUT_DIR/08-services.txt" \
        "$OUTPUT_DIR/09-schedules.txt" \
        "$OUTPUT_DIR/13-suid-sgid-capabilities.txt" \
        "$OUTPUT_DIR/14-writable-surfaces.txt" \
        "$OUTPUT_DIR/15-apps-configs.txt" \
        "$OUTPUT_DIR/16-credentials-artifacts.txt" \
        "$OUTPUT_DIR/17-containers.txt" \
        "$OUTPUT_DIR/18-custom-code.txt" 2>/dev/null | head -n 300 || true
    echo
    echo "## Section Status"
    echo
    echo '```text'
    cat "$OUTPUT_DIR/status.tsv"
    echo '```'
    echo
    echo "Raw output can contain credentials. Keep this directory private."
} > "$OUTPUT_DIR/summary.md"

printf '[100%%] Complete in %ss\n' "$ELAPSED"
printf 'Report directory: %s\n' "$OUTPUT_DIR"
printf 'Summary: %s/summary.md\n' "$OUTPUT_DIR"

