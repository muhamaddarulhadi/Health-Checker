#!/usr/bin/env bash
# =============================================================================
# Linux Server Health & Security Check
# Checks:
#   System ...... OS, kernel, uptime
#   CPU ......... usage (1s sample), load average
#   Memory ...... RAM (GB) and swap
#   Storage ..... every filesystem, inodes, read-only mounts, disk SMART health
#   Network ..... IP addresses, gateway, internet ping + latency + loss, DNS,
#                 interface errors, connection count
#   Open ports .. every listening port with its process, risky ports exposed
#   Security .... pending security updates (with package names), last update age,
#                 reboot needed, firewall, SSH root login,
#                 failed SSH logins (count, latest attempts, top source IPs)
#   Services .... failed units, zombies, time sync,
#                 recent error events in the system log (details)
#   Top processes by CPU and by memory
#
# Usage:  sudo bash healthcheck.sh            (root recommended for full info)
#         bash healthcheck.sh --quiet         (only WARN/FAIL lines)
#         bash healthcheck.sh --html          (also write an HTML report)
#         bash healthcheck.sh --html --out /var/www/html/health.html
#         bash healthcheck.sh --log ./health.log      (plain-text log)
# Exit code: 0 = all OK, 1 = warnings, 2 = failures
# =============================================================================

# ---------- Thresholds (edit to taste) ----------
CPU_WARN=80;  CPU_FAIL=95
MEM_WARN=80;  MEM_FAIL=95
SWAP_WARN=50; SWAP_FAIL=80
DISK_WARN=80; DISK_FAIL=90
INODE_WARN=80; INODE_FAIL=90
LOAD_WARN_FACTOR=1      # load per core
PING_TARGET="8.8.8.8"
DNS_TARGET="google.com"
SSH_FAIL_WARN=20        # failed SSH logins in last 24h
PING_WARN_MS=150        # warn if average ping is slower than this (ms)
PATCH_AGE_WARN_DAYS=35  # warn if no package update for this many days
SYSERR_WARN=20          # warn if more system-log errors than this in 24h
SHOW_LAST_N=5           # how many recent events / attempts to list
# ------------------------------------------------

QUIET=0; HTML=0; OUT=""; LOGFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --html)  HTML=1 ;;
    --out)   OUT="$2"; HTML=1; shift ;;
    --log)   LOGFILE="$2"; shift ;;
  esac
  shift
done
WARN=0; FAILS=0
SECTION="General"; RL=(); RS=(); RM=(); PORTS_TXT=""; TOP_TXT=""
SECLIST=(); MN=(); MV=(); MS=(); MD=(); LOGLINES=()
rec() { RL+=("$1"); RS+=("$SECTION"); RM+=("$2"); }
lg()  { LOGLINES+=("$1"); }

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; NC=$'\e[0m'; else G=; Y=; R=; B=; NC=; fi

ok()     { rec OK "$*";   lg "  [ OK ] $*";   [ $QUIET -eq 0 ] && printf "  ${G}[ OK ]${NC} %s\n" "$*"; }
warn()   { rec WARN "$*"; lg "  [WARN] $*";   printf "  ${Y}[WARN]${NC} %s\n" "$*"; WARN=$((WARN+1)); }
fail()   { rec FAIL "$*"; lg "  [FAIL] $*";   printf "  ${R}[FAIL]${NC} %s\n" "$*"; FAILS=$((FAILS+1)); }
info()   { rec INFO "$*"; lg "  [INFO] $*";   [ $QUIET -eq 0 ] && printf "  [INFO] %s\n" "$*"; }
detail() { rec INFO "$*"; lg "      - $*";    [ $QUIET -eq 0 ] && printf "      - %s\n" "$*"; }
hdr()    { SECTION="$*"; SECLIST+=("$*"); lg ""; lg "== $* =="; [ $QUIET -eq 0 ] && printf "\n${B}== %s ==${NC}\n" "$*"; }
# log (always) and print (unless --quiet) a block of text, indented
show_block() { local ind="$1"; shift; local l; while IFS= read -r l; do lg "${ind}${l}"; [ $QUIET -eq 0 ] && printf '%s%s\n' "$ind" "$l"; done <<< "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# remember a percentage metric for the "At a glance" gauges in the HTML report
# metric <label> <value> <warn> <fail> <detail>
metric() {
  local v=${2%.*} st=ok
  [ "$v" -ge "$4" ] && st=fail || { [ "$v" -ge "$3" ] && st=warn; }
  MN+=("$1"); MV+=("$v"); MS+=("$st"); MD+=("$5")
}

# level helper: lvl <value> <warn> <fail> <message>
lvl() {
  local v=${1%.*} w=$2 f=$3; shift 3
  if   [ "$v" -ge "$f" ]; then fail "$*"
  elif [ "$v" -ge "$w" ]; then warn "$*"
  else ok "$*"; fi
}

printf "${B}Health check: %s  |  Host: %s${NC}\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$(hostname)"
lg "Health check: $(date '+%Y-%m-%d %H:%M:%S')  |  Host: $(hostname)"
if [ "$(id -u)" -ne 0 ]; then
  echo "  (not root - some checks may be limited; try sudo)"
  lg "  (not root - some checks may be limited; try sudo)"
fi

# ---------- System ----------
hdr "SYSTEM"
[ -r /etc/os-release ] && info "OS: $(. /etc/os-release; echo "$PRETTY_NAME")"
info "Kernel: $(uname -r)"
info "Uptime: $(uptime -p 2>/dev/null || uptime)"

# ---------- CPU ----------
hdr "CPU"
CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
info "Cores: $CORES"
# CPU usage sampled over 1 second from /proc/stat
read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat
sleep 1
read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
t1=$((u1+n1+s1+i1+w1+q1+sq1+st1)); t2=$((u2+n2+s2+i2+w2+q2+sq2+st2))
dt=$((t2-t1)); di=$(( (i2+w2) - (i1+w1) ))
CPU_USE=$(( dt>0 ? (100*(dt-di))/dt : 0 ))
lvl "$CPU_USE" $CPU_WARN $CPU_FAIL "CPU usage: ${CPU_USE}%"
metric "CPU" "$CPU_USE" $CPU_WARN $CPU_FAIL "$CORES cores"
read -r L1 L5 L15 _ < /proc/loadavg
LOAD_LIMIT=$(awk -v c="$CORES" -v f="$LOAD_WARN_FACTOR" 'BEGIN{print c*f}')
if awk -v l="$L5" -v m="$LOAD_LIMIT" 'BEGIN{exit !(l>m)}'; then
  warn "Load avg (1/5/15m): $L1 $L5 $L15  (> $LOAD_LIMIT)"
else
  ok "Load avg (1/5/15m): $L1 $L5 $L15"
fi

# ---------- Memory ----------
hdr "MEMORY"
MEM_TOTAL=$(awk '/MemTotal/{print $2}' /proc/meminfo)
MEM_AVAIL=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
MEM_USED_PCT=$(( 100*(MEM_TOTAL-MEM_AVAIL)/MEM_TOTAL ))
MEM_USED_GB=$(LC_ALL=C awk -v t="$MEM_TOTAL" -v a="$MEM_AVAIL" 'BEGIN{printf "%.2f", (t-a)/1048576}')
MEM_TOTAL_GB=$(LC_ALL=C awk -v t="$MEM_TOTAL" 'BEGIN{printf "%.2f", t/1048576}')
lvl "$MEM_USED_PCT" $MEM_WARN $MEM_FAIL "RAM used: ${MEM_USED_PCT}% (${MEM_USED_GB} GB of ${MEM_TOTAL_GB} GB)"
metric "RAM" "$MEM_USED_PCT" $MEM_WARN $MEM_FAIL "${MEM_USED_GB} GB of ${MEM_TOTAL_GB} GB"
SW_TOTAL=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
SW_FREE=$(awk '/SwapFree/{print $2}' /proc/meminfo)
if [ "${SW_TOTAL:-0}" -gt 0 ]; then
  SW_PCT=$(( 100*(SW_TOTAL-SW_FREE)/SW_TOTAL ))
  lvl "$SW_PCT" $SWAP_WARN $SWAP_FAIL "Swap used: ${SW_PCT}%"
  metric "Swap" "$SW_PCT" $SWAP_WARN $SWAP_FAIL ""
else
  info "No swap configured"
fi

# ---------- Disk ----------
hdr "STORAGE"
while read -r fs size used avail pct mount; do
  p=${pct%\%}
  lvl "$p" $DISK_WARN $DISK_FAIL "Disk $mount: ${pct} used ($used / $size, $avail free) [$fs]"
  metric "Disk $mount" "$p" $DISK_WARN $DISK_FAIL "$avail free of $size"
done < <(df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
while read -r fs inodes iused ifree ipct mount; do
  [ "$ipct" = "-" ] && continue
  p=${ipct%\%}
  case "$p" in ''|*[!0-9]*) continue;; esac
  lvl "$p" $INODE_WARN $INODE_FAIL "Inodes $mount: ${ipct} used"
done < <(df -iP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
# physical disk health (needs smartmontools and root)
if have smartctl && [ "$(id -u)" -eq 0 ]; then
  for dev in $(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk"{print "/dev/"$1}'); do
    case "$dev" in /dev/loop*|/dev/ram*|/dev/zram*) continue;; esac
    out=$(smartctl -H "$dev" 2>/dev/null)
    if   echo "$out" | grep -qiE 'PASSED|OK$'; then ok "Disk health $dev (SMART): PASSED"
    elif echo "$out" | grep -qi 'FAILED';       then fail "Disk health $dev (SMART): FAILED"
    fi
  done
else
  have smartctl || info "Disk SMART health skipped (install smartmontools to enable)"
fi
# read-only filesystems (sign of disk errors)
RO=$(awk '$4 ~ /(^|,)ro(,|$)/ && $3 ~ /^(ext[234]|xfs|btrfs)$/ {print $2}' /proc/mounts)
RO=$(echo $RO)
[ -n "$RO" ] && fail "Read-only filesystem(s): $RO" || ok "No read-only filesystems"

# ---------- Network ----------
hdr "NETWORK"
if have ip; then
  IPS=$(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); printf "%s%s", (n++?", ":""), a[1]}')
  [ -n "$IPS" ] && info "IP address(es): $IPS"
  while read -r ifn ifaddr; do info "Interface $ifn: $ifaddr"; done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2, $4}')
  GW=$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')
else
  GW=
fi
if [ -n "$GW" ]; then
  if have ping && ping -c1 -W2 "$GW" >/dev/null 2>&1; then ok "Gateway $GW reachable"; else warn "Gateway $GW not reachable"; fi
else
  warn "No default gateway"
fi
if have ping; then
  PING_OUT=$(ping -c4 -W2 "$PING_TARGET" 2>/dev/null)
  PING_RX=$(echo "$PING_OUT" | sed -nE 's/.* ([0-9]+) (packets )?received.*/\1/p' | head -1)
  PING_AVG=$(echo "$PING_OUT" | awk -F'/' '/^(rtt|round-trip)/{printf "%d", $5+0.5}')
  if [ -n "$PING_RX" ] && [ "$PING_RX" -gt 0 ]; then
    if   [ "$PING_RX" -lt 4 ]; then warn "Internet ($PING_TARGET): packet loss, $PING_RX of 4 replies, avg ${PING_AVG} ms"
    elif [ "${PING_AVG:-0}" -ge "$PING_WARN_MS" ]; then warn "Internet reachable ($PING_TARGET) but slow: avg ${PING_AVG} ms (limit $PING_WARN_MS ms)"
    else ok "Internet reachable ($PING_TARGET), avg ${PING_AVG} ms"; fi
  else
    fail "Internet NOT reachable ($PING_TARGET)"
  fi
fi
if have getent; then
  if getent hosts "$DNS_TARGET" >/dev/null 2>&1; then ok "DNS resolves $DNS_TARGET"; else fail "DNS resolution failed for $DNS_TARGET"; fi
fi
# established connections
if have ss; then info "Established TCP connections: $(ss -tanH state established 2>/dev/null | wc -l)"; fi
# interface errors / drops
for d in /sys/class/net/*; do
  n=$(basename "$d"); [ "$n" = "lo" ] && continue
  e=$(( $(cat "$d/statistics/rx_errors" 2>/dev/null || echo 0) + $(cat "$d/statistics/tx_errors" 2>/dev/null || echo 0) ))
  dr=$(( $(cat "$d/statistics/rx_dropped" 2>/dev/null || echo 0) + $(cat "$d/statistics/tx_dropped" 2>/dev/null || echo 0) ))
  [ "$e" -gt 0 ] || [ "$dr" -gt 0 ] && warn "Interface $n: $e errors, $dr dropped packets"
done

# ---------- Open ports ----------
hdr "OPEN PORTS (listening)"
if have ss; then
  PORTS_TXT=$(printf "%-6s %-28s %s\n" "PROTO" "ADDRESS:PORT" "PROCESS"
  ss -tulnpH 2>/dev/null | awk '{
      proto=$1; addr=$5; proc=$NF; if (proc !~ /users:/) proc="-";
      gsub(/users:\(\("/,"",proc); gsub(/".*/,"",proc);
      printf "%-6s %-28s %s\n", proto, addr, proc }' | sort -u)
  LISTEN_N=$(ss -tlnH 2>/dev/null | wc -l)
  PUB=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]|::1)' | wc -l)
  info "Listening TCP endpoints: $LISTEN_N ($PUB reachable beyond localhost)"
  show_block "  " "$PORTS_TXT"
  info "UDP endpoints exposed: $(ss -ulnH 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]|::1)' | wc -l)"
  # commonly-attacked services listening on the network
  RISKY="21 23 111 139 445 2375 3306 3389 5432 5900 6379 9200 11211 27017"
  EXPOSED_PORTS=$(ss -tlnH 2>/dev/null | awk '{a=$4; p=a; sub(/.*:/,"",p); h=a; sub(/:[^:]*$/,"",h); if (h !~ /^(127\.|\[?::1\]?$)/) print p}' | sort -un)
  RISKY_HIT=""
  for rp in $RISKY; do echo "$EXPOSED_PORTS" | grep -qx "$rp" && RISKY_HIT="$RISKY_HIT$rp "; done
  if [ -n "$RISKY_HIT" ]; then
    warn "Sensitive ports listening on network: ${RISKY_HIT% }  (21 FTP, 23 Telnet, 111 rpcbind, 139/445 SMB, 2375 Docker API, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 5900 VNC, 6379 Redis, 9200 Elasticsearch, 11211 Memcached, 27017 MongoDB)"
  else
    ok "No commonly-attacked ports exposed"
  fi
elif have netstat; then
  netstat -tulnp 2>/dev/null | sed 's/^/  /'
else
  warn "Neither ss nor netstat found"
fi

# ---------- Security updates ----------
hdr "SECURITY UPDATES"
if have apt-get; then
  # simulate upgrade, count packages from *-security pockets
  SEC=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst.*[Ss]ecurity')
  ALL=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
  if [ "$SEC" -gt 0 ]; then
    fail "$SEC security update(s) pending ($ALL total updates)"
    while read -r pkg; do detail "$pkg"; done < <(apt-get -s upgrade 2>/dev/null | grep '^Inst.*[Ss]ecurity' | awk '{print $2}' | head -10)
  else
    ok "No pending security updates ($ALL other updates)"
  fi
  info "Tip: run 'apt-get update' first for fresh data"
elif have dnf; then
  OUT=$(dnf -q updateinfo list security 2>/dev/null | grep -E '^[A-Z]+-[0-9]+' | wc -l)
  [ "$OUT" -gt 0 ] && fail "$OUT security advisory update(s) pending" || ok "No pending security updates"
elif have yum; then
  OUT=$(yum -q updateinfo list security 2>/dev/null | grep -cE '^[A-Z]+-[0-9]+')
  [ "$OUT" -gt 0 ] && fail "$OUT security advisory update(s) pending" || ok "No pending security updates"
elif have zypper; then
  OUT=$(zypper -q lp --category security 2>/dev/null | grep -c '|')
  [ "$OUT" -gt 0 ] && fail "Security patches pending (see: zypper lp --category security)" || ok "No pending security patches"
else
  warn "No supported package manager found (apt/dnf/yum/zypper)"
fi
# age of the last package update
LAST_EPOCH=""
if have apt-get; then
  LAST_DATE=$(grep -h -E ' (upgrade|install) ' /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null | tail -1 | awk '{print $1" "$2}')
  [ -n "$LAST_DATE" ] && LAST_EPOCH=$(date -d "$LAST_DATE" +%s 2>/dev/null)
elif have rpm; then
  LAST_DATE=$(rpm -qa --last 2>/dev/null | head -1 | sed -E 's/^[^ ]+ +//')
  [ -n "$LAST_DATE" ] && LAST_EPOCH=$(date -d "$LAST_DATE" +%s 2>/dev/null)
fi
if [ -n "$LAST_EPOCH" ]; then
  AGE_DAYS=$(( ( $(date +%s) - LAST_EPOCH ) / 86400 ))
  if [ "$AGE_DAYS" -gt "$PATCH_AGE_WARN_DAYS" ]; then warn "Last package update $AGE_DAYS days ago ($(date -d @"$LAST_EPOCH" +%Y-%m-%d))"
  else ok "Last package update $AGE_DAYS days ago ($(date -d @"$LAST_EPOCH" +%Y-%m-%d))"; fi
else
  info "Last package update date unavailable"
fi
# reboot required
if [ -f /var/run/reboot-required ]; then warn "Reboot required (kernel/library update)";
elif have needs-restarting && ! needs-restarting -r >/dev/null 2>&1; then warn "Reboot required";
else ok "No reboot pending"; fi
# unattended upgrades
if have systemctl; then
  systemctl is-enabled unattended-upgrades >/dev/null 2>&1 && info "unattended-upgrades enabled" || \
  systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 && info "dnf-automatic enabled"
fi

# ---------- Services ----------
hdr "SERVICES & TIME"
if have systemctl; then
  FAILED=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}')
  if [ -n "$FAILED" ]; then fail "Failed systemd units: $(echo $FAILED | tr '\n' ' ')"; else ok "No failed systemd units"; fi
fi
Z=$(ps -eo stat= 2>/dev/null | grep -c '^Z')
[ "$Z" -gt 0 ] && warn "$Z zombie process(es)" || ok "No zombie processes"
# time sync
if have timedatectl; then
  timedatectl 2>/dev/null | grep -qiE 'synchronized: yes|NTP synchronized: yes' && ok "Clock synchronized (NTP)" || warn "Clock NOT synchronized"
fi
# recent error events in the system log
if have journalctl; then
  SYSERR=$(journalctl -p err --since "24 hours ago" --no-pager -q -o short-iso 2>/dev/null | grep -v '^-- ')
  SYSERR_N=$(printf '%s' "$SYSERR" | grep -c .)
  if [ "$SYSERR_N" -gt "$SYSERR_WARN" ]; then warn "$SYSERR_N error events in the system log (24h)"; else ok "$SYSERR_N error events in the system log (24h)"; fi
  if [ "$SYSERR_N" -gt 0 ]; then
    while IFS= read -r line; do
      detail "$(printf '%s' "$line" | sed -E 's/^([^ ]+) [^ ]+ ([^:]+): (.*)$/\1  [\2] \3/' | cut -c1-170)"
    done < <(printf '%s\n' "$SYSERR" | tail -n "$SHOW_LAST_N" | tac)
  fi
else
  info "journalctl not available: system-log error check skipped"
fi

# ---------- Security posture ----------
hdr "SECURITY"
if have ufw; then
  ufw status 2>/dev/null | grep -q "Status: active" && ok "Firewall (ufw) active" || warn "Firewall (ufw) inactive"
elif have firewall-cmd; then
  firewall-cmd --state >/dev/null 2>&1 && ok "Firewall (firewalld) running" || warn "Firewall (firewalld) not running"
elif have iptables; then
  N=$(iptables -S 2>/dev/null | wc -l)
  [ "$N" -gt 3 ] && ok "iptables has rules ($N)" || warn "iptables has no rules / no firewall detected"
else
  warn "No firewall tool detected"
fi
# failed SSH logins in last 24h: count, latest attempts, top source IPs
SSH_LINES=""; SSH_SRC=""
if have journalctl && journalctl -u ssh -u sshd --since "24 hours ago" --no-pager -q >/dev/null 2>&1; then
  SSH_LINES=$(journalctl -u ssh -u sshd --since "24 hours ago" --no-pager -q -o short-iso 2>/dev/null | grep "Failed password"); SSH_SRC=1
elif [ -r /var/log/auth.log ]; then
  SSH_LINES=$(grep "Failed password" /var/log/auth.log); SSH_SRC=1
elif [ -r /var/log/secure ]; then
  SSH_LINES=$(grep "Failed password" /var/log/secure); SSH_SRC=1
fi
if [ -n "$SSH_SRC" ]; then
  SSH_FAILS=$(printf '%s' "$SSH_LINES" | grep -c .)
  if [ "$SSH_FAILS" -ge "$SSH_FAIL_WARN" ]; then warn "$SSH_FAILS failed SSH logins (24h) - possible brute force"; else ok "$SSH_FAILS failed SSH logins (24h)"; fi
  if [ "$SSH_FAILS" -gt 0 ]; then
    PARSED=$(printf '%s\n' "$SSH_LINES" | sed -nE 's/^(.*) [^ ]+ sshd(-session)?\[[0-9]+\]: Failed password for (invalid user )?([^ ]+) from ([^ ]+).*/\1|\4|\5/p')
    while IFS='|' read -r t u ip; do detail "$t  user: $u  from: $ip"; done < <(printf '%s\n' "$PARSED" | tail -n "$SHOW_LAST_N" | tac)
    TOPIPS=$(printf '%s\n' "$PARSED" | awk -F'|' 'NF>=3{print $3}' | sort | uniq -c | sort -rn | head -3 | awk '{printf "%s%s (%s)", (n++?", ":""), $2, $1}')
    [ -n "$TOPIPS" ] && detail "Top source IPs: $TOPIPS"
  fi
fi
# root SSH login
if [ -r /etc/ssh/sshd_config ]; then
  grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config >/dev/null 2>&1 && warn "SSH PermitRootLogin is 'yes'"
fi

# ---------- Top processes ----------
hdr "TOP PROCESSES"
TOP_TXT=$(echo "By CPU:"; ps -eo pid,comm,%cpu --sort=-%cpu 2>/dev/null | head -6
          echo; echo "By MEM:"; ps -eo pid,comm,%mem --sort=-%mem 2>/dev/null | head -6)
show_block "  " "$TOP_TXT"

# ---------- HTML report ----------
esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
e()   { printf '%s' "$1" | esc; }
make_html() {
  local f="$1" title="SERVER HEALTH &amp; SECURITY DIAGNOSTIC REPORT"
  local nPass nTotal status sclass osname runas now host i n lv name nf nw no cls badges
  host=$(hostname); now=$(date '+%Y-%m-%d %H:%M:%S')
  osname=$( [ -r /etc/os-release ] && . /etc/os-release && echo "$PRETTY_NAME" || uname -sr )
  [ "$(id -u)" -eq 0 ] && runas="root" || runas="Standard user"
  nPass=$(printf '%s\n' "${RL[@]}" | grep -c '^OK$')
  nTotal=$((nPass + WARN + FAILS))
  local pPass pWarn pFail score c2
  read -r pPass pWarn pFail score c2 < <(LC_ALL=C awk -v p="$nPass" -v w="$WARN" -v f="$FAILS" 'BEGIN{
      t=p+w+f; if(t==0){print "100.0 0.0 0.0 100 100.0"; exit}
      pp=int(1000*p/t+.5)/10; pw=int(1000*w/t+.5)/10; pf=100-pp-pw; if(pf<0)pf=0;
      printf "%.1f %.1f %.1f %d %.1f\n", pp, pw, pf, int(100*p/t+.5), pp+pw }')
  if   [ $FAILS -gt 0 ]; then status="UNHEALTHY"; sclass="s-unhealthy"
  elif [ $WARN  -gt 0 ]; then status="DEGRADED";  sclass="s-degraded"
  else                        status="HEALTHY";   sclass="s-healthy"; fi
  {
    printf '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    printf '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">'
    printf '<title>%s - %s</title><style>\n' "$title" "$(e "$host")"
    cat <<'HC_CSS'
:root{
  --bg:#f3f5ff;
  --bg-grad:radial-gradient(900px 500px at 5% -5%,#e0e7ff 0,transparent 60%),radial-gradient(800px 500px at 100% 0,#fce7f3 0,transparent 55%),radial-gradient(700px 500px at 50% 110%,#cffafe 0,transparent 55%);
  --card:#ffffff;--card2:#f8f9ff;--text:#0f172a;--muted:#5b667a;--line:#e3e7f5;
  --glass:rgba(255,255,255,.75);
  --shadow:0 1px 2px rgba(15,23,42,.05),0 8px 24px rgba(79,70,229,.08);
  --ok:#059669;--warn:#d97706;--fail:#e11d48;--info:#64748b;
  --ok-bg:#ecfdf5;--warn-bg:#fffbeb;--fail-bg:#fff1f2;
  --track:#e8ebf7;
}
:root[data-theme="dark"]{
  --bg:#0a0e1f;
  --bg-grad:radial-gradient(900px 500px at 5% -5%,rgba(99,102,241,.28) 0,transparent 60%),radial-gradient(800px 500px at 100% 0,rgba(236,72,153,.16) 0,transparent 55%),radial-gradient(700px 500px at 50% 110%,rgba(6,182,212,.14) 0,transparent 55%);
  --card:#131a33;--card2:#192142;--text:#e9edfb;--muted:#9aa6c4;--line:#26305a;
  --glass:rgba(19,26,51,.75);
  --shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
  --ok:#34d399;--warn:#fbbf24;--fail:#fb7185;--info:#94a3b8;
  --ok-bg:rgba(16,185,129,.12);--warn-bg:rgba(245,158,11,.12);--fail-bg:rgba(244,63,94,.14);
  --track:#222c57;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#0a0e1f;
    --bg-grad:radial-gradient(900px 500px at 5% -5%,rgba(99,102,241,.28) 0,transparent 60%),radial-gradient(800px 500px at 100% 0,rgba(236,72,153,.16) 0,transparent 55%),radial-gradient(700px 500px at 50% 110%,rgba(6,182,212,.14) 0,transparent 55%);
    --card:#131a33;--card2:#192142;--text:#e9edfb;--muted:#9aa6c4;--line:#26305a;--glass:rgba(19,26,51,.75);
    --shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
    --ok:#34d399;--warn:#fbbf24;--fail:#fb7185;--info:#94a3b8;
    --ok-bg:rgba(16,185,129,.12);--warn-bg:rgba(245,158,11,.12);--fail-bg:rgba(244,63,94,.14);--track:#222c57;
  }
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);background-image:var(--bg-grad);background-attachment:fixed;color:var(--text);line-height:1.55}
a{color:#6366f1}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}

/* top bar */
.topbar{position:sticky;top:0;z-index:50;background:var(--glass);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.topbar-in{max-width:1100px;margin:0 auto;padding:10px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:800}
.logo{width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#ec4899);display:grid;place-items:center;box-shadow:0 6px 16px rgba(99,102,241,.4)}
.logo svg{width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
.spacer{flex:1}
.seg{display:flex;background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:3px;gap:2px}
.seg button{border:0;background:transparent;color:var(--muted);padding:6px 14px;border-radius:999px;cursor:pointer;font-size:13px;font-weight:600;font-family:inherit}
.seg button.on{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;box-shadow:0 4px 12px rgba(99,102,241,.4)}
.iconbtn{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);background:var(--card2);color:var(--text);border-radius:999px;padding:7px 14px;cursor:pointer;font-size:13px;font-weight:600;font-family:inherit}
.iconbtn:hover{border-color:#6366f1}
.iconbtn svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
#themeBtn .sun{display:none}
:root[data-theme="dark"] #themeBtn .sun{display:block}
:root[data-theme="dark"] #themeBtn .moon{display:none}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]) #themeBtn .sun{display:block}
  :root:not([data-theme="light"]) #themeBtn .moon{display:none}
}

.wrap{max-width:1100px;margin:0 auto;padding:22px 16px 40px}

/* hero */
.hero{position:relative;overflow:hidden;border-radius:24px;padding:34px 36px;margin-bottom:22px;color:#fff;display:flex;gap:28px;align-items:center;justify-content:space-between;flex-wrap:wrap;box-shadow:0 22px 50px rgba(15,23,42,.25)}
.hero.s-healthy{background:linear-gradient(120deg,#047857,#10b981 55%,#06b6d4)}
.hero.s-degraded{background:linear-gradient(120deg,#b45309,#f59e0b 55%,#f97316)}
.hero.s-unhealthy{background:linear-gradient(120deg,#9f1239,#e11d48 55%,#f97316)}
.hero::before,.hero::after{content:"";position:absolute;border-radius:50%;filter:blur(40px);opacity:.45;pointer-events:none}
.hero::before{width:300px;height:300px;right:-70px;top:-100px;background:#fff}
.hero::after{width:240px;height:240px;left:35%;bottom:-150px;background:#fde68a;opacity:.3}
.hero>*{position:relative}
.hero-text{flex:1;min-width:260px}
.kicker{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.35);padding:5px 12px;border-radius:999px;margin-bottom:14px}
.hero h1{margin:0 0 12px;font-size:clamp(24px,4.2vw,38px);line-height:1.12;letter-spacing:-.01em;font-weight:800;text-transform:uppercase}
.statuspill{display:inline-flex;align-items:center;gap:10px;background:rgba(255,255,255,.95);color:#0f172a;font-weight:800;letter-spacing:.06em;padding:8px 18px;border-radius:999px;font-size:15px;box-shadow:0 8px 20px rgba(0,0,0,.18)}
.statuspill i{width:12px;height:12px;border-radius:50%;background:currentColor;box-shadow:0 0 0 4px rgba(0,0,0,.08)}
.s-healthy .statuspill{color:#047857}.s-degraded .statuspill{color:#b45309}.s-unhealthy .statuspill{color:#be123c}
.metaline{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.meta{display:inline-flex;gap:6px;align-items:center;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.3);padding:5px 12px;border-radius:999px;font-size:13px}
.meta b{font-weight:700}
.ring{width:150px;height:150px;border-radius:50%;display:grid;place-items:center;flex:none;box-shadow:0 10px 30px rgba(0,0,0,.25)}
.ring-in{width:112px;height:112px;border-radius:50%;background:rgba(15,23,42,.82);display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff}
.ring-in b{font-size:30px;line-height:1}
.ring-in span{font-size:11px;letter-spacing:.1em;text-transform:uppercase;opacity:.8;margin-top:4px}

/* stat cards */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:22px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px 18px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--c)}
.stat b{display:block;font-size:32px;line-height:1.1;color:var(--c)}
.stat span{color:var(--muted);font-size:13px;font-weight:600}
.stat.f{--c:var(--fail)}.stat.w{--c:var(--warn)}.stat.p{--c:var(--ok)}.stat.i{--c:#6366f1}
.stackbar{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--track);margin-bottom:22px;box-shadow:var(--shadow)}
.stackbar i{display:block;height:100%}
.stackbar .p{background:#10b981}.stackbar .w{background:#f59e0b}.stackbar .f{background:#f43f5e}

/* section titles */
.title{display:flex;align-items:center;gap:10px;margin:26px 2px 12px;font-size:13px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.title::after{content:"";flex:1;height:1px;background:var(--line)}

/* gauges */
.gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.gauge{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px 18px;box-shadow:var(--shadow)}
.gauge .top{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.gauge .lbl{font-weight:700;font-size:14px}
.gauge .val{font-weight:800;font-size:24px}
.gauge .sub{color:var(--muted);font-size:12px;margin-top:2px;min-height:18px}
.bar{height:10px;border-radius:999px;background:var(--track);margin-top:10px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:999px}
.gauge.ok .val{color:var(--ok)}.gauge.ok .bar i{background:linear-gradient(90deg,#34d399,#10b981)}
.gauge.warn .val{color:var(--warn)}.gauge.warn .bar i{background:linear-gradient(90deg,#fbbf24,#f59e0b)}
.gauge.fail .val{color:var(--fail)}.gauge.fail .bar i{background:linear-gradient(90deg,#fb7185,#e11d48)}

/* summary of issues */
.sumwrap{background:var(--card);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);overflow-x:auto}
.sumtbl{width:100%;border-collapse:collapse;font-size:14px}
.sumtbl th{background:var(--card2);text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:11px 16px}
.sumtbl td{padding:11px 16px;border-top:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.sumtbl td.n{width:44px;color:var(--muted);font-weight:700}
.sumtbl td.sn{white-space:nowrap;font-weight:700;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted)}
.sumtbl .pill{display:inline-block;white-space:nowrap;min-width:58px;text-align:center;font-size:11px;font-weight:800;letter-spacing:.05em;border-radius:999px;padding:3px 10px;color:#fff}
.sumtbl tr.FAIL{background:var(--fail-bg)}.sumtbl tr.FAIL .pill{background:var(--fail)}
.sumtbl tr.WARN{background:var(--warn-bg)}.sumtbl tr.WARN .pill{background:var(--warn)}
.sumhead{display:flex;align-items:center;gap:12px}
.sumhead .title{flex:1}
.sumhead .iconbtn{margin-top:14px;flex:none}
.sumok{text-align:center;padding:22px;border:2px dashed var(--line);border-radius:18px;color:var(--ok);font-weight:700}

/* sections */
.sec{background:var(--card);border:1px solid var(--line);border-radius:18px;margin-bottom:14px;box-shadow:var(--shadow);overflow:hidden}
.sec>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;padding:14px 18px;font-weight:800;letter-spacing:.03em;text-transform:uppercase;font-size:14px;user-select:none}
.sec>summary::-webkit-details-marker{display:none}
.sec>summary::after{content:"";margin-left:auto;width:9px;height:9px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .2s;flex:none}
.sec[open]>summary::after{transform:rotate(-135deg)}
.sec .ico{width:34px;height:34px;border-radius:11px;flex:none;display:grid;place-items:center;background:linear-gradient(135deg,#6366f1,#8b5cf6)}
.sec .ico svg{width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.sec.has-warn .ico{background:linear-gradient(135deg,#f59e0b,#f97316)}
.sec.has-fail .ico{background:linear-gradient(135deg,#f43f5e,#e11d48)}
.sec.clean .ico{background:linear-gradient(135deg,#10b981,#06b6d4)}
.cnts{display:flex;gap:6px;margin-left:6px}
.cnt{font-size:11px;font-weight:800;padding:2px 9px;border-radius:999px;letter-spacing:.03em;text-transform:none}
.cnt.f{background:var(--fail-bg);color:var(--fail)}.cnt.w{background:var(--warn-bg);color:var(--warn)}.cnt.o{background:var(--ok-bg);color:var(--ok)}
.row{display:flex;gap:14px;align-items:flex-start;padding:10px 18px;border-top:1px solid var(--line);font-size:14px}
.row .pill{flex:none;min-width:58px;text-align:center;font-size:11px;font-weight:800;letter-spacing:.05em;border-radius:999px;padding:3px 10px;margin-top:1px}
.row .msg{flex:1;min-width:0;overflow-wrap:anywhere}
.row.OK .pill{background:var(--ok-bg);color:var(--ok)}
.row.WARN{background:var(--warn-bg)}.row.WARN .pill{background:var(--warn);color:#fff}
.row.FAIL{background:var(--fail-bg)}.row.FAIL .pill{background:var(--fail);color:#fff}
.row.INFO .pill{background:var(--card2);color:var(--info);border:1px solid var(--line)}
.row.INFO .msg{color:var(--muted);font-size:13.5px}
.tbl{padding:4px 18px 16px;border-top:1px solid var(--line);overflow-x:auto}
.tbl h3{font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:14px 0 6px}
.tbl table{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:12px;overflow:hidden;font-size:13px}
.tbl th{background:var(--card2);text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.tbl th,.tbl td{padding:8px 12px;border-bottom:1px solid var(--line)}
.tbl tr:last-child td{border-bottom:0}
.tbl tr:hover td{background:var(--card2)}
.tag-net{color:#fff;background:#f59e0b;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:800}
.tag-local{color:var(--muted);background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:2px 9px;font-size:11px;font-weight:700}
pre.mono{margin:0;font-size:12.5px;line-height:1.5;white-space:pre;overflow:auto;background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.issues-only .row.OK,.issues-only .row.INFO,.issues-only .tbl,.issues-only .sec.clean{display:none}
.empty{display:none;text-align:center;padding:26px;border:2px dashed var(--line);border-radius:18px;color:var(--ok);font-weight:700}
.issues-only.no-issues .empty{display:block}

footer{color:var(--muted);font-size:12px;text-align:center;padding:26px 14px 6px}
footer .credit{display:inline-flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:center;font-size:14px}
footer a.gh{display:inline-flex;align-items:center;gap:8px;padding:7px 16px 7px 12px;border-radius:999px;border:1px solid var(--line);background:var(--card);color:var(--text);text-decoration:none;font-weight:700;box-shadow:var(--shadow)}
footer a.gh:hover{border-color:#6366f1;color:#6366f1}
footer a.gh svg{width:19px;height:19px}
footer .sub{margin-top:10px;font-size:12px}

@media (max-width:640px){
  .hero{padding:26px 22px}
  .ring{width:120px;height:120px}.ring-in{width:90px;height:90px}.ring-in b{font-size:24px}
  .brand span{display:none}
}

/* print: always light, everything expanded */
@page{size:A4;margin:11mm}
@media print{
  :root,:root[data-theme="dark"]{--bg:#fff;--bg-grad:none;--card:#fff;--card2:#f6f7fb;--text:#0f172a;--muted:#475569;--line:#d9deea;--shadow:none;--ok:#047857;--warn:#b45309;--fail:#be123c;--info:#475569;--ok-bg:#ecfdf5;--warn-bg:#fffbeb;--fail-bg:#fff1f2;--track:#e5e8f2}
  body{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact;font-size:11.5px}
  .topbar,.empty{display:none!important}
  .wrap{max-width:none;padding:0}
  .hero{box-shadow:none;padding:22px 24px;border-radius:16px}
  .hero::before,.hero::after{display:none}
  .ring{box-shadow:none}
  .stat,.gauge,.sec{box-shadow:none}
  .row,.gauge,.stat,.tbl tr{break-inside:avoid;page-break-inside:avoid}
  .sec{break-inside:auto}
  .sumtbl tr{break-inside:avoid;page-break-inside:avoid}
  .sumwrap{box-shadow:none}
  .sumhead .iconbtn{display:none}
  .sec>summary,.title{break-after:avoid;page-break-after:avoid}
  .stats{grid-template-columns:repeat(4,1fr)}
  .gauges{grid-template-columns:repeat(3,1fr)}
  .sec>summary::after{display:none}
  .issues-only .row.OK,.issues-only .row.INFO,.issues-only .tbl,.issues-only .sec.clean{display:flex}
  .issues-only .tbl{display:block}
}
HC_CSS
    printf '</style></head><body>\n'
    cat <<'HC_TOP'
<header class="topbar noprint"><div class="topbar-in">
<div class="brand"><div class="logo"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></div><span>Health Check</span></div>
<div class="spacer"></div>
<div class="seg" role="group" aria-label="Filter"><button type="button" data-f="all" class="on">All checks</button><button type="button" data-f="issues">Issues only</button></div>
<button class="iconbtn" id="themeBtn" type="button" aria-label="Toggle dark / light mode"><svg class="moon" viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg><svg class="sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg><span id="themeLabel">Dark</span></button>
<button class="iconbtn" type="button" onclick="window.print()" title="Print or save as PDF"><svg viewBox="0 0 24 24"><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>Save as PDF</button>
</div></header>
HC_TOP
    printf '<main class="wrap">\n'
    # ---- hero ----
    printf '<section class="hero %s"><div class="hero-text"><span class="kicker">Linux Server</span><h1>%s</h1>' "$sclass" "$title"
    printf '<span class="statuspill"><i></i>%s</span><div class="metaline">' "$status"
    printf '<span class="meta">Host <b>%s</b></span><span class="meta">OS <b>%s</b></span>' "$(e "$host")" "$(e "$osname")"
    printf '<span class="meta">Generated <b>%s</b></span><span class="meta">Run as <b>%s</b></span></div></div>' "$now" "$runas"
    printf '<div class="ring" style="background:conic-gradient(#10b981 0 %s%%, #f59e0b %s%% %s%%, #f43f5e %s%% 100%%)"><div class="ring-in"><b>%s%%</b><span>checks passed</span></div></div></section>\n' "$pPass" "$pPass" "$c2" "$c2" "$score"
    # ---- stat cards ----
    printf '<div class="stats"><div class="stat f"><b>%s</b><span>Failures</span></div><div class="stat w"><b>%s</b><span>Warnings</span></div><div class="stat p"><b>%s</b><span>Checks passed</span></div><div class="stat i"><b>%s</b><span>Checks run</span></div></div>\n' "$FAILS" "$WARN" "$nPass" "$nTotal"
    printf '<div class="stackbar" title="Passed / warnings / failures"><i class="p" style="width:%s%%"></i><i class="w" style="width:%s%%"></i><i class="f" style="width:%s%%"></i></div>\n' "$pPass" "$pWarn" "$pFail"
    # ---- gauges ----
    if [ ${#MN[@]} -gt 0 ]; then
      printf '<div class="title">At a glance</div><div class="gauges">\n'
      for i in "${!MN[@]}"; do
        w=${MV[$i]}; [ "$w" -gt 100 ] && w=100; [ "$w" -lt 0 ] && w=0
        printf '<div class="gauge %s"><div class="top"><span class="lbl">%s</span><span class="val">%s%%</span></div><div class="sub">%s</div><div class="bar"><i style="width:%s%%"></i></div></div>\n' "${MS[$i]}" "$(e "${MN[$i]}")" "${MV[$i]}" "$(e "${MD[$i]}")" "$w"
      done
      printf '</div>\n'
    fi
    # ---- summary of issues (failures first, then warnings) ----
    printf '<div class="sumhead"><div class="title">Summary of issues</div><button class="iconbtn" id="xlsBtn" type="button" title="Download the issues as an Excel file"><svg viewBox="0 0 24 24"><path d="M12 3v12M7 10l5 5 5-5M4 21h16"/></svg>Download Excel</button></div>\n'
    if [ $((WARN + FAILS)) -gt 0 ]; then
      printf '<div class="sumwrap"><table class="sumtbl"><thead><tr><th>#</th><th>Status</th><th>Section</th><th>Finding</th></tr></thead><tbody>\n'
      n=0
      for lv in FAIL WARN; do
        for i in "${!RL[@]}"; do
          [ "${RL[$i]}" = "$lv" ] || continue
          n=$((n+1))
          printf '<tr class="%s"><td class="n">%s</td><td><span class="pill">%s</span></td><td class="sn">%s</td><td>%s</td></tr>\n' "$lv" "$n" "$lv" "$(e "${RS[$i]}")" "$(e "${RM[$i]}")"
        done
      done
      printf '</tbody></table></div>\n'
    else
      printf '<div class="sumok">No warnings or failures. Everything looks healthy.</div>\n'
    fi
    # ---- sections ----
    printf '<div class="title">Detailed results</div>\n'
    for name in "${SECLIST[@]}"; do
      nf=0; nw=0; no=0
      for i in "${!RL[@]}"; do
        [ "${RS[$i]}" = "$name" ] || continue
        case "${RL[$i]}" in FAIL) nf=$((nf+1));; WARN) nw=$((nw+1));; OK) no=$((no+1));; esac
      done
      if [ $nf -gt 0 ]; then cls="has-fail"; elif [ $nw -gt 0 ]; then cls="has-warn"; else cls="clean"; fi
      badges=""
      [ $nf -gt 0 ] && badges="$badges<span class=\"cnt f\">$nf fail</span>"
      [ $nw -gt 0 ] && badges="$badges<span class=\"cnt w\">$nw warn</span>"
      [ $no -gt 0 ] && badges="$badges<span class=\"cnt o\">$no ok</span>"
      printf '<details class="sec %s" open data-name="%s"><summary><span class="ico"></span>%s<span class="cnts">%s</span></summary>\n' "$cls" "$(e "$name")" "$(e "$name")" "$badges"
      for i in "${!RL[@]}"; do
        [ "${RS[$i]}" = "$name" ] || continue
        printf '<div class="row %s"><span class="pill">%s</span><span class="msg">%s</span></div>\n' "${RL[$i]}" "${RL[$i]}" "$(e "${RM[$i]}")"
      done
      case "$name" in
        "OPEN PORTS"*)
          if [ -n "$PORTS_TXT" ]; then
            printf '<div class="tbl">'
            printf '%s\n' "$PORTS_TXT" | LC_ALL=C awk '
              function h(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
              NR==1{print "<table><tr><th>Proto</th><th>Address:Port</th><th>Exposed</th><th>Process</th></tr>";next}
              NF{x=($2 ~ /^(127\.|\[::1\]|::1)/)?"local":"NETWORK"; printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",h($1),h($2),x,h($3)}
              END{print "</table>"}'
            printf '</div>\n'
          fi ;;
        "TOP PROCESSES"*)
          [ -n "$TOP_TXT" ] && printf '<div class="tbl"><pre class="mono">%s</pre></div>\n' "$(printf '%s' "$TOP_TXT" | esc)" ;;
      esac
      printf '</details>\n'
    done
    printf '<div class="empty">No warnings or failures. Everything looks healthy.</div>\n'
    cat <<'HC_FOOT'
<footer>
<div class="credit"><span>Created by</span>
<a class="gh" href="https://github.com/muhamaddarulhadi" target="_blank" rel="noopener noreferrer"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>muhamaddarulhadi</a></div>
HC_FOOT
    printf '<div class="sub">Generated by healthcheck.sh</div></footer></main>\n<script>\n'
    cat <<'HC_JS'
(function(){
  var root=document.documentElement;
  var ICONS={
    cpu:'<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
    mem:'<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 7v10M10 7v10M14 7v10M18 7v10"/>',
    disk:'<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
    net:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    ports:'<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1"/><path d="M2 9a15 15 0 0 1 20 0"/>',
    shield:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    lock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    sliders:'<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
    list:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    monitor:'<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>'
  };
  function iconFor(n){
    n=n.toUpperCase();
    if(/CPU/.test(n))return 'cpu'; if(/MEMORY|RAM/.test(n))return 'mem'; if(/STORAGE|DISK/.test(n))return 'disk';
    if(/NETWORK/.test(n))return 'net'; if(/PORT/.test(n))return 'ports'; if(/UPDATE/.test(n))return 'shield';
    if(/SECURITY/.test(n))return 'lock'; if(/SERVICE/.test(n))return 'sliders'; if(/PROCESS/.test(n))return 'list';
    return 'monitor';
  }
  document.querySelectorAll('.sec').forEach(function(s){
    var ico=s.querySelector('.ico'); if(!ico)return;
    ico.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true">'+ICONS[iconFor(s.getAttribute('data-name')||'')]+'</svg>';
  });
  document.querySelectorAll('.tbl td').forEach(function(td){
    var t=td.textContent.trim();
    if(t==='NETWORK'){td.innerHTML='<span class="tag-net">NETWORK</span>';}
    else if(t==='local'){td.innerHTML='<span class="tag-local">local</span>';}
  });

  /* theme */
  var btn=document.getElementById('themeBtn'), lbl=document.getElementById('themeLabel');
  var mq=window.matchMedia?window.matchMedia('(prefers-color-scheme: dark)'):null;
  function cur(){var t=root.getAttribute('data-theme'); if(t)return t; return (mq&&mq.matches)?'dark':'light';}
  function paint(){ if(lbl) lbl.textContent=(cur()==='dark')?'Light':'Dark'; }
  try{var saved=localStorage.getItem('hc-report-theme'); if(saved==='light'||saved==='dark')root.setAttribute('data-theme',saved);}catch(e){}
  if(btn)btn.addEventListener('click',function(){
    var next=(cur()==='dark')?'light':'dark';
    root.setAttribute('data-theme',next);
    try{localStorage.setItem('hc-report-theme',next);}catch(e){}
    paint();
  });
  paint();

  /* filter */
  var fb=document.querySelectorAll('.seg button');
  var hasIssues=document.querySelectorAll('.row.WARN,.row.FAIL').length>0;
  if(!hasIssues)document.body.classList.add('no-issues');
  fb.forEach(function(b){b.addEventListener('click',function(){
    fb.forEach(function(x){x.classList.toggle('on',x===b);});
    document.body.classList.toggle('issues-only',b.getAttribute('data-f')==='issues');
  });});

  /* download the summary of issues as an Excel (.xlsx) file - built in the browser, no libraries */
  (function(){
    var xb=document.getElementById('xlsBtn'); if(!xb)return;
    if(!document.querySelector('.sumtbl')){xb.style.display='none';return;}
    var enc=new TextEncoder();
    var crcT=(function(){var t=[],c,n,k;for(n=0;n<256;n++){c=n;for(k=0;k<8;k++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);t[n]=c>>>0;}return t;})();
    function crc32(b){var c=0xFFFFFFFF;for(var i=0;i<b.length;i++)c=crcT[(c^b[i])&255]^(c>>>8);return (c^0xFFFFFFFF)>>>0;}
    function xe(s){return String(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
    function cs(ref,st,text){return '<c r="'+ref+'" s="'+st+'" t="inlineStr"><is><t xml:space="preserve">'+xe(text)+'</t></is></c>';}
    function cn(ref,st,num){return '<c r="'+ref+'" s="'+st+'"><v>'+num+'</v></c>';}
    function ce(ref,st){return '<c r="'+ref+'" s="'+st+'"/>';}
    function zip(files){
      var parts=[],central=[],off=0,i,name,data,crc,h,dv,c,cv,d=new Date();
      var dt=((d.getHours()<<11)|(d.getMinutes()<<5)|(d.getSeconds()>>1))&0xFFFF;
      var dd=(((d.getFullYear()-1980)<<9)|((d.getMonth()+1)<<5)|d.getDate())&0xFFFF;
      for(i=0;i<files.length;i++){
        name=enc.encode(files[i][0]); data=enc.encode(files[i][1]); crc=crc32(data);
        h=new Uint8Array(30+name.length); dv=new DataView(h.buffer);
        dv.setUint32(0,0x04034b50,true);dv.setUint16(4,20,true);dv.setUint16(6,0x0800,true);dv.setUint16(8,0,true);
        dv.setUint16(10,dt,true);dv.setUint16(12,dd,true);dv.setUint32(14,crc,true);dv.setUint32(18,data.length,true);dv.setUint32(22,data.length,true);
        dv.setUint16(26,name.length,true);dv.setUint16(28,0,true);h.set(name,30);
        parts.push(h,data);
        c=new Uint8Array(46+name.length); cv=new DataView(c.buffer);
        cv.setUint32(0,0x02014b50,true);cv.setUint16(4,20,true);cv.setUint16(6,20,true);cv.setUint16(8,0x0800,true);cv.setUint16(10,0,true);
        cv.setUint16(12,dt,true);cv.setUint16(14,dd,true);cv.setUint32(16,crc,true);cv.setUint32(20,data.length,true);cv.setUint32(24,data.length,true);
        cv.setUint16(28,name.length,true);cv.setUint32(42,off,true);
        c.set(name,46);central.push(c);
        off+=h.length+data.length;
      }
      var csz=0; central.forEach(function(x){csz+=x.length;});
      var e=new Uint8Array(22),ev=new DataView(e.buffer);
      ev.setUint32(0,0x06054b50,true);ev.setUint16(8,files.length,true);ev.setUint16(10,files.length,true);ev.setUint32(12,csz,true);ev.setUint32(16,off,true);
      return new Blob(parts.concat(central,[e]),{type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
    }
    xb.addEventListener('click',function(){
      var heads=['#','Status','Section','Finding','Solution','Date Solved'];
      var L=['A','B','C','D','E','F'];
      var trs=document.querySelectorAll('.sumtbl tbody tr');
      var x='<row r="1" ht="24" customHeight="1">';
      heads.forEach(function(h,k){x+=cs(L[k]+'1',1,h);});
      x+='</row>';
      for(var i=0;i<trs.length;i++){
        var r=i+2, td=trs[i].querySelectorAll('td'), st=td[1].textContent.trim();
        x+='<row r="'+r+'">'+cn('A'+r,2,parseInt(td[0].textContent,10)||(i+1))+cs('B'+r,st==='FAIL'?3:4,st)+cs('C'+r,2,td[2].textContent.trim())+cs('D'+r,2,td[3].textContent.trim())+ce('E'+r,2)+ce('F'+r,5)+'</row>';
      }
      var H='<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
      var NS='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
      var sheet=H+'<worksheet xmlns="'+NS+'"><dimension ref="A1:F'+(trs.length+1)+'"/>'+
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'+
        '<sheetFormatPr defaultRowHeight="15"/>'+
        '<cols><col min="1" max="1" width="6" customWidth="1"/><col min="2" max="2" width="11" customWidth="1"/><col min="3" max="3" width="30" customWidth="1"/><col min="4" max="4" width="90" customWidth="1"/><col min="5" max="5" width="55" customWidth="1"/><col min="6" max="6" width="16" customWidth="1"/></cols>'+
        '<sheetData>'+x+'</sheetData><autoFilter ref="A1:F'+(trs.length+1)+'"/></worksheet>';
      var styles=H+'<styleSheet xmlns="'+NS+'">'+
        '<fonts count="4"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFBE123C"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFB45309"/><name val="Calibri"/></font></fonts>'+
        '<fills count="5"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F2937"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFE4E6"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFEF3C7"/><bgColor indexed="64"/></patternFill></fill></fills>'+
        '<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD9DEEA"/></left><right style="thin"><color rgb="FFD9DEEA"/></right><top style="thin"><color rgb="FFD9DEEA"/></top><bottom style="thin"><color rgb="FFD9DEEA"/></bottom><diagonal/></border></borders>'+
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'+
        '<cellXfs count="6"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'+
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf>'+
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'+
        '<xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>'+
        '<xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>'+
        '<xf numFmtId="14" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf></cellXfs>'+
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>';
      var RNS='http://schemas.openxmlformats.org/officeDocument/2006/relationships';
      var PR='http://schemas.openxmlformats.org/package/2006/relationships';
      var files=[
        ['[Content_Types].xml',H+'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'],
        ['_rels/.rels',H+'<Relationships xmlns="'+PR+'"><Relationship Id="rId1" Type="'+RNS+'/officeDocument" Target="xl/workbook.xml"/></Relationships>'],
        ['xl/workbook.xml',H+'<workbook xmlns="'+NS+'" xmlns:r="'+RNS+'"><sheets><sheet name="Summary of issues" sheetId="1" r:id="rId1"/></sheets></workbook>'],
        ['xl/_rels/workbook.xml.rels',H+'<Relationships xmlns="'+PR+'"><Relationship Id="rId1" Type="'+RNS+'/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="'+RNS+'/styles" Target="styles.xml"/></Relationships>'],
        ['xl/styles.xml',styles],
        ['xl/worksheets/sheet1.xml',sheet]
      ];
      var d=new Date(), p=function(n){return (n<10?'0':'')+n;};
      var tm=document.title.match(/ - (.+)$/), host=(tm?tm[1]:'server').replace(/[^A-Za-z0-9._-]+/g,'_');
      var fn='healthcheck-issues-'+host+'-'+d.getFullYear()+p(d.getMonth()+1)+p(d.getDate())+'-'+p(d.getHours())+p(d.getMinutes())+p(d.getSeconds())+'.xlsx';
      var a=document.createElement('a');
      a.href=URL.createObjectURL(zip(files)); a.download=fn;
      document.body.appendChild(a); a.click();
      setTimeout(function(){URL.revokeObjectURL(a.href); a.remove();},1000);
    });
  })();

  /* expand everything when printing */
  window.addEventListener('beforeprint',function(){document.querySelectorAll('.sec').forEach(function(s){s.setAttribute('open','');});});
})();
HC_JS
    printf '</script></body></html>\n'
  } > "$f"
}
if [ $HTML -eq 1 ]; then
  [ -z "$OUT" ] && OUT="healthcheck-report-$(hostname)-$(date +%Y%m%d-%H%M%S).html"
  make_html "$OUT" && printf "\n  HTML report saved: %s\n" "$(readlink -f "$OUT" 2>/dev/null || echo "$OUT")"
fi

# ---------- Summary ----------
if   [ $FAILS -gt 0 ]; then FINAL="UNHEALTHY"; CODE=2; FC=$R
elif [ $WARN  -gt 0 ]; then FINAL="DEGRADED";  CODE=1; FC=$Y
else                        FINAL="HEALTHY";   CODE=0; FC=$G; fi
lg ""; lg "== SUMMARY =="; lg "  Warnings: $WARN   Failures: $FAILS"; lg "  STATUS: $FINAL"
printf "\n${B}== SUMMARY ==${NC}\n"
printf "  Warnings: %d   Failures: %d\n" "$WARN" "$FAILS"
printf "  ${FC}STATUS: %s${NC}\n" "$FINAL"

# ---------- Plain-text log ----------
if [ -n "$LOGFILE" ]; then
  mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null
  if printf '%s\n' "${LOGLINES[@]}" > "$LOGFILE" 2>/dev/null; then
    printf "  Log saved: %s\n" "$(readlink -f "$LOGFILE" 2>/dev/null || echo "$LOGFILE")"
  else
    echo "  Could not write log file: $LOGFILE"
  fi
fi
exit $CODE
