#!/usr/bin/env bash
# =============================================================================
# Linux Server Health Check
# Checks: CPU, RAM, Swap, Disk, Inodes, Network, Open Ports, Security Updates,
#         Reboot-needed, Failed services, Firewall, SSH failed logins,
#         Time sync, Zombie processes, Top processes
#
# Usage:  sudo bash healthcheck.sh            (root recommended for full info)
#         bash healthcheck.sh --quiet         (only WARN/FAIL lines)
#         bash healthcheck.sh --html          (also write an HTML report)
#         bash healthcheck.sh --html --out /var/www/html/health.html
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
# ------------------------------------------------

QUIET=0; HTML=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --html)  HTML=1 ;;
    --out)   OUT="$2"; HTML=1; shift ;;
  esac
  shift
done
WARN=0; FAILS=0
SECTION="General"; RL=(); RS=(); RM=(); PORTS_TXT=""; TOP_TXT=""
rec() { RL+=("$1"); RS+=("$SECTION"); RM+=("$2"); }

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; NC=$'\e[0m'; else G=; Y=; R=; B=; NC=; fi

ok()   { rec OK "$*";   [ $QUIET -eq 0 ] && printf "  ${G}[ OK ]${NC} %s\n" "$*"; }
warn() { rec WARN "$*"; printf "  ${Y}[WARN]${NC} %s\n" "$*"; WARN=$((WARN+1)); }
fail() { rec FAIL "$*"; printf "  ${R}[FAIL]${NC} %s\n" "$*"; FAILS=$((FAILS+1)); }
info() { rec INFO "$*"; [ $QUIET -eq 0 ] && printf "  [INFO] %s\n" "$*"; }
hdr()  { SECTION="$*"; [ $QUIET -eq 0 ] && printf "\n${B}== %s ==${NC}\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# level helper: lvl <value> <warn> <fail> <message>
lvl() {
  local v=${1%.*} w=$2 f=$3; shift 3
  if   [ "$v" -ge "$f" ]; then fail "$*"
  elif [ "$v" -ge "$w" ]; then warn "$*"
  else ok "$*"; fi
}

printf "${B}Health check: %s  |  Host: %s${NC}\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$(hostname)"
[ "$(id -u)" -ne 0 ] && echo "  (not root - some checks may be limited; try sudo)"

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
lvl "$MEM_USED_PCT" $MEM_WARN $MEM_FAIL "RAM used: ${MEM_USED_PCT}% ($(( (MEM_TOTAL-MEM_AVAIL)/1024 )) MB of $(( MEM_TOTAL/1024 )) MB)"
SW_TOTAL=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
SW_FREE=$(awk '/SwapFree/{print $2}' /proc/meminfo)
if [ "${SW_TOTAL:-0}" -gt 0 ]; then
  SW_PCT=$(( 100*(SW_TOTAL-SW_FREE)/SW_TOTAL ))
  lvl "$SW_PCT" $SWAP_WARN $SWAP_FAIL "Swap used: ${SW_PCT}%"
else
  info "No swap configured"
fi

# ---------- Disk ----------
hdr "STORAGE"
while read -r fs size used avail pct mount; do
  p=${pct%\%}
  lvl "$p" $DISK_WARN $DISK_FAIL "Disk $mount: ${pct} used ($used / $size, $avail free) [$fs]"
done < <(df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
while read -r fs inodes iused ifree ipct mount; do
  [ "$ipct" = "-" ] && continue
  p=${ipct%\%}
  case "$p" in ''|*[!0-9]*) continue;; esac
  lvl "$p" $INODE_WARN $INODE_FAIL "Inodes $mount: ${ipct} used"
done < <(df -iP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
# read-only filesystems (sign of disk errors)
RO=$(awk '$4 ~ /(^|,)ro(,|$)/ && $3 ~ /^(ext[234]|xfs|btrfs)$/ {print $2}' /proc/mounts)
RO=$(echo $RO)
[ -n "$RO" ] && fail "Read-only filesystem(s): $RO" || ok "No read-only filesystems"

# ---------- Network ----------
hdr "NETWORK"
if have ip; then
  ip -o -4 addr show scope global 2>/dev/null | awk '{print "  [INFO] Interface " $2 ": " $4}'
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
  if ping -c2 -W2 "$PING_TARGET" >/dev/null 2>&1; then ok "Internet reachable ($PING_TARGET)"; else fail "Internet NOT reachable ($PING_TARGET)"; fi
fi
if have getent; then
  if getent hosts "$DNS_TARGET" >/dev/null 2>&1; then ok "DNS resolves $DNS_TARGET"; else fail "DNS resolution failed for $DNS_TARGET"; fi
fi
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
  [ $QUIET -eq 0 ] && echo "$PORTS_TXT" | sed 's/^/  /'
  PUB=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]|::1)' | wc -l)
  info "$PUB TCP listener(s) exposed beyond localhost"
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
  [ "$SEC" -gt 0 ] && fail "$SEC security update(s) pending ($ALL total updates)" || ok "No pending security updates ($ALL other updates)"
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
hdr "SERVICES"
if have systemctl; then
  FAILED=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}')
  if [ -n "$FAILED" ]; then fail "Failed systemd units: $(echo $FAILED | tr '\n' ' ')"; else ok "No failed systemd units"; fi
fi
Z=$(ps -eo stat= 2>/dev/null | grep -c '^Z')
[ "$Z" -gt 0 ] && warn "$Z zombie process(es)" || ok "No zombie processes"

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
# failed SSH logins in last 24h
SSH_FAILS=
if have journalctl; then
  SSH_FAILS=$(journalctl -u ssh -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Failed password")
elif [ -r /var/log/auth.log ]; then
  SSH_FAILS=$(grep -c "Failed password" /var/log/auth.log)
elif [ -r /var/log/secure ]; then
  SSH_FAILS=$(grep -c "Failed password" /var/log/secure)
fi
if [ -n "$SSH_FAILS" ]; then
  [ "$SSH_FAILS" -ge "$SSH_FAIL_WARN" ] && warn "$SSH_FAILS failed SSH logins (24h) - possible brute force" || ok "$SSH_FAILS failed SSH logins (24h)"
fi
# root SSH login
if [ -r /etc/ssh/sshd_config ]; then
  grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config >/dev/null 2>&1 && warn "SSH PermitRootLogin is 'yes'"
fi
# time sync
if have timedatectl; then
  timedatectl 2>/dev/null | grep -qiE 'synchronized: yes|NTP synchronized: yes' && ok "Clock synchronized (NTP)" || warn "Clock NOT synchronized"
fi

# ---------- Top processes ----------
hdr "TOP PROCESSES"
TOP_TXT=$(echo "By CPU:"; ps -eo pid,comm,%cpu --sort=-%cpu 2>/dev/null | head -6
          echo; echo "By MEM:"; ps -eo pid,comm,%mem --sort=-%mem 2>/dev/null | head -6)
[ $QUIET -eq 0 ] && echo "$TOP_TXT" | sed 's/^/  /'

# ---------- HTML report ----------
esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
make_html() {
  local f="$1" status color last="" i
  if [ $FAILS -gt 0 ]; then status="UNHEALTHY"; color="#d93025"
  elif [ $WARN -gt 0 ]; then status="DEGRADED"; color="#e8a100"
  else status="HEALTHY"; color="#1e8e3e"; fi
  {
    cat <<HEAD
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Health Report - $(hostname)</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1f2933}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
.banner{background:$color;color:#fff;border-radius:10px;padding:20px 24px}
.banner h1{margin:0 0 4px;font-size:26px}.banner p{margin:0;opacity:.9}
.cards{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}
.card{flex:1;min-width:140px;background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card b{display:block;font-size:28px}
h2{font-size:16px;margin:24px 0 8px;text-transform:uppercase;letter-spacing:.05em;color:#52606d}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
td{padding:9px 14px;border-bottom:1px solid #eef1f4;font-size:14px;vertical-align:top}
td.s{width:70px;font-weight:700;font-size:12px}
.OK td.s{color:#1e8e3e}.WARN td.s{color:#e8a100}.FAIL td.s{color:#d93025}.INFO td.s{color:#52606d}
.FAIL{background:#fdecea}.WARN{background:#fff6e0}
pre{background:#fff;border-radius:10px;padding:14px;overflow:auto;font-size:13px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
footer{color:#7b8794;font-size:12px;margin-top:28px;text-align:center}
footer .credit{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:center;font-size:13px}
footer a.gh{display:inline-flex;align-items:center;gap:7px;padding:5px 13px 5px 10px;border-radius:999px;background:#fff;border:1px solid #e3e7f5;color:#1f2933;text-decoration:none;font-weight:700}
footer a.gh svg{width:17px;height:17px}
footer .sub{margin-top:8px;font-size:11px}
.toolbar{display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.toolbar button{background:#1f2933;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-size:14px;cursor:pointer}
.toolbar button:hover{background:#3e4c59}
.toolbar span{color:#7b8794;font-size:13px}
@page{size:A4;margin:12mm}
@media print{
 body{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact;font-size:12px}
 .noprint{display:none!important}
 .wrap{max-width:none;padding:0}
 .banner,.card,table,pre{box-shadow:none}
 table,pre,.card{border:1px solid #d9dee3}
 tr,.card,.banner{break-inside:avoid;page-break-inside:avoid}
 h2,h3{break-after:avoid;page-break-after:avoid}
 td,th{padding:6px 10px;font-size:12px}
}
</style></head><body><div class="wrap">
<div class="toolbar noprint"><button onclick="window.print()">Save as PDF / Print</button><span>In the print window choose &quot;Save as PDF&quot; as the destination.</span></div>
<div class="banner"><h1>$status</h1><p>Host: $(hostname) &middot; $(date '+%Y-%m-%d %H:%M:%S')</p></div>
<div class="cards">
<div class="card"><b style="color:#d93025">$FAILS</b>Failures</div>
<div class="card"><b style="color:#e8a100">$WARN</b>Warnings</div>
<div class="card"><b style="color:#1e8e3e">$(printf '%s\n' "${RL[@]}" | grep -c '^OK$')</b>Passed</div>
</div>
HEAD
    for i in "${!RL[@]}"; do
      if [ "${RS[$i]}" != "$last" ]; then
        [ -n "$last" ] && echo "</table>"
        echo "<h2>${RS[$i]}</h2><table>"
        last="${RS[$i]}"
      fi
      printf '<tr class="%s"><td class="s">%s</td><td>%s</td></tr>\n' "${RL[$i]}" "${RL[$i]}" "$(printf '%s' "${RM[$i]}" | esc)"
      if [ "${RS[$i]}" = "OPEN PORTS (listening)" ] && [ "$i" = "$(( ${#RL[@]} - 1 ))" ]; then :; fi
    done
    [ -n "$last" ] && echo "</table>"
    [ -n "$PORTS_TXT" ] && { echo "<h2>Listening ports</h2><pre>"; echo "$PORTS_TXT" | esc; echo "</pre>"; }
    [ -n "$TOP_TXT" ]   && { echo "<h2>Top processes</h2><pre>"; echo "$TOP_TXT" | esc; echo "</pre>"; }
    cat <<'FOOT'
<footer>
<div class="credit"><span>Created by</span>
<a class="gh" href="https://github.com/muhamaddarulhadi" target="_blank" rel="noopener noreferrer"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>muhamaddarulhadi</a></div>
<div class="sub">Generated by healthcheck.sh</div>
</footer>
</div></body></html>
FOOT
  } > "$f"
}
if [ $HTML -eq 1 ]; then
  [ -z "$OUT" ] && OUT="healthcheck-report-$(hostname)-$(date +%Y%m%d-%H%M%S).html"
  make_html "$OUT" && printf "\n  HTML report saved: %s\n" "$(readlink -f "$OUT" 2>/dev/null || echo "$OUT")"
fi

# ---------- Summary ----------
printf "\n${B}== SUMMARY ==${NC}\n"
printf "  Warnings: %d   Failures: %d\n" "$WARN" "$FAILS"
if   [ $FAILS -gt 0 ]; then printf "  ${R}STATUS: UNHEALTHY${NC}\n"; exit 2
elif [ $WARN  -gt 0 ]; then printf "  ${Y}STATUS: DEGRADED${NC}\n";  exit 1
else                        printf "  ${G}STATUS: HEALTHY${NC}\n";   exit 0; fi
