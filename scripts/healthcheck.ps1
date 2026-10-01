<#
=============================================================================
 Windows Server Health Check  (PowerShell 5.1+)
 Checks: CPU, RAM, Disk, Network, Open Ports, Security Updates (Windows
         Update), Last patch date, Pending reboot, Defender, Firewall,
         Failed logons, Stopped services, Time sync, Top processes

 Usage (run PowerShell as Administrator for best results):
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Quiet
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -SkipUpdates   (faster)
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Html          (HTML report, opens in browser)
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Html -NoOpen -OutFile C:\inetpub\wwwroot\health.html

 Exit code: 0 = healthy, 1 = warnings, 2 = failures
=============================================================================
#>
param(
    [switch]$Quiet,
    [switch]$SkipUpdates,
    [switch]$Html,          # write an HTML report
    [string]$OutFile = '',  # where to save it (default: next to the script)
    [switch]$NoOpen         # do not open the report in the browser
)

# ---------- Thresholds (edit to taste) ----------
$CpuWarn = 80;  $CpuFail = 95
$MemWarn = 80;  $MemFail = 95
$DiskWarn = 80; $DiskFail = 90
$PingTarget = '8.8.8.8'
$DnsTarget  = 'google.com'
$FailedLogonWarn = 20      # failed logons in last 24h
$PatchAgeWarnDays = 35     # warn if no patch installed for this many days
# ------------------------------------------------

$ErrorActionPreference = 'SilentlyContinue'
$script:Warn = 0
$script:Fails = 0
$script:Section = 'General'
$script:Results = New-Object System.Collections.ArrayList
$script:PortsHtml = ''
$script:TopHtml = ''
function Rec($lvl, $m) { [void]$script:Results.Add([pscustomobject]@{ Level = $lvl; Section = $script:Section; Msg = "$m" }) }

function Ok($m)   { Rec 'OK' $m;   if (-not $Quiet) { Write-Host "  [ OK ] $m" -ForegroundColor Green } }
function Warn($m) { Rec 'WARN' $m; Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:Warn++ }
function Fail($m) { Rec 'FAIL' $m; Write-Host "  [FAIL] $m" -ForegroundColor Red;    $script:Fails++ }
function Info($m) { Rec 'INFO' $m; if (-not $Quiet) { Write-Host "  [INFO] $m" -ForegroundColor Cyan } }
function Hdr($m)  { $script:Section = $m; if (-not $Quiet) { Write-Host "`n== $m ==" -ForegroundColor White } }

function Level($value, $warnAt, $failAt, $msg) {
    if     ($value -ge $failAt) { Fail $msg }
    elseif ($value -ge $warnAt) { Warn $msg }
    else                        { Ok $msg }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ("Health check: {0}  |  Host: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME) -ForegroundColor White
if (-not $isAdmin) { Write-Host "  (not running as Administrator - some checks may be limited)" -ForegroundColor DarkYellow }

# ---------- System ----------
Hdr 'SYSTEM'
$os = Get-CimInstance Win32_OperatingSystem
Info "OS: $($os.Caption) (build $($os.BuildNumber))"
$uptime = (Get-Date) - $os.LastBootUpTime
Info ("Uptime: {0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)

# ---------- CPU ----------
Hdr 'CPU'
$cpuInfo = Get-CimInstance Win32_Processor
Info "CPU: $(($cpuInfo | Select-Object -First 1).Name)  (cores: $(($cpuInfo | Measure-Object NumberOfCores -Sum).Sum))"
$samples = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3).CounterSamples.CookedValue
$cpu = [math]::Round(($samples | Measure-Object -Average).Average)
Level $cpu $CpuWarn $CpuFail "CPU usage (3s avg): $cpu%"
$q = (Get-Counter '\System\Processor Queue Length').CounterSamples.CookedValue
Info "Processor queue length: $q"

# ---------- Memory ----------
Hdr 'MEMORY'
$totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024)
$freeMB  = [math]::Round($os.FreePhysicalMemory / 1024)
$usedPct = [math]::Round(100 * ($totalMB - $freeMB) / $totalMB)
Level $usedPct $MemWarn $MemFail "RAM used: $usedPct% ($($totalMB - $freeMB) MB of $totalMB MB)"
$pf = Get-CimInstance Win32_PageFileUsage
if ($pf) {
    $pfPct = [math]::Round(100 * ($pf | Measure-Object CurrentUsage -Sum).Sum / ($pf | Measure-Object AllocatedBaseSize -Sum).Sum)
    Level $pfPct 50 80 "Page file used: $pfPct%"
}

# ---------- Storage ----------
Hdr 'STORAGE'
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $pct = [math]::Round(100 * ($_.Size - $_.FreeSpace) / $_.Size)
    Level $pct $DiskWarn $DiskFail ("Disk {0} {1}% used ({2} GB free of {3} GB)" -f $_.DeviceID, $pct, [math]::Round($_.FreeSpace/1GB,1), [math]::Round($_.Size/1GB,1))
}
# physical disk health (SMART-ish)
Get-PhysicalDisk | ForEach-Object {
    if ($_.HealthStatus -ne 'Healthy') { Fail "Physical disk '$($_.FriendlyName)' health: $($_.HealthStatus)" }
    else { Ok "Physical disk '$($_.FriendlyName)' health: Healthy" }
}

# ---------- Network ----------
Hdr 'NETWORK'
Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address } | ForEach-Object {
    Info ("Adapter {0}: {1}  GW: {2}" -f $_.InterfaceAlias, $_.IPv4Address.IPAddress, $_.IPv4DefaultGateway.NextHop)
}
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if ($gw) {
    if (Test-Connection $gw -Count 1 -Quiet) { Ok "Gateway $gw reachable" } else { Warn "Gateway $gw not reachable" }
} else { Warn 'No default gateway' }
if (Test-Connection $PingTarget -Count 2 -Quiet) { Ok "Internet reachable ($PingTarget)" } else { Fail "Internet NOT reachable ($PingTarget)" }
if (Resolve-DnsName $DnsTarget -DnsOnly -QuickTimeout) { Ok "DNS resolves $DnsTarget" } else { Fail "DNS resolution failed for $DnsTarget" }
Get-NetAdapter | Where-Object { $_.Status -eq 'Disconnected' -and $_.HardwareInterface } | ForEach-Object { Info "Adapter $($_.Name) is disconnected" }
$est = (Get-NetTCPConnection -State Established).Count
Info "Established TCP connections: $est"

# ---------- Open Ports ----------
Hdr 'OPEN PORTS (listening)'
$procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$portRows = Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object {
    [pscustomobject]@{
        Proto   = 'TCP'
        Address = $_.LocalAddress
        Port    = $_.LocalPort
        Exposed = if ($_.LocalAddress -in '127.0.0.1','::1') { 'local' } else { 'NETWORK' }
        Process = $procs[[int]$_.OwningProcess]
    }
}
$script:PortsHtml = ($portRows | ConvertTo-Html -Fragment) -join "`n"
if (-not $Quiet) {
    $portRows | Format-Table -AutoSize | Out-String -Stream | Where-Object { $_.Trim() } | ForEach-Object { "  $_" }
    Info "UDP endpoints: $((Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' }).Count) exposed"
}
$risky = @(21,23,135,139,445,3389,5985,5900)
$exposedRisky = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in $risky -and $_.LocalAddress -notin '127.0.0.1','::1' } | Select-Object -ExpandProperty LocalPort -Unique
if ($exposedRisky) { Warn "Sensitive ports listening on network: $($exposedRisky -join ', ')  (21 FTP, 23 Telnet, 135/139/445 SMB/RPC, 3389 RDP, 5985 WinRM, 5900 VNC)" }
else { Ok 'No commonly-attacked ports exposed' }

# ---------- Security Updates ----------
Hdr 'SECURITY UPDATES (Windows Update)'
$last = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($last) {
    $age = ((Get-Date) - $last.InstalledOn).Days
    if ($age -gt $PatchAgeWarnDays) { Warn "Last patch installed $age days ago ($($last.HotFixID), $($last.InstalledOn.ToString('yyyy-MM-dd')))" }
    else { Ok "Last patch installed $age days ago ($($last.HotFixID))" }
}
if (-not $SkipUpdates) {
    try {
        Info 'Searching Windows Update for pending updates (can take 30-60s)...'
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and IsHidden=0")
        $pending  = @($result.Updates)
        $security = @($pending | Where-Object { $_.MsrcSeverity -or ($_.Categories | Where-Object Name -match 'Security|Critical') })
        if ($security.Count -gt 0) {
            Fail "$($security.Count) security/critical update(s) pending (of $($pending.Count) total)"
            if (-not $Quiet) { $security | Select-Object -First 10 | ForEach-Object { "      - $($_.Title)" } }
        } elseif ($pending.Count -gt 0) {
            Warn "$($pending.Count) non-security update(s) pending"
        } else { Ok 'No pending updates' }
    } catch { Warn "Could not query Windows Update: $($_.Exception.Message)" }
} else { Info 'Windows Update scan skipped (-SkipUpdates)' }

# pending reboot
$reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
          (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
          ($null -ne (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations))
if ($reboot) { Warn 'Reboot required to finish updates' } else { Ok 'No reboot pending' }

# ---------- Security posture ----------
Hdr 'SECURITY'
$mp = Get-MpComputerStatus
if ($mp) {
    if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) { Ok 'Windows Defender: enabled, real-time protection ON' } else { Fail 'Windows Defender / real-time protection is OFF' }
    $sigAge = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days
    if ($sigAge -gt 3) { Warn "Defender signatures $sigAge days old" } else { Ok "Defender signatures up to date ($sigAge d)" }
} else { Info 'Defender status unavailable (third-party AV or not admin)' }
Get-NetFirewallProfile | ForEach-Object {
    if ($_.Enabled) { Ok "Firewall profile $($_.Name): ON" } else { Warn "Firewall profile $($_.Name): OFF" }
}
if ($isAdmin) {
    $since = (Get-Date).AddHours(-24)
    $fl = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($fl -ge $FailedLogonWarn) { Warn "$fl failed logons (24h) - possible brute force" } else { Ok "$fl failed logons (24h)" }
} else { Info 'Failed-logon check needs Administrator' }
$rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
if ($rdp -eq 0) { Info 'RDP is enabled' }
$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($bl) { if ($bl.ProtectionStatus -eq 'On') { Ok 'BitLocker on system drive: ON' } else { Info 'BitLocker on system drive: OFF' } }

# ---------- Services & time ----------
Hdr 'SERVICES & TIME'
$stopped = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $_.Name -notmatch 'sppsvc|gupdate|edgeupdate|MapsBroker|RemoteRegistry|TrustedInstaller|clr_optimization|CDPUserSvc|WbioSrvc' }
if ($stopped) { Warn "Auto-start services not running: $(($stopped | Select-Object -First 8 -ExpandProperty Name) -join ', ')" } else { Ok 'All auto-start services running' }
$tz = w32tm /query /status 2>$null
if ($LASTEXITCODE -eq 0 -and $tz) { Ok 'Time service (w32time) running' } else { Warn 'Time service not synced / not running' }
$crit = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue | Measure-Object).Count
if ($crit -gt 50) { Warn "$crit critical/error events in System log (24h)" } else { Ok "$crit critical/error events in System log (24h)" }

# ---------- Top processes ----------
Hdr 'TOP PROCESSES'
$topCpu = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, @{n='CPU(s)';e={[math]::Round($_.CPU,1)}}
$topMem = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 Name, Id, @{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB)}}
$script:TopHtml = '<h3>By CPU time</h3>' + (($topCpu | ConvertTo-Html -Fragment) -join "`n") + '<h3>By memory</h3>' + (($topMem | ConvertTo-Html -Fragment) -join "`n")
if (-not $Quiet) {
    Write-Host '  By CPU time:'
    $topCpu | Format-Table -AutoSize | Out-String -Stream | Where-Object { $_.Trim() } | ForEach-Object { "    $_" }
    Write-Host '  By memory:'
    $topMem | Format-Table -AutoSize | Out-String -Stream | Where-Object { $_.Trim() } | ForEach-Object { "    $_" }
}

# ---------- HTML report ----------
if ($Html -or $OutFile) {
    Add-Type -AssemblyName System.Web
    if     ($script:Fails -gt 0) { $status = 'UNHEALTHY'; $color = '#d93025' }
    elseif ($script:Warn  -gt 0) { $status = 'DEGRADED';  $color = '#e8a100' }
    else                         { $status = 'HEALTHY';   $color = '#1e8e3e' }
    $passed = @($script:Results | Where-Object Level -eq 'OK').Count
    $sb = New-Object System.Text.StringBuilder
    foreach ($grp in ($script:Results | Group-Object Section)) {
        [void]$sb.AppendLine("<h2>$([System.Web.HttpUtility]::HtmlEncode($grp.Name))</h2><table>")
        foreach ($r in $grp.Group) {
            [void]$sb.AppendLine("<tr class=`"$($r.Level)`"><td class=`"s`">$($r.Level)</td><td>$([System.Web.HttpUtility]::HtmlEncode($r.Msg))</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }
    $page = @"
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Health Report - $env:COMPUTERNAME</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1f2933}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
.banner{background:$color;color:#fff;border-radius:10px;padding:20px 24px}
.banner h1{margin:0 0 4px;font-size:26px}.banner p{margin:0;opacity:.9}
.cards{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}
.card{flex:1;min-width:140px;background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card b{display:block;font-size:28px}
h2{font-size:16px;margin:24px 0 8px;text-transform:uppercase;letter-spacing:.05em;color:#52606d}
h3{font-size:14px;margin:14px 0 6px;color:#52606d}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
td,th{padding:9px 14px;border-bottom:1px solid #eef1f4;font-size:14px;text-align:left;vertical-align:top}
th{background:#eef1f4}
td.s{width:70px;font-weight:700;font-size:12px}
.OK td.s{color:#1e8e3e}.WARN td.s{color:#e8a100}.FAIL td.s{color:#d93025}.INFO td.s{color:#52606d}
.FAIL{background:#fdecea}.WARN{background:#fff6e0}
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
<div class="banner"><h1>$status</h1><p>Host: $env:COMPUTERNAME &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p></div>
<div class="cards">
<div class="card"><b style="color:#d93025">$($script:Fails)</b>Failures</div>
<div class="card"><b style="color:#e8a100">$($script:Warn)</b>Warnings</div>
<div class="card"><b style="color:#1e8e3e">$passed</b>Passed</div>
</div>
$($sb.ToString())
<h2>Listening ports</h2>$($script:PortsHtml)
<h2>Top processes</h2>$($script:TopHtml)
<footer>
<div class="credit"><span>Created by</span>
<a class="gh" href="https://github.com/muhamaddarulhadi" target="_blank" rel="noopener noreferrer"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>muhamaddarulhadi</a></div>
<div class="sub">Generated by healthcheck.ps1</div>
</footer>
</div></body></html>
"@
    if (-not $OutFile) {
        $dir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $OutFile = Join-Path $dir ("healthcheck-report-{0}-{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    [System.IO.File]::WriteAllText($OutFile, $page, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "`n  HTML report saved: $OutFile" -ForegroundColor Cyan
    if (-not $NoOpen) { Start-Process $OutFile }
}

# ---------- Summary ----------
Write-Host "`n== SUMMARY ==" -ForegroundColor White
Write-Host "  Warnings: $script:Warn   Failures: $script:Fails"
if     ($script:Fails -gt 0) { Write-Host '  STATUS: UNHEALTHY' -ForegroundColor Red;    exit 2 }
elseif ($script:Warn  -gt 0) { Write-Host '  STATUS: DEGRADED'  -ForegroundColor Yellow; exit 1 }
else                         { Write-Host '  STATUS: HEALTHY'   -ForegroundColor Green;  exit 0 }
