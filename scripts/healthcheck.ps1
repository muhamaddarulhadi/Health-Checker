<#
=============================================================================
 Windows Server Health & Security Check  (PowerShell 5.1+ / PowerShell 7)

 Checks:
   System ........ OS, uptime
   CPU ........... usage (3s average, with fallback), processor queue
   Memory ........ RAM (GB) and page file
   Storage ....... every drive, physical disk health
   Network ....... IP addresses, gateway, internet ping + latency + loss, DNS,
                   adapter status, connection count
   Open ports .... every listening port with its process, risky ports exposed
   Security ...... pending Windows Updates, last patch, pending reboot,
                   Defender, firewall, BitLocker, RDP,
                   failed logons (count, latest attempts, top source IPs)
   Services/time . stopped auto-start services, time sync,
                   recent critical/error events in the System log (details)
   Top processes . by CPU time and by memory

 Usage (run PowerShell as Administrator for best results):
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Quiet
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -SkipUpdates   (faster)
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Html          (HTML report, opens in browser)
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Html -NoOpen -OutFile C:\inetpub\wwwroot\health.html
   powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -LogFile .\health.log   (plain-text log)

 Exit code: 0 = healthy, 1 = warnings, 2 = failures
=============================================================================
#>
param(
    [switch]$Quiet,
    [switch]$SkipUpdates,
    [switch]$Html,          # write an HTML report
    [string]$OutFile = '',  # where to save the HTML report (default: next to the script)
    [switch]$NoOpen,        # do not open the HTML report in the browser
    [string]$LogFile = ''   # also save the full plain-text output to this file
)

# ---------- Thresholds (edit to taste) ----------
$CpuWarn = 80;  $CpuFail = 95
$MemWarn = 80;  $MemFail = 95
$DiskWarn = 80; $DiskFail = 90
$PingTarget = '8.8.8.8'
$DnsTarget  = 'google.com'
$PingWarnMs = 150          # warn if average ping is slower than this (ms)
$FailedLogonWarn = 20      # failed logons in last 24h
$PatchAgeWarnDays = 35     # warn if no patch installed for this many days
$SysErrWarn = 20           # warn if more System-log errors than this in 24h
$ShowLastN = 5             # how many recent events / attempts to list
# ------------------------------------------------

$ErrorActionPreference = 'SilentlyContinue'
$script:Warn = 0
$script:Fails = 0
$script:Section = 'General'
$script:Results = New-Object System.Collections.ArrayList
$script:Log = New-Object System.Collections.Generic.List[string]
$script:PortsHtml = ''
$script:TopHtml = ''
$script:SectionNames = New-Object System.Collections.ArrayList
$script:Metrics = New-Object System.Collections.ArrayList

function Rec($lvl, $m) { [void]$script:Results.Add([pscustomobject]@{ Level = $lvl; Section = $script:Section; Msg = "$m" }) }
function Log($t)       { [void]$script:Log.Add("$t") }

function Ok($m)     { Rec 'OK' $m;   Log "  [ OK ] $m";   if (-not $Quiet) { Write-Host "  [ OK ] $m" -ForegroundColor Green } }
function Warn($m)   { Rec 'WARN' $m; Log "  [WARN] $m";   Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:Warn++ }
function Fail($m)   { Rec 'FAIL' $m; Log "  [FAIL] $m";   Write-Host "  [FAIL] $m" -ForegroundColor Red;    $script:Fails++ }
function Info($m)   { Rec 'INFO' $m; Log "  [INFO] $m";   if (-not $Quiet) { Write-Host "  [INFO] $m" -ForegroundColor Cyan } }
function Detail($m) { Rec 'INFO' $m; Log "      - $m";    if (-not $Quiet) { Write-Host "      - $m" -ForegroundColor Gray } }
function Hdr($m)    { $script:Section = $m; [void]$script:SectionNames.Add($m); Log ''; Log "== $m =="; if (-not $Quiet) { Write-Host "`n== $m ==" -ForegroundColor White } }

# remember a percentage metric for the "At a glance" gauges in the HTML report
function Metric($label, $value, $warnAt, $failAt, $detail = '') {
    $state = if ($value -ge $failAt) { 'fail' } elseif ($value -ge $warnAt) { 'warn' } else { 'ok' }
    [void]$script:Metrics.Add([pscustomobject]@{ Label = $label; Value = [int]$value; State = $state; Detail = $detail })
}

function Level($value, $warnAt, $failAt, $msg) {
    if     ($value -ge $failAt) { Fail $msg }
    elseif ($value -ge $warnAt) { Warn $msg }
    else                        { Ok $msg }
}

# print + log a table (console only when not -Quiet, always logged)
function Show-Table($rows, $indent = '  ') {
    $lines = $rows | Format-Table -AutoSize | Out-String -Width 200 -Stream | Where-Object { $_.Trim() } | ForEach-Object { "$indent$_" }
    foreach ($l in $lines) { Log $l; if (-not $Quiet) { Write-Host $l } }
}

# first line of a message, trimmed to a sensible length
function FirstLine($t, $max = 140) {
    if (-not $t) { return '' }
    $l = ($t -split "`r?`n")[0].Trim()
    if ($l.Length -gt $max) { $l = $l.Substring(0, $max) + '...' }
    return $l
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$banner = "Health check: {0}  |  Host: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME
Log $banner
Write-Host $banner -ForegroundColor White
if (-not $isAdmin) {
    Log '  (not running as Administrator - some checks may be limited)'
    Write-Host '  (not running as Administrator - some checks may be limited)' -ForegroundColor DarkYellow
}

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
$cpu = $null; $cpuSrc = '3s avg'
try {
    $samples = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop).CounterSamples.CookedValue
    $cpu = [math]::Round(($samples | Measure-Object -Average).Average)
} catch { }
if ($null -eq $cpu) {
    # fallback (works on any language / if performance counters are broken)
    $cpu = [math]::Round(($cpuInfo | Measure-Object LoadPercentage -Average).Average)
    $cpuSrc = 'instant'
}
Level $cpu $CpuWarn $CpuFail "CPU usage ($cpuSrc): $cpu%"
Metric 'CPU' $cpu $CpuWarn $CpuFail "$cpuSrc"
$q = $null
try { $q = (Get-Counter '\System\Processor Queue Length' -ErrorAction Stop).CounterSamples.CookedValue } catch { }
if ($null -ne $q) { Info "Processor queue length: $q" }

# ---------- Memory ----------
Hdr 'MEMORY'
$totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
$freeGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
$usedGB  = [math]::Round($totalGB - $freeGB, 2)
$usedPct = [math]::Round(100 * $usedGB / $totalGB)
Level $usedPct $MemWarn $MemFail "RAM used: $usedPct% ($usedGB GB of $totalGB GB)"
Metric 'RAM' $usedPct $MemWarn $MemFail "$usedGB GB of $totalGB GB"
$pf = Get-CimInstance Win32_PageFileUsage
if ($pf) {
    $pfPct = [math]::Round(100 * ($pf | Measure-Object CurrentUsage -Sum).Sum / ($pf | Measure-Object AllocatedBaseSize -Sum).Sum)
    Level $pfPct 50 80 "Page file used: $pfPct%"
    Metric 'Page file' $pfPct 50 80 ''
}

# ---------- Storage ----------
Hdr 'STORAGE'
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $pct = [math]::Round(100 * ($_.Size - $_.FreeSpace) / $_.Size)
    Level $pct $DiskWarn $DiskFail ("Disk {0} {1}% used ({2} GB free of {3} GB)" -f $_.DeviceID, $pct, [math]::Round($_.FreeSpace/1GB,1), [math]::Round($_.Size/1GB,1))
    Metric ("Disk " + $_.DeviceID) $pct $DiskWarn $DiskFail ("{0} GB free of {1} GB" -f [math]::Round($_.FreeSpace/1GB,1), [math]::Round($_.Size/1GB,1))
}
# physical disk health (SMART-ish)
Get-PhysicalDisk | ForEach-Object {
    if ($_.HealthStatus -ne 'Healthy') { Fail "Physical disk '$($_.FriendlyName)' health: $($_.HealthStatus)" }
    else { Ok "Physical disk '$($_.FriendlyName)' health: Healthy" }
}

# ---------- Network ----------
Hdr 'NETWORK'
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' }
if ($ips) { Info "IP address(es): $((($ips | Select-Object -ExpandProperty IPAddress) -join ', '))" }
Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address } | ForEach-Object {
    Info ("Adapter {0}: {1}  GW: {2}" -f $_.InterfaceAlias, $_.IPv4Address.IPAddress, $_.IPv4DefaultGateway.NextHop)
}
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if ($gw) {
    if (Test-Connection $gw -Count 1 -Quiet) { Ok "Gateway $gw reachable" } else { Warn "Gateway $gw not reachable" }
} else { Warn 'No default gateway' }

# internet: reachability + average latency + packet loss
$pingCount = 4
$ping = @(Test-Connection $PingTarget -Count $pingCount -ErrorAction SilentlyContinue)
if ($ping.Count -gt 0) {
    $prop = if ($ping[0].PSObject.Properties['Latency']) { 'Latency' } else { 'ResponseTime' }   # PS7 / PS5.1
    $avg  = [math]::Round(($ping | Measure-Object -Property $prop -Average).Average)
    if ($ping.Count -lt $pingCount) {
        Warn "Internet ($PingTarget): packet loss, $($ping.Count) of $pingCount replies, avg $avg ms"
    } elseif ($avg -ge $PingWarnMs) {
        Warn "Internet reachable ($PingTarget) but slow: avg $avg ms (limit $PingWarnMs ms)"
    } else {
        Ok "Internet reachable ($PingTarget), avg $avg ms"
    }
} else { Fail "Internet NOT reachable ($PingTarget)" }

if (Resolve-DnsName $DnsTarget -DnsOnly -QuickTimeout) { Ok "DNS resolves $DnsTarget" } else { Fail "DNS resolution failed for $DnsTarget" }
Get-NetAdapter | Where-Object { $_.Status -eq 'Disconnected' -and $_.HardwareInterface } | ForEach-Object { Info "Adapter $($_.Name) is disconnected" }
$est = (Get-NetTCPConnection -State Established).Count
Info "Established TCP connections: $est"

# ---------- Open Ports ----------
Hdr 'OPEN PORTS (listening)'
$procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$listen = @(Get-NetTCPConnection -State Listen)
$portRows = $listen | Sort-Object LocalPort -Unique | ForEach-Object {
    [pscustomobject]@{
        Proto   = 'TCP'
        Address = $_.LocalAddress
        Port    = $_.LocalPort
        Exposed = if ($_.LocalAddress -in '127.0.0.1','::1') { 'local' } else { 'NETWORK' }
        Process = $procs[[int]$_.OwningProcess]
    }
}
$script:PortsHtml = ($portRows | ConvertTo-Html -Fragment) -join "`n"
Info "Listening TCP endpoints: $($listen.Count) ($(@($portRows | Where-Object Exposed -eq 'NETWORK').Count) distinct ports reachable from the network)"
Show-Table $portRows '  '
Info "UDP endpoints exposed: $((Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' }).Count)"
$risky = @(21,23,135,139,445,3389,5985,5900)
$exposedRisky = $listen | Where-Object { $_.LocalPort -in $risky -and $_.LocalAddress -notin '127.0.0.1','::1' } | Select-Object -ExpandProperty LocalPort -Unique
if ($exposedRisky) { Warn "Sensitive ports listening on network: $($exposedRisky -join ', ')  (21 FTP, 23 Telnet, 135/139/445 SMB/RPC, 3389 RDP, 5985 WinRM, 5900 VNC)" }
else { Ok 'No commonly-attacked ports exposed' }

# ---------- Security Updates ----------
Hdr 'SECURITY UPDATES (Windows Update)'
$last = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($last) {
    $age = ((Get-Date) - $last.InstalledOn).Days
    if ($age -gt $PatchAgeWarnDays) { Warn "Last patch installed $age days ago ($($last.HotFixID), $($last.InstalledOn.ToString('yyyy-MM-dd')))" }
    else { Ok "Last patch installed $age days ago ($($last.HotFixID), $($last.InstalledOn.ToString('yyyy-MM-dd')))" }
} else { Warn 'No update (hotfix) records could be retrieved' }
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
            $security | Select-Object -First 10 | ForEach-Object { Detail $_.Title }
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

$fwProfiles = Get-NetFirewallProfile
$fwOff = @($fwProfiles | Where-Object { -not $_.Enabled })
foreach ($p in $fwProfiles) {
    if ($p.Enabled) { Ok "Firewall profile $($p.Name): ON" } else { Warn "Firewall profile $($p.Name): OFF" }
}
if ($fwProfiles -and $fwOff.Count -eq 0) { Ok 'Firewall: Domain, Private and Public profiles are all enabled' }

# failed logons (24h): count, latest attempts, top source IPs
if ($isAdmin) {
    $since  = (Get-Date).AddHours(-24)
    $failed = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -MaxEvents 5000 -ErrorAction SilentlyContinue)
    $fl = $failed.Count
    $flText = if ($fl -ge 5000) { '5000+' } else { "$fl" }
    if ($fl -ge $FailedLogonWarn) { Warn "$flText failed logons (24h) - possible brute force" } else { Ok "$flText failed logons (24h)" }
    if ($fl -gt 0) {
        $failed | Select-Object -First $ShowLastN | ForEach-Object {
            $user = $_.Properties[5].Value
            $src  = $_.Properties[19].Value
            if (-not $src -or $src -eq '-') { $src = 'local/unknown' }
            Detail ("{0}  user: {1}  from: {2}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $user, $src)
        }
        $topIps = $failed | ForEach-Object { $_.Properties[19].Value } | Where-Object { $_ -and $_ -ne '-' } |
                  Group-Object | Sort-Object Count -Descending | Select-Object -First 3
        if ($topIps) { Detail ('Top source IPs: ' + (($topIps | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')) }
    }
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

# recent critical/error events in the System log
$sysErr = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 2000 -ErrorAction SilentlyContinue)
$crit = $sysErr.Count
if ($crit -gt $SysErrWarn) { Warn "$crit critical/error events in System log (24h)" } else { Ok "$crit critical/error events in System log (24h)" }
if ($crit -gt 0) {
    $sysErr | Select-Object -First $ShowLastN | ForEach-Object {
        Detail ("{0}  [{1}] ID {2}: {3}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $_.ProviderName, $_.Id, (FirstLine $_.Message))
    }
}

# ---------- Top processes ----------
Hdr 'TOP PROCESSES'
$topCpu = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, @{n='CPU(s)';e={[math]::Round($_.CPU,1)}}
$topMem = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 Name, Id, @{n='MemMB';e={[math]::Round($_.WorkingSet64/1MB)}}
$script:TopHtml = '<h3>By CPU time</h3>' + (($topCpu | ConvertTo-Html -Fragment) -join "`n") + '<h3>By memory</h3>' + (($topMem | ConvertTo-Html -Fragment) -join "`n")
Log '  By CPU time:'; if (-not $Quiet) { Write-Host '  By CPU time:' }
Show-Table $topCpu '    '
Log '  By memory:';   if (-not $Quiet) { Write-Host '  By memory:' }
Show-Table $topMem '    '

# ---------- HTML report ----------
if ($Html -or $OutFile) {
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $reportTitle = 'SERVER HEALTH &amp; SECURITY DIAGNOSTIC REPORT'

    $nPass = @($script:Results | Where-Object Level -eq 'OK').Count
    $nWarn = $script:Warn
    $nFail = $script:Fails
    $nInfo = @($script:Results | Where-Object Level -eq 'INFO').Count
    $nTotal = $nPass + $nWarn + $nFail
    $score  = if ($nTotal -gt 0) { [int][math]::Round(100 * $nPass / $nTotal) } else { 100 }
    $pPass  = if ($nTotal -gt 0) { [math]::Round(100 * $nPass / $nTotal, 1) } else { 100 }
    $pWarn  = if ($nTotal -gt 0) { [math]::Round(100 * $nWarn / $nTotal, 1) } else { 0 }
    $pFail  = [math]::Round(100 - $pPass - $pWarn, 1)
    $c1 = $pPass; $c2 = [math]::Round($pPass + $pWarn, 1)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ringBg = 'conic-gradient(#10b981 0 {0}%, #f59e0b {0}% {1}%, #f43f5e {1}% 100%)' -f $c1.ToString($inv), $c2.ToString($inv)

    if     ($nFail -gt 0) { $status = 'UNHEALTHY'; $sClass = 's-unhealthy' }
    elseif ($nWarn -gt 0) { $status = 'DEGRADED';  $sClass = 's-degraded' }
    else                  { $status = 'HEALTHY';   $sClass = 's-healthy' }

    $runAs = if ($isAdmin) { 'Administrator' } else { 'Standard user' }
    $now   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $hero = @()
    $hero += '<section class="hero ' + $sClass + '"><div class="hero-text">'
    $hero += '<span class="kicker">Windows Server</span>'
    $hero += '<h1>' + $reportTitle + '</h1>'
    $hero += '<span class="statuspill"><i></i>' + $status + '</span>'
    $hero += '<div class="metaline">'
    $hero += '<span class="meta">Host <b>' + (& $enc $env:COMPUTERNAME) + '</b></span>'
    $hero += '<span class="meta">OS <b>' + (& $enc $os.Caption) + '</b></span>'
    $hero += '<span class="meta">Generated <b>' + $now + '</b></span>'
    $hero += '<span class="meta">Run as <b>' + $runAs + '</b></span>'
    $hero += '</div></div>'
    $hero += '<div class="ring" style="background:' + $ringBg + '"><div class="ring-in"><b>' + $score + '%</b><span>checks passed</span></div></div>'
    $hero += '</section>'

    $stats = @()
    $stats += '<div class="stats">'
    $stats += '<div class="stat f"><b>' + $nFail + '</b><span>Failures</span></div>'
    $stats += '<div class="stat w"><b>' + $nWarn + '</b><span>Warnings</span></div>'
    $stats += '<div class="stat p"><b>' + $nPass + '</b><span>Checks passed</span></div>'
    $stats += '<div class="stat i"><b>' + $nTotal + '</b><span>Checks run</span></div>'
    $stats += '</div>'
    $stats += '<div class="stackbar" title="Passed / warnings / failures"><i class="p" style="width:' + $pPass.ToString($inv) + '%"></i><i class="w" style="width:' + $pWarn.ToString($inv) + '%"></i><i class="f" style="width:' + $pFail.ToString($inv) + '%"></i></div>'

    $gauges = @()
    if ($script:Metrics.Count -gt 0) {
        $gauges += '<div class="title">At a glance</div><div class="gauges">'
        foreach ($m in $script:Metrics) {
            $w = [math]::Min(100, [math]::Max(0, $m.Value))
            $gauges += '<div class="gauge ' + $m.State + '"><div class="top"><span class="lbl">' + (& $enc $m.Label) + '</span><span class="val">' + $m.Value + '%</span></div>' +
                       '<div class="sub">' + (& $enc $m.Detail) + '</div><div class="bar"><i style="width:' + $w + '%"></i></div></div>'
        }
        $gauges += '</div>'
    }

    $secs = New-Object System.Text.StringBuilder
    [void]$secs.AppendLine('<div class="title">Detailed results</div>')
    foreach ($name in $script:SectionNames) {
        $rows = @($script:Results | Where-Object { $_.Section -eq $name })
        $cF = @($rows | Where-Object Level -eq 'FAIL').Count
        $cW = @($rows | Where-Object Level -eq 'WARN').Count
        $cO = @($rows | Where-Object Level -eq 'OK').Count
        $cls = if ($cF -gt 0) { 'has-fail' } elseif ($cW -gt 0) { 'has-warn' } else { 'clean' }
        $badges = ''
        if ($cF -gt 0) { $badges += '<span class="cnt f">' + $cF + ' fail</span>' }
        if ($cW -gt 0) { $badges += '<span class="cnt w">' + $cW + ' warn</span>' }
        if ($cO -gt 0) { $badges += '<span class="cnt o">' + $cO + ' ok</span>' }
        [void]$secs.AppendLine('<details class="sec ' + $cls + '" open data-name="' + (& $enc $name) + '"><summary><span class="ico"></span>' + (& $enc $name) + '<span class="cnts">' + $badges + '</span></summary>')
        foreach ($r in $rows) {
            [void]$secs.AppendLine('<div class="row ' + $r.Level + '"><span class="pill">' + $r.Level + '</span><span class="msg">' + (& $enc $r.Msg) + '</span></div>')
        }
        if ($name -like 'OPEN PORTS*' -and $script:PortsHtml) { [void]$secs.AppendLine('<div class="tbl">' + $script:PortsHtml + '</div>') }
        if ($name -like 'TOP PROCESSES*' -and $script:TopHtml) { [void]$secs.AppendLine('<div class="tbl">' + $script:TopHtml + '</div>') }
        [void]$secs.AppendLine('</details>')
    }
    [void]$secs.AppendLine('<div class="empty">No warnings or failures. Everything looks healthy.</div>')

    $css = @'
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
  .sec>summary,.title{break-after:avoid;page-break-after:avoid}
  .stats{grid-template-columns:repeat(4,1fr)}
  .gauges{grid-template-columns:repeat(3,1fr)}
  .sec>summary::after{display:none}
  .issues-only .row.OK,.issues-only .row.INFO,.issues-only .tbl,.issues-only .sec.clean{display:flex}
  .issues-only .tbl{display:block}
}
'@
    $topbar = @'
<header class="topbar noprint"><div class="topbar-in">
<div class="brand"><div class="logo"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></div><span>Health Check</span></div>
<div class="spacer"></div>
<div class="seg" role="group" aria-label="Filter"><button type="button" data-f="all" class="on">All checks</button><button type="button" data-f="issues">Issues only</button></div>
<button class="iconbtn" id="themeBtn" type="button" aria-label="Toggle dark / light mode"><svg class="moon" viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg><svg class="sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg><span id="themeLabel">Dark</span></button>
<button class="iconbtn" type="button" onclick="window.print()" title="Print or save as PDF"><svg viewBox="0 0 24 24"><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>Save as PDF</button>
</div></header>
'@
    $footer = @'
<footer>
<div class="credit"><span>Created by</span>
<a class="gh" href="https://github.com/muhamaddarulhadi" target="_blank" rel="noopener noreferrer"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>muhamaddarulhadi</a></div>
'@
    $js = @'
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

  /* expand everything when printing */
  window.addEventListener('beforeprint',function(){document.querySelectorAll('.sec').forEach(function(s){s.setAttribute('open','');});});
})();
'@

    $page = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
            '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">' +
            '<title>' + $reportTitle + ' - ' + (& $enc $env:COMPUTERNAME) + '</title>' +
            '<style>' + $css + '</style></head><body>' + $topbar +
            '<main class="wrap">' + ($hero -join "`n") + ($stats -join "`n") + ($gauges -join "`n") + $secs.ToString() +
            $footer + '<div class="sub">Generated by healthcheck.ps1</div></footer></main>' +
            '<script>' + $js + '</script></body></html>'

    if (-not $OutFile) {
        $dir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $OutFile = Join-Path $dir ("healthcheck-report-{0}-{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    [System.IO.File]::WriteAllText($OutFile, $page, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "`n  HTML report saved: $OutFile" -ForegroundColor Cyan
    if (-not $NoOpen) { Start-Process $OutFile }
}

# ---------- Summary ----------
if     ($script:Fails -gt 0) { $finalStatus = 'UNHEALTHY'; $finalCode = 2; $finalColor = 'Red' }
elseif ($script:Warn  -gt 0) { $finalStatus = 'DEGRADED';  $finalCode = 1; $finalColor = 'Yellow' }
else                         { $finalStatus = 'HEALTHY';   $finalCode = 0; $finalColor = 'Green' }
Log ''; Log '== SUMMARY =='
Log "  Warnings: $script:Warn   Failures: $script:Fails"
Log "  STATUS: $finalStatus"
Write-Host "`n== SUMMARY ==" -ForegroundColor White
Write-Host "  Warnings: $script:Warn   Failures: $script:Fails"
Write-Host "  STATUS: $finalStatus" -ForegroundColor $finalColor

# ---------- Plain-text log ----------
if ($LogFile) {
    try {
        $logDir = Split-Path -Parent $LogFile
        if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        [System.IO.File]::WriteAllLines($LogFile, $script:Log, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "  Log saved: $LogFile" -ForegroundColor Cyan
    } catch { Write-Host "  Could not write log file: $($_.Exception.Message)" -ForegroundColor Yellow }
}
exit $finalCode
