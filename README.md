# Server Health Check

Two scripts that check the health of a server and print a clear OK / WARN / FAIL report.

| File | For | Run with |
|------|-----|----------|
| `healthcheck.ps1` | Windows (PowerShell 5.1+) | PowerShell |
| `healthcheck.sh` | Linux (bash) | Terminal |

> Prefer a web page? Open `index.html` in a browser for this guide with copy buttons and a Windows / Linux filter, or you can open it via this [link guide](https://muhamaddarulhadi.github.io/Health-Checker/).

## Project structure

```
Health-Checker/
|-- index.html            guide web page (open in a browser)
|-- README.md             this file
|-- .nojekyll             needed for GitHub Pages
|-- .gitignore            keeps generated reports out of git
|-- scripts/
|   |-- healthcheck.ps1   Windows (PowerShell)
|   |-- healthcheck.sh    Linux (bash)
|-- assets/
    |-- icons/            favicon.ico, favicon.svg, PNG icons
```

Run the scripts from inside the `scripts` folder (`cd scripts` first), or give the full path to the script.

## What it checks

- **CPU**: usage and load / processor queue
- **RAM**: memory used, plus swap or page file
- **Storage**: disk usage per drive; inodes (Linux) or physical disk health (Windows)
- **Network**: IP addresses, gateway, internet ping with latency and packet loss, DNS, adapter errors
- **Open ports**: every listening port with the process using it, and a warning for risky ports exposed to the network
- **Security updates**: pending security patches (with package names), last update age, pending reboot
- **Extras**: failed services, firewall, failed logins in the last 24h with the latest attempts and top source IPs (Windows logons / Linux SSH), recent system-log errors with details, time sync, top processes. Windows also checks Defender, BitLocker and RDP; Linux also checks SSH root login and disk SMART health.

You do not need to supply a list of ports. The scripts ask the server what is listening.

---

## Windows

### 1. Open PowerShell as Administrator
Start menu > type `PowerShell` > right-click > **Run as administrator**.
(Admin is needed for the failed-logon and Windows Update checks.)

### 2. Go to the folder with the script
```powershell
cd C:\Users\DELL\Desktop
```

### 3. Run it
```powershell
powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1
```

### Options

Put options at the **end** of the command, after the file name.

| Option | Effect |
|--------|--------|
| `-SkipUpdates` | Skip the Windows Update scan (much faster; the scan takes 30-60s) |
| `-Quiet` | Show only warnings and failures |
| `-Html` | Also save an HTML report and open it in your browser |
| `-OutFile <path>` | Where to save the HTML report (default: next to the script) |
| `-NoOpen` | Save the HTML report but do not open the browser |
| `-LogFile <path>` | Also save the full plain-text output to a log file |

```powershell
# Fast run
powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -SkipUpdates

# Only problems
powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Quiet

# Both
powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -SkipUpdates -Quiet

# Save a plain-text log as well
powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -LogFile .\health.log
```

### Troubleshooting
- **"running scripts is disabled"**: use the `-ExecutionPolicy Bypass` form shown above.
- **"file not found"**: you are in the wrong folder. Run `cd` to the folder where you saved the script.
- **Do not use `bash`** on Windows PowerShell. It points to WSL, which may not be installed. Use the `.ps1` script.

---

## Linux

### 1. Open a terminal on the server

### 2. Go to the folder with the script
```bash
cd /path/to/folder
```

### 3. Run it
```bash
sudo bash healthcheck.sh
```

Or make it executable once and run it directly:
```bash
chmod +x healthcheck.sh
sudo ./healthcheck.sh
```

### Options

| Option | Effect |
|--------|--------|
| `--quiet` | Show only warnings and failures |
| `--html` | Also save an HTML report (default: current folder) |
| `--out <path>` | Where to save the HTML report (implies `--html`) |
| `--log <path>` | Also save the full plain-text output to a log file |

```bash
sudo bash healthcheck.sh --quiet
sudo bash healthcheck.sh --html
sudo bash healthcheck.sh --html --out /var/www/html/health.html
sudo bash healthcheck.sh --log ./health.log
```

(Linux uses a double dash `--quiet`; Windows uses a single dash `-Quiet`.)

### Notes
- Run with `sudo` for full results (logs, firewall, and package checks need root).
- For fresh security-update data on Debian/Ubuntu, run `sudo apt-get update` first.
- Supported package managers: apt, dnf, yum, zypper.

---

## HTML report

Add `-Html` (Windows) or `--html` (Linux) to get a modern web page titled **SERVER HEALTH & SECURITY DIAGNOSTIC REPORT**. It has a green / amber / red status banner with a pass-rate ring, counts of failures, warnings and passed checks, "At a glance" gauges for CPU, RAM and every disk, a **Summary of issues** table of every warning and failure with a **Download Excel** button, collapsible sections with the listening-ports and top-process tables, an **Issues only** filter, and a dark / light toggle.

```powershell
# Windows: saves the report and opens it in your browser
powershell -ExecutionPolicy Bypass -File .\healthcheck.ps1 -Html -SkipUpdates
```
```bash
# Linux: saves healthcheck-report-<host>-<time>.html in the current folder
sudo bash healthcheck.sh --html
```

### Summary of issues and Excel download

Just above "Detailed results", the report lists every warning and failure in one table (failures first) with the columns **#**, **Status**, **Section** and **Finding**.

Click **Download Excel** to save the table as an `.xlsx` file named `healthcheck-issues-<host>-<time>.xlsx`. The Excel file has the same columns plus two empty ones on the right, **Solution** and **Date Solved**, so you can write what you did and when each issue was fixed. The file is created in your browser, so it also works offline and on a report copied from a headless server. If there are no warnings or failures, the button is hidden.

A headless Ubuntu server has no browser, so see the next section, "Viewing the HTML report on a headless server".

For a page that always shows the latest result, run it on a schedule with a fixed output file (see below), for example `--html --out /var/www/html/health.html`.

---

## Viewing the HTML report on a headless server

A headless server (no screen, SSH only) cannot open a browser, so view the report from your own PC. Pick one option.

> The report lists open ports and server details. Only expose it on a private network, or protect it with a password (Option 3).

### Option 1: Copy the file to your PC (simplest)

First create the report on the server:
```bash
sudo bash healthcheck.sh --html --out /tmp/health.html
```

Then run this on **your PC** (Windows PowerShell, or a Mac/Linux terminal), not on the server:
```powershell
scp youruser@SERVER_IP:/tmp/health.html .
```
Double-click the downloaded `health.html` to open it. On Windows you can also use WinSCP or FileZilla (SFTP) with the same login you use for SSH.

### Option 2: Temporary web page with Python (no install needed)

On the server:
```bash
sudo bash healthcheck.sh --html --out /tmp/report/health.html
cd /tmp/report
python3 -m http.server 8080
```
On your PC browser open `http://SERVER_IP:8080/health.html`. Press `Ctrl+C` on the server to stop.

If the page does not load, the firewall may be blocking the port:
```bash
sudo ufw allow 8080/tcp
# when finished, remove it again:
sudo ufw delete allow 8080/tcp
```

**Safer version (SSH tunnel, nothing exposed):**
```bash
# on the server
cd /tmp/report && python3 -m http.server 8080 --bind 127.0.0.1
```
```powershell
# on your PC (keep this window open)
ssh -L 8080:127.0.0.1:8080 youruser@SERVER_IP
```
Then open `http://localhost:8080/health.html` on your PC.

### Option 3: Always-on page with nginx (best for scheduled checks)

1. Install nginx:
   ```bash
   sudo apt update && sudo apt install -y nginx
   ```
2. Schedule the check so the page always shows the latest result:
   ```bash
   sudo crontab -e
   ```
   Add:
   ```
   */5 * * * * /path/to/healthcheck.sh --quiet --html --out /var/www/html/health.html >/dev/null 2>&1
   ```
3. Open `http://SERVER_IP/health.html` in your PC browser.
4. (Recommended) Add a password:
   ```bash
   sudo apt install -y apache2-utils
   sudo htpasswd -c /etc/nginx/.htpasswd admin
   ```
   Add these two lines inside the `location /` block of `/etc/nginx/sites-available/default`:
   ```
   auth_basic "Restricted";
   auth_basic_user_file /etc/nginx/.htpasswd;
   ```
   Then reload nginx:
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```
5. If you cannot connect, allow web traffic through the firewall:
   ```bash
   sudo ufw allow 'Nginx HTTP'
   ```

**Which one?** For a one-off look use Option 1. For regular monitoring use Option 3.

---

## Save the report as PDF

The HTML report is built to print cleanly on A4, with the status colors kept.

1. Open the report in your browser.
2. Click **Save as PDF / Print** at the top of the report (or press `Ctrl+P`).
3. Choose **Save as PDF** as the destination and click Save.
4. If colors look faded, tick **Background graphics** under "More settings".

The Download Excel button is left out of the printed page.

---

## Reading the results

```
[ OK ]  all good
[WARN]  needs attention soon
[FAIL]  needs attention now
```

The last lines show a summary and an overall status:

| Status | Exit code | Meaning |
|--------|-----------|---------|
| HEALTHY | 0 | No warnings or failures |
| DEGRADED | 1 | One or more warnings |
| UNHEALTHY | 2 | One or more failures |

In the HTML report, the **Summary of issues** table gathers all `WARN` and `FAIL` lines in one place, and **Download Excel** turns it into a worksheet you can use to track fixes (see "HTML report" above).

In the open-ports section:
- `0.0.0.0` / `::` (Windows column shows `NETWORK`) means reachable from other machines (unless a firewall blocks it).
- `127.0.0.1` (shown as `local`) means reachable only from the server itself.

---

## Changing the thresholds

Open the script in a text editor. The settings are at the top of the file.

**Linux (`healthcheck.sh`)**
```
CPU_WARN=80    CPU_FAIL=95      # CPU %
MEM_WARN=80    MEM_FAIL=95      # RAM %
SWAP_WARN=50   SWAP_FAIL=80     # swap %
DISK_WARN=80   DISK_FAIL=90     # disk %
INODE_WARN=80  INODE_FAIL=90    # inode %
LOAD_WARN_FACTOR=1              # load per CPU core
PING_TARGET="8.8.8.8"           # internet test address
DNS_TARGET="google.com"         # DNS test name
PING_WARN_MS=150                # slow ping (ms)
SSH_FAIL_WARN=20                # failed SSH logins in 24h
PATCH_AGE_WARN_DAYS=35          # days since last package update
SYSERR_WARN=20                  # system-log errors in 24h
SHOW_LAST_N=5                   # recent events / attempts to list
```

**Windows (`healthcheck.ps1`)**
```
$CpuWarn = 80;  $CpuFail = 95
$MemWarn = 80;  $MemFail = 95
$DiskWarn = 80; $DiskFail = 90
$PingTarget = '8.8.8.8'; $DnsTarget = 'google.com'
$PingWarnMs = 150; $FailedLogonWarn = 20; $PatchAgeWarnDays = 35
$SysErrWarn = 20;  $ShowLastN = 5
```

---

## Run it automatically

### Windows: Task Scheduler
1. Open **Task Scheduler** > **Create Task**.
2. Tick **Run with highest privileges**.
3. **Triggers**: New > Daily > repeat every 15 minutes (or your choice).
4. **Actions**: New
   - Program: `powershell.exe`
   - Arguments:
     ```
     -ExecutionPolicy Bypass -File "C:\path\healthcheck.ps1" -SkipUpdates -Quiet
     ```

To save output to a log, add `-LogFile`:
```
-ExecutionPolicy Bypass -File "C:\path\healthcheck.ps1" -SkipUpdates -Quiet -LogFile "C:\path\health.log"
```

### Linux: cron
```bash
sudo crontab -e
```
Add:
```
*/5 * * * * /path/healthcheck.sh --quiet >> /var/log/health.log 2>&1
```

Use the exit code in your own scripts:
```bash
./healthcheck.sh --quiet || echo "Server needs attention"
```

---

Created by [muhamaddarulhadi](https://github.com/muhamaddarulhadi)
