# Detection and Containment in Incident Response

### A Multi-Level Visibility Approach

*A study guide based on the INE IHRP / eCIR learning path.*

> **Educational purpose only.** These notes are for learning and study. Run the commands only on systems you own or are explicitly authorized to investigate.

## Table of Contents

- [Introduction: Why Detection Is Never a Single Tool](#introduction-why-detection-is-never-a-single-tool)
- [1. Network-Level Detection](#1-network-level-detection)
- [2. Host Perimeter: Manual Live Response](#2-host-perimeter-manual-live-response)
- [3. Host Level: Continuous Detection Tools](#3-host-level-continuous-detection-tools)
- [4. Application-Level Detection](#4-application-level-detection)
- [5. Correlation: Connecting the Levels](#5-correlation-connecting-the-levels)
- [6. Containment Strategy](#6-containment-strategy)
- [Conclusion](#conclusion)

---

## Introduction: Why Detection Is Never a Single Tool

No single control sees everything. A firewall sees conversations between machines but not what happens inside them. An antivirus sees files but not the network. A web server log sees requests but not the operating system underneath. Incident responders therefore think in terms of **visibility levels**: each level shows part of the attack and is blind to another part.

This article walks through the Detection & Analysis and Containment phases of the incident response (IR) life cycle, organized by where the visibility comes from:

1. **Network Level**
2. **Host Perimeter** (manual live response)
3. **Host Level** (Antivirus, HIDS, EDR)
4. **Application Level** (web servers, web shells, IIS, WAF/RASP/DAM)

The IHRP material describes the IR process as Preparation, Detection & Analysis, Investigation, and Containment & Eradication. Detection feeds Investigation, and what we learn drives Containment.

| Level | What it sees | What it is blind to |
|---|---|---|
| Network | Who talked to whom, volume, timing | What happens inside the host; encrypted payloads |
| Host Perimeter | Live state of one machine (manual) | Anything before the commands were run |
| Host Level | Continuous behavior on the endpoint | The wider network; attackers who disable the agent |
| Application | Application logic and web server activity | Apps that do not log security events |

The glue between these levels is **correlation**: events that look harmless alone become an obvious incident when combined.

---

## 1. Network-Level Detection

### Data sources

| Source | What it provides |
|---|---|
| Firewall logs | Allow/deny decisions, IPs, ports, sessions |
| NetFlow / IPFIX | Metadata only (source, destination, bytes, duration), no payload |
| Full packet capture (PCAP) | Every packet; the most accurate but expensive to store |
| IDS/IPS (Snort, Suricata) | Alerts from signatures and rules |
| Zeek | Structured logs (conn, dns, http, ssl) |
| DNS logs | Every query made, a goldmine for detection |
| Proxy / web gateway | URLs and categories |
| Email gateway | Phishing and malicious attachments |

### Detection methods

1. **Signature-based:** matches known patterns. Precise with few false positives, but blind to zero-days.
2. **Anomaly-based:** learns a baseline and alerts on deviation. Finds new threats but produces more false positives.
3. **Stateful protocol analysis:** compares protocol behavior against its specification, for example HTTP on an unusual port or DNS that does not behave like DNS.
4. **Threat intelligence / IOC matching:** compares IPs, domains, and hashes against known-bad lists.

### Behaviors detectable on the network

- **Beaconing:** periodic, regular connections from a host to a command-and-control (C2) server. Defenders look for fixed intervals; malware that adds jitter requires statistical analysis.
- **DNS tunneling:** long, high-entropy subdomains, unusual query volume, and heavy use of TXT records.
- **Scanning:** one host probing many ports or many hosts in a short time.
- **Lateral movement:** SMB, RDP, or WinRM between machines that should not talk to each other (East-West traffic).
- **Data exfiltration:** large uploads to external destinations or at odd hours.

### Blind spots

The main blind spot is **encryption (TLS)**. Partial answers include analyzing metadata such as SNI, JA3/JA3S fingerprints, and certificate details, or using TLS inspection where deployed. East-West traffic is also invisible without internal sensors.

### Containment at the network level

- Move the host into an isolated or quarantine VLAN
- Block the malicious IP or domain on the firewall
- DNS sinkholing for malicious domains
- ACLs to restrict traffic between segments

---

## 2. Host Perimeter: Manual Live Response

The Host Perimeter is the set of commands an analyst runs by hand once a machine is suspected. It is **reactive**: it answers the question *"who is talking to whom, and which process is responsible?"* All of this is **volatile data**, so it must be collected before any isolation or shutdown.

### Order of volatility

**Memory → Network state → Running processes → Disk → Logs → Backups**

Shutting a machine down early destroys the most valuable evidence.

### Linux live response

**Connections and listening ports**

```bash
netstat -antp            # all TCP connections with PID/process
netstat -tulpn           # listening ports
ss -antp                 # modern replacement (netstat is deprecated)
ss -o state established  # established connections with timers
```

Flags: `a` all, `n` numeric (faster, no DNS lookups), `p` process, `t/u` TCP/UDP, `l` listening only.

**Everything that is open: `lsof`**

On Linux everything is a file (regular files, sockets, pipes), so `lsof` links processes to both the network and the filesystem.

```bash
lsof -i -P -n            # all network connections
lsof -i :4444            # who owns a given port
lsof -p <PID>            # everything a process has open
lsof -u www-data         # everything a user has open
lsof +L1                 # files deleted from disk but still open
```

`lsof +L1` is one of the most valuable IR commands: attackers often run a binary and then delete it. The process keeps running and the file appears marked `(deleted)`.

**Drilling into a suspicious PID**

```bash
ls -l /proc/<PID>/exe                     # the real binary
cat /proc/<PID>/cmdline | tr '\0' ' '     # how it was launched
ls -l /proc/<PID>/cwd                     # working directory
ls -l /proc/<PID>/fd                      # open file descriptors
cp /proc/<PID>/exe /mnt/evidence/bin      # recover a deleted binary
sha256sum /mnt/evidence/bin
```

**Users, persistence, and recent changes**

```bash
ps auxf ; w ; who ; last -a ; lastb
crontab -l ; ls -la /etc/cron*
systemctl list-units --type=service --state=running
find / -mtime -1 -type f 2>/dev/null       # modified in the last day
find / -perm -4000 -type f 2>/dev/null     # SUID files
```

### Windows live response

**Baseline: document the time first**

```cmd
date /t & time /t
hostname
whoami /all
systeminfo
ipconfig /all
```

**Network state**

```cmd
netstat -ano                    :: connections + PID
netstat -anob                   :: + executable name (needs Admin)
netstat -rn                     :: routing table
arp -a                          :: ARP cache
ipconfig /displaydns            :: DNS cache (domains visited)
net session                     :: who is connected remotely
net use ; net share             :: mapped and shared resources
netsh interface portproxy show all   :: port forwarding used for pivoting
```

```powershell
Get-NetTCPConnection -State Established |
  Select LocalPort,RemoteAddress,RemotePort,OwningProcess
```

**Processes**

```cmd
tasklist /v ; tasklist /svc ; tasklist /m
wmic process get name,processid,parentprocessid,commandline,executablepath
```

```powershell
Get-CimInstance Win32_Process |
  Select ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath
Get-FileHash C:\path\file.exe -Algorithm SHA256
(Get-AuthenticodeSignature C:\path\file.exe).Status
```

`wmic` is removed in recent Windows 11 builds, so `Get-CimInstance` is the replacement. Useful Sysinternals tools: `procexp`, `tcpview`, `handle`, `listdlls`, `sigcheck`, `autorunsc`.

**Users and persistence**

```cmd
net user ; net localgroup administrators ; query user
schtasks /query /fo LIST /v
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
autorunsc.exe -a * -c -h -s > E:\evidence\autoruns.csv
```

**Files and event logs**

```cmd
dir /r                                  :: reveals Alternate Data Streams
certutil -hashfile <file> SHA256
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:20 /rd:true /f:text
wevtutil epl Security E:\evidence\Security.evtx   :: export as evidence
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=(Get-Date).AddHours(-24)}
```

### Key Windows Event IDs

| ID | Meaning |
|---|---|
| 4624 / 4625 | Successful / failed logon (Type 3 = network, Type 10 = RDP) |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned |
| 4688 | Process creation (enable command-line auditing) |
| 4698 | Scheduled task created |
| 4720 / 4732 | User created / added to a group |
| 7045 | New service installed |
| 1102 / 104 | Security / System log cleared (a strong red flag) |
| 4104 | PowerShell script block logging |

### What to look for

| Observation | Likely meaning |
|---|---|
| `powershell.exe` or `winword.exe` with an ESTABLISHED external connection | Reverse shell or C2 |
| Listening on an odd port (4444, 1337, 31337) | Backdoor or bind shell |
| Many `SYN_SENT` to different IPs | The host is scanning |
| A system process (`svchost`) connecting to an unusual IP | Possible process injection |
| Listening on `0.0.0.0` instead of `127.0.0.1` | Service exposed to the network |
| `(deleted)` in `lsof` output | Malware removed from disk but still running |

### Cautions

1. **The tools themselves can be compromised.** With a rootkit, `netstat`, `ps`, and `ls` can lie. Use trusted, statically linked tools from read-only external media, and cross-check (for example `ps` against `/proc`, or `netstat` against `ss`).
2. **Every command changes something** (memory, access times). Record each command with its timestamp and store output on external media, not on the suspect machine.
3. **It is a snapshot.** A beacon that fires every 60 seconds may not appear in a single run. Continuous telemetry (Sysmon, EDR) covers that gap.

---

## 3. Host Level: Continuous Detection Tools

Where the Host Perimeter is manual and reactive, the Host Level is **continuous and automatic**. The tools evolve from the simplest to the most capable: Antivirus, HIDS, EDR.

### 3.1 Antivirus (AV)

AV is the first layer and its goal is **prevention**, not investigation.

| Method | How it works | Strength | Weakness |
|---|---|---|---|
| Signature-based | Matches a hash or byte pattern against a malware database | Fast, few false positives | Misses anything new; trivial changes break it |
| Heuristic | Scores file traits (strings, suspicious imports, structure) | Catches new variants | More false positives |
| Behavioral | Watches runtime behavior (mass file writes, registry changes) | Catches modified malware | Detects only after execution starts |
| Sandbox / emulation | Runs the file in isolation first | Unpacks packed malware | Malware can detect the sandbox |
| Cloud reputation / ML | Queries reputation or applies a model | Fast coverage of new threats | Needs connectivity; false positives |

**Blind spots:**

- **Fileless malware** running in memory through PowerShell or WMI
- **Living-off-the-Land (LOLBins):** abusing built-in tools such as `certutil` and `mshta`
- **Obfuscation, packing, and crypters**
- **Zero-days:** no signature exists yet
- **Tampering:** an admin-level attacker can disable AV or add exclusions

### 3.2 HIDS (Wazuh / OSSEC)

A host-based IDS relies on **logs and changes**, not malware signatures.

- **Log analysis:** rules over Windows Security events and Linux `auth.log`
- **File Integrity Monitoring (FIM):** hashes sensitive files and registry keys and alerts on change
- **Rootkit detection:** looks for hidden processes and ports
- **Security Configuration Assessment (SCA):** checks hosts against CIS benchmarks
- **Active Response:** automatic actions such as blocking an IP

### 3.3 EDR (Endpoint Detection and Response)

The philosophical difference:

> AV asks: **"Is this file malicious?"**
> EDR asks: **"Is this behavior normal?"**

**Architecture**

1. A lightweight **agent** (often kernel-level) runs on the endpoint
2. **Telemetry** is collected continuously: process creation, network connections, file and registry changes, DLL loads
3. Data is shipped to a **backend / cloud** data lake
4. Analysis happens there using rules, behavioral analytics, ML, and threat intelligence
5. An **alert** reaches the SOC with full context
6. **Response** actions are executed from the console

**Detection approaches**

- **IOA (Indicators of Attack):** looks at intent and behavior, such as "Word spawned PowerShell, which then connected to the internet." More durable than IOCs because it does not depend on a hash or IP that can change.
- **IOC matching:** known hashes, IPs, and domains
- **MITRE ATT&CK mapping:** each alert tied to a technique (for example `T1059.001`, PowerShell)
- **Process tree / attack storyline:** the full chain of events instead of isolated alerts
- **Threat hunting:** proactive queries over stored telemetry

**Response capabilities** (where detection connects to containment)

- Network isolation while keeping the console connection
- Kill or suspend a process
- Quarantine a file
- Remote shell / live response (the same commands from the Host Perimeter, run remotely)
- Collect artifacts and memory dumps
- Rollback (in some products), for example to reverse ransomware encryption

**EDR vs XDR vs MDR**

- **EDR:** endpoint only
- **XDR:** correlates endpoint, network, email, and cloud in one platform
- **MDR:** a managed service where an external team monitors for you

### Comparison

| | Antivirus | HIDS | EDR |
|---|---|---|---|
| Goal | Prevention | Detect changes and log events | Detect, investigate, respond |
| Basis | Signatures | Logs and FIM | Behavior and telemetry |
| Visibility | The file | Events and files | Full context (storyline) |
| Response | Quarantine | Limited active response | Isolation, kill, remote shell |
| Fileless detection | Weak | Partial | Strong |
| Cost | Low | Low (open source) | High |

### Containment at the host level

- Isolate the host through the EDR (it stays online but cut off)
- Stop the malicious process or service
- Disable the compromised account or reset its credentials
- **Capture a memory dump before stopping anything**

---

## 4. Application-Level Detection

The application level answers a different question: **"Is this user or request using the application as intended?"** Here the visibility is on **logic**: who logged in, what was queried, which parameters were sent. A malicious request can pass the firewall and IPS as perfectly normal HTTPS on port 443 and still be an attack from the application's point of view.

### 4.1 Web shells

A web shell is a script (ASPX, PHP, JSP) uploaded to a server and used as a persistent backdoor.

**How they are planted**

- A file upload vulnerability
- Exploiting a CMS or plugin flaw
- Remote code execution followed by writing a file
- Stolen credentials (FTP, admin panel)

**Types**

- **One-liner:** a tiny snippet that executes whatever it receives; hard to catch with signatures
- **Full-featured** (China Chopper, c99, WSO, b374k): a complete interface for file management, command execution, and database access
- **Obfuscated:** encoded with base64 or hidden behind `eval`

**Detection methods**

| Method | What it looks for |
|---|---|
| File-based | New or modified files in the web root (FIM); `.aspx`/`.php` files inside uploads or images folders |
| Content-based | Dangerous functions: `eval`, `exec`, `system`, `base64_decode`, `Process.Start`, `cmd.exe` |
| Log-based | Repeated requests to one file, usually POST, from an unusual IP |
| Behavior-based | Process tree: `w3wp.exe` spawning `cmd.exe` or `powershell.exe` |

### 4.2 Analyzing IIS logs

Default location: `C:\inetpub\logs\LogFiles\W3SVC1\`

Important fields: `date`, `time`, `c-ip`, `cs-method`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `cs(User-Agent)`, `sc-bytes`, `time-taken`.

**What to look for**

- POST requests to unusual files, especially in upload folders
- Status 200 on a file that should never be requested
- SQL injection markers (`union select`, `xp_cmdshell`) in `cs-uri-query`
- Traversal patterns (`..%2f`, `%252e`)
- Scanner User-Agents (`sqlmap`, `Nikto`)
- Waves of 401/403 (brute force), many 404s (scanning), and 500s (a partially successful injection)
- High `time-taken` on a single request (a long-running command or a `sleep`)
- A file requested rarely and from only one IP, with a small constant response size

**Useful commands**

```cmd
%windir%\system32\inetsrv\appcmd list sites
%windir%\system32\inetsrv\appcmd list wp          :: worker processes (w3wp)
forfiles /p C:\inetpub\wwwroot /s /m *.aspx /d -7 /c "cmd /c echo @path @fdate @ftime"
findstr /s /i /m /c:"eval(" /c:"Process.Start" /c:"cmd.exe" C:\inetpub\wwwroot\*.aspx

cd C:\inetpub\logs\LogFiles\W3SVC1
findstr /i "POST" u_ex*.log | findstr /i "uploads"
findstr /i "cmd.exe whoami powershell certutil" u_ex*.log
```

```powershell
# Any child process of w3wp.exe is a very strong indicator
$w3 = (Get-Process w3wp -EA SilentlyContinue).Id
Get-CimInstance Win32_Process | Where {$_.ParentProcessId -in $w3} |
  Select ProcessId,Name,CommandLine
```

Related Windows events: `4688` / Sysmon `1` (child of `w3wp.exe`), `4624` Type 3 (remote logon after compromise), and `7045` (new service used for persistence). Analysis tools include Log Parser, PowerShell, Splunk, and Wazuh.

### 4.3 Application protection tools

**WAF (Web Application Firewall)** sits in front of the application as a reverse proxy and inspects HTTP/HTTPS at Layer 7.

- *Negative model (blacklist):* rules for known attack patterns (for example OWASP CRS)
- *Positive model (whitelist):* defines what a normal request looks like and blocks the rest
- *Anomaly scoring:* rules add points; crossing a threshold blocks the request
- *Virtual patching:* a temporary rule that shields a known vulnerability until developers fix it

Weaknesses: encoding evasion, business-logic attacks (a tampered price looks like a valid request), encrypted traffic without TLS termination, and direct access to the origin server that bypasses the WAF.

**RASP (Runtime Application Self-Protection)** runs *inside* the application. A WAF guesses from outside; RASP sees what actually executed, such as user input reaching a SQL query. That gives high-confidence blocking, at the cost of performance overhead and language-specific agents.

**DAM (Database Activity Monitoring)** watches the database independently of the application, including DBAs. It detects mass `SELECT` (exfiltration), access to sensitive tables, `GRANT` or new users, and unapproved `DROP`/`ALTER`. It catches attacks even if they passed the WAF, and it catches insider threats.

| | WAF | RASP | DAM | App logs + SIEM |
|---|---|---|---|---|
| Location | In front of the app | Inside the app | At the database | In the SIEM |
| Sees | HTTP requests | Actual execution | Queries | Events and context |
| Can block | Yes | Yes | Usually no | No (alerts) |
| False positives | Medium | Low | Low | Depends on rules |
| Strongest at | Injection, scanners | Zero-days in code | Data theft, insiders | Brute force, logic abuse |

### 4.4 Authentication and API behaviors

- **Brute force:** many failures on one account
- **Password spraying:** one password tried across many accounts to avoid lockout
- **Credential stuffing:** leaked credentials replayed across many accounts
- **Impossible travel:** logins from two countries in an impossible time
- **MFA fatigue:** repeated MFA prompts until the user approves
- **BOLA/IDOR:** changing an ID in an API request to read another user's data

### Containment at the application level

This follows the web shell scenario, which is the typical case:

1. **Preserve evidence:** copy the shell and the logs, and hash them, before deleting anything
2. **Isolate:** take the server off the network or into maintenance mode
3. **Block** the IPs that used the shell
4. **Rotate** every credential the server could access (database connection strings, service accounts, API keys); revoke sessions
5. **Hunt for additional shells:** attackers usually plant more than one
6. **Fix the original vulnerability** before bringing the server back, or it will be compromised again

Other options: a WAF virtual patch, disabling the affected endpoint, and restricting or isolating the database account.

---

## 5. Correlation: Connecting the Levels

Correlation is what turns scattered low-severity events into one clear incident. Consider a phishing-to-web-shell scenario:

1. **Email gateway:** a message with a suspicious link arrives
2. **Proxy / DNS:** the user visits a domain registered only days ago
3. **Host (Sysmon/EDR):** an unusual process starts and makes a new external connection
4. **Network:** beaconing begins
5. **Application:** a login from an unfamiliar IP, followed by a file upload into the uploads folder
6. **Host again:** `w3wp.exe` spawns `cmd.exe`
7. **SIEM:** a correlation rule links all of it into a single high-severity alert

Any one of these events might be dismissed alone. Together they tell a story, and building that story is the core skill of Detection & Analysis.

---

## 6. Containment Strategy

### Short-term vs long-term

| | Short-term | Long-term |
|---|---|---|
| Goal | Stop the damage quickly | Hold the situation stable until eradication |
| Examples | Isolate the host, block an IP | Temporarily patched system, new segmentation, a clean system built in parallel |

### Speed versus evidence

The central tension in containment is **speed of isolation versus preservation of evidence**. Practical rules:

- Capture memory first (for example with WinPmem or LiME), then network state, then processes, then disk
- Prefer **isolation** (host stays powered on but cut off) over shutdown
- Prefer `kill -STOP <PID>` over `kill -9` on Linux to keep the process in memory for analysis; on Windows, `taskkill /F` destroys memory evidence, so dump first
- Document everything and maintain chain of custody (hash evidence, record times and commands)
- Remember the business impact: containment decisions affect availability

### Containment commands (Windows CLI)

```cmd
netsh advfirewall firewall add rule name="Block C2" dir=out action=block remoteip=<IP>
net user <username> /active:no
net localgroup administrators <user> /delete
sc stop <service> & sc config <service> start= disabled
schtasks /delete /tn "TaskName" /f
taskkill /PID <PID> /F        :: destroys memory evidence: dump memory first
```

Disabling the network interface entirely is a last resort, since it will cut off a remote session as well.

---

## Conclusion

Effective detection is layered. The **network** shows communication patterns, the **Host Perimeter** gives an analyst a live view of one suspect machine, the **Host Level** (AV, HIDS, EDR) watches behavior continuously, and the **application level** exposes attacks that look legitimate to every lower layer. Each level has blind spots, and only correlation across them produces a reliable picture.

Containment then mirrors the same structure: network blocks, host isolation, and application-level fixes, always balanced against the need to preserve volatile evidence.

**Key takeaways**

- No single tool or level sees everything
- Collect volatile data in order of volatility, before isolating or shutting down
- AV asks whether a file is bad; EDR asks whether behavior is normal
- Web shells are best caught by combining file, content, log, and process-tree evidence
- Fix the root cause before restoring a contained system

