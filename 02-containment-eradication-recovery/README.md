# Containment, Eradication, Recovery, and Post-Incident Activity

### Part 2: A Practical Study Guide

*Study notes based on the INE IHRP / eCIR learning path. Continues [Part 1: Detection and Containment](../01-detection-and-containment/).*

> **Educational purpose only.** Run commands only on systems you own or are explicitly authorized to investigate.

## Table of Contents

- [Introduction](#introduction)
- [1. Before Containment: Decisions That Come First](#1-before-containment-decisions-that-come-first)
- [2. Containment](#2-containment)
- [3. Eradication](#3-eradication)
- [4. Recovery](#4-recovery)
- [5. Post-Incident Activity](#5-post-incident-activity)
- [6. End-to-End Example: A Compromised IIS Web Server](#6-end-to-end-example-a-compromised-iis-web-server)
- [Conclusion](#conclusion)

---

## Introduction

[Part 1](../01-detection-and-containment/) covered how to **detect** an incident at the network, host, and application levels. This part continues the incident response (IR) life cycle from the moment an incident is confirmed:

```
Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident Activity
```

| Phase | Goal | Key question |
|---|---|---|
| Preparation | Be ready before anything happens | Do we have the people, tools, and plans? |
| Detection & Analysis | Find the incident and scope it | What happened, where, and how bad is it? |
| **Containment** | Prevent the incident from getting worse | How do we limit the damage right now? |
| **Eradication** | Eliminate the intruder's artifacts and understand the root cause | What must be removed, and how did they get in? |
| **Recovery** | Restore systems and monitor | Can we safely go back to normal, and did anything evade detection? |
| **Post-Incident Activity** | Learn and improve | What do we change so this is harder next time? |

Two ideas from the detection phase matter again here. First, the **levels of detection** (network perimeter, host perimeter, host level, application level) tell us *where* to contain and eradicate. Second, the **baseline** (what normal looks like) is what lets us confirm during recovery that things are back to normal.

---

## 1. Before Containment: Decisions That Come First

Containment is not the first thing you do the moment you see an alert. A few questions have to be answered first, because a rushed containment can destroy evidence, tip off the attacker, or miss part of the intrusion.

### 1.1 Is it a malicious insider or not?

This changes how you work, not just what you find.

- An insider knows the environment, may have admin rights, and may be reading the same email, chat, and tickets that the response team uses.
- Keep the circle small (need-to-know), use channels the suspect cannot read, and involve HR and legal early.
- Preserve evidence more carefully, because the case may become disciplinary or legal.
- An external attacker and an insider need different containment: disabling an insider's account may be the right first move, while for an external attacker it may only tell them they were seen.

### 1.2 Isolate the area under investigation

Define a boundary around what is being investigated and keep everything else out of it.

- Limit access to the affected systems, segment, or room (physical access matters too).
- Tell staff not to log in, reboot, "clean up," or run their own antivirus on the affected machines.
- This prevents well-meaning people from altering evidence and prevents the incident from spreading through normal use.

### 1.3 Use incident forms

Standardized forms (the course notes call them incident casualty forms) record the details while they are fresh:

- Who reported it and when
- Affected systems, accounts, and data
- Symptoms observed
- Every action taken, with timestamps and the person who took it
- Who handled which piece of evidence

These forms feed the chain of custody and later become the backbone of the incident report.

### 1.4 Classify the incident: type, impact, extent

| Dimension | Question | Examples |
|---|---|---|
| **Type** | What kind of incident is it? | Malware, ransomware, phishing, unauthorized access, web compromise, DoS, insider threat |
| **Impact** | What does it affect? | Critical systems (domain controller, payment system) vs non-critical systems |
| **Extent** | How far has it spread? | One host, one segment, many hosts, many accounts |

The course notes link impact to the containment approach:

- **Affects critical systems → short-term containment** (act immediately to stop the damage)
- **Does not affect critical systems → long-term containment** (a planned approach with less urgency)

In practice, critical systems also need close coordination with the business owner, because taking them offline has its own cost.

### 1.5 Act normally

Until you are ready to contain, behave as usual. Sudden visible changes (mass password resets, emergency announcements, shutting down servers) can tell a capable attacker that they have been discovered. They may then destroy evidence, deploy ransomware early, or dig in deeper. The goal is to prepare quietly and then contain in a coordinated way.

### 1.6 Tools that support the process

- **RTIR (Request Tracker for Incident Response):** a ticketing system built for IR teams. It tracks incidents, assignments, communications, and **escalation** in one place.
- **Security Onion:** a free, open platform for network security monitoring, threat hunting, and log management. It bundles tools such as Suricata, Zeek, and the Elastic stack, which support both detection and the scoping needed before containment.

---

## 2. Containment

**Goal:** prevent the incident from getting worse (stop it spreading and limit damage) while preserving evidence for the investigation.

The course divides containment into three forms:

| Form | Purpose | Typical timing |
|---|---|---|
| **Short-term containment** | Stop the damage immediately | First minutes to hours |
| **System backup** | Preserve a forensic copy of the evidence | Before changes that would destroy it |
| **Long-term containment** | Hold the situation stable while a clean system is prepared | Hours to days or longer, until eradication |

### 2.1 Short-term containment

Quick actions that stop the bleeding without necessarily fixing the problem.

**Common actions**

- Isolate the host from the network (EDR isolation, unplug the cable, move to a quarantine VLAN)
- Block malicious IPs and domains on the firewall or proxy; sinkhole malicious DNS
- Disable or lock compromised accounts; revoke active sessions and tokens
- Stop a malicious process or service, ideally after capturing memory
- Take a compromised web application into maintenance mode or add a WAF block rule

**Example: ransomware on a file server**

1. Disconnect the server from the network (do not power it off, so memory stays available)
2. Disable the account that launched the encryption
3. Block the C2 IP and domain at the firewall
4. Isolate the file server's VLAN from the rest of the network
5. Capture memory and start forensic acquisition (section 2.2)

**Canary tokens**

Canary tokens are small decoys that raise an alert the moment someone touches them. They are a form of **deception**, and they help the team watch for the attacker's activity during containment without relying only on the attacker's mistakes elsewhere.

Examples of tokens:

- A fake document (such as `passwords.xlsx`) that alerts when opened
- A fake cloud access key placed on a compromised host that alerts when used
- A fake URL or DNS name that alerts when resolved

If the attacker later opens the fake file or tries the fake key, you learn which host they are on, when, and from where. Free generators such as canarytokens.org make these easy to create.

**Trade-offs of short-term containment**

- Speed versus evidence: acting too fast can destroy volatile data
- Speed versus visibility: blocking everything at once may stop you from seeing what the attacker does next
- Availability: isolating a production system affects the business

### 2.2 System backup (forensic data acquisition)

Before you change a compromised system, take a **forensically sound copy** of it. This protects the evidence and lets the team analyze a copy while the original goes back into the process.

**Data acquisition** means collecting data from a device in a way that does not alter it and can be proven in court or in an internal case. There are two kinds, based on the type of data:

| | Dynamic (live) acquisition | Static acquisition |
|---|---|---|
| **Data** | Volatile data | Non-volatile data |
| **System state** | Still powered on | Usually powered off, or the drive removed |
| **Examples** | RAM, running processes, network connections, logged-in users, open files | Hard disks, SSDs, USB flash drives |
| **Risk** | Collection itself changes the system slightly | Powering off first destroys volatile data |

**Dead acquisition** is acquisition from a powered-off system, for example by removing the drive and connecting it to a forensic workstation (through a write blocker), or booting the machine from forensic media. It is the classic way to image a disk, and it is why the order of volatility matters: capture memory *first*, then power down if needed.

A special case: if the disk is encrypted (for example BitLocker), powering off may make the data unreadable. Capturing it while the system is live, with the volume unlocked, may be the only chance.

**Acquisition approaches**

| | Imaging (disk to image file) | Cloning (disk to disk) |
|---|---|---|
| **What it does** | Copies the source drive into one or more image files | Copies the source drive onto another drive, sector by sector |
| **Output** | Image file (raw/dd, E01, AFF), can be compressed and split, and can carry case metadata | A second physical drive identical to the source |
| **Advantages** | Easy to store, make copies of, and hash; many tools read it directly | The copy can be mounted or booted directly for review |
| **Considerations** | Needs enough storage; analysis tools must open the format | Target must be the same size or larger and **wiped first**; one wrong target destroys data |

**Write blockers**

A write blocker sits between the evidence drive and your workstation and allows **read commands only**. It prevents the operating system from writing to the evidence (for example, updating timestamps or journals) and is standard whenever you image a disk.

- **Hardware write blockers** (for example Tableau units) are the most trusted
- **Software write blockers** (for example read-only mounts or registry-based blocking) are an alternative when hardware is not available

**Evidence integrity with hash functions**

A hash function (SHA-256 is the common choice; MD5 and SHA-1 are often reported too for compatibility) produces a fixed fingerprint of the data. You hash the **source** and the **copy**. If the hashes match, the copy is bit-for-bit identical and unchanged. Any later change to the evidence changes the hash, so hashes also protect the **chain of custody**.

**Example workflow (Linux)**

```bash
# 1. Make the evidence drive read-only
sudo blockdev --setro /dev/sdb

# 2. Image it with hashing and logging (dc3dd)
sudo dc3dd if=/dev/sdb of=/mnt/evidence/disk.dd hash=sha256 log=/mnt/evidence/acquisition.log

# 3. Verify: the hash of the source and the image must match
sudo sha256sum /dev/sdb
sha256sum /mnt/evidence/disk.dd

# Cloning to another drive (DANGEROUS: of= must be the correct, wiped target)
sudo dd if=/dev/sdb of=/dev/sdc bs=4M conv=noerror,sync status=progress
```

**Example workflow (Windows)**

```cmd
:: Memory first (live acquisition)
winpmem_mini_x64.exe E:\evidence\mem.raw

:: Disk image: FTK Imager > File > Create Disk Image > Physical Drive > E01
:: Fill in case details, then use "Verify" to compare the hashes
```

Always:

1. Image from a write-protected source
2. Hash source and copy, and record both
3. Work on a **copy**, never on the original
4. Document who did what and when (chain of custody)
5. Store the original securely and make more than one verified copy

### 2.3 Long-term containment

Long-term containment keeps the incident from causing more harm while the team prepares a clean solution. It is used when the system cannot simply be switched off, or when a full rebuild takes time.

**Communicate with the ISP**

The course notes highlight contacting the **Internet Service Provider (ISP)**, because the ISP has visibility into traffic that you do not:

- Upstream filtering or blackholing of malicious traffic
- Help with large denial-of-service attacks (scrubbing, rate limiting)
- Tracing the source of attack traffic
- Support for takedown requests

The same idea applies to cloud and hosting providers.

**Other long-term actions**

- Build a clean replacement system in parallel and prepare to cut over
- Apply temporary fixes: patches, WAF virtual patches, configuration changes
- Change network segmentation and tighten ACLs around the affected area
- Reset credentials and rotate secrets for everything the attacker could have reached
- Increase logging and monitoring on the affected area to watch for further activity

**Example: DDoS against a public website**

1. Short-term: enable rate limiting and block the loudest sources
2. Long-term: work with the ISP for upstream filtering and use a scrubbing service while the website stays online

### 2.4 Containment at a glance

| | Short-term | System backup | Long-term |
|---|---|---|---|
| **Purpose** | Stop the damage fast | Preserve evidence | Keep stable until eradication |
| **Examples** | Isolate host, block IP, disable account, canary tokens | Memory capture, disk imaging, hashing | ISP coordination, parallel clean system, temporary patches |
| **Main risk** | Destroying evidence or alerting the attacker | Altering evidence if done wrongly | Attacker staying in place for longer |

---

## 3. Eradication

**Goal:** eliminate the intruder's artifacts and **understand the root cause**, including the attack vector and the attacker's tactics, techniques, and procedures (TTPs). Eradication only works if the investigation has produced a clear picture of what was touched and how the attacker got in.

### 3.1 Identify the root cause

Questions to answer:

- What was the **initial access** (phishing, exposed RDP, vulnerable web application, stolen credentials, supply chain, insider)?
- Which **vulnerability or weakness** made it possible?
- Which systems, accounts, and data were affected (the full scope)?
- Which **TTPs** did the attacker use? Mapping them to MITRE ATT&CK makes them reusable for detection.

If you remove the malware but not the way in, the attacker comes back.

### 3.2 Remove the intruder's artifacts

| Artifact | Examples | How to find it |
|---|---|---|
| Malware and tools | Backdoors, RATs, credential dumpers | EDR, AV, hash and IOC sweeps |
| Persistence | Run keys, scheduled tasks, new services, cron jobs, WMI subscriptions, startup items | `autorunsc`, `schtasks`, `sc query`, `crontab -l` |
| Web shells | `.aspx`/`.php` files in upload folders | FIM, content search, IIS logs |
| Accounts and keys | Rogue users, added SSH keys, API keys | Account review, `net user`, `authorized_keys` |
| Network footholds | Port forwarding, tunnels, firewall changes | `netsh interface portproxy`, firewall review |

### 3.3 Forms of eradication

1. **Clean:** remove the malware and persistence from the existing system (suitable for minor, well-understood infections)
2. **Rebuild / reimage:** wipe the system and reinstall from a known-good image (the safest choice after a serious compromise)
3. **Restore from a clean backup:** use a backup that predates the compromise, after checking the date of initial access
4. **Replace:** swap hardware when firmware or low-level components may be compromised

Cleaning a deeply compromised system is risky, because you cannot be sure you found everything. For serious incidents, rebuilding is usually preferred.

### 3.4 Close the way in

- Patch the exploited vulnerability or disable the exposed service
- Fix configuration weaknesses (weak passwords, missing MFA, open RDP)
- Reset **all** credentials the attacker may have seen. In an Active Directory compromise this can include the `krbtgt` account (reset twice) when forged Kerberos tickets are suspected
- Revoke tokens, sessions, and API keys
- Add detection rules for the observed TTPs and block the known IOCs

### 3.5 Verify

Before moving on, confirm the eradication worked: rescan for the IOCs across the environment, re-run persistence checks, review EDR and SIEM for any sign of the attacker, and have a second analyst check the result.

---

## 4. Recovery

**Goal:** restore systems to normal operation and **monitor** closely to make sure nothing evaded detection.

The course breaks recovery into three parts:

| Part | Focus |
|---|---|
| **Process: system recovery** | Rebuild and restore everything that was affected |
| **Restore of operation** | Bring services back, in coordination with the business |
| **Monitoring** | Watch statistics, network traffic, and logs for signs of the attacker |

### 4.1 System recovery (include everything)

The recovery plan has to cover **every layer** that was affected, not just the one that was obvious:

- Operating system and applications (rebuild from golden images)
- Data (restore from backups verified as clean and dated before the compromise)
- Configuration (hardened settings, firewall rules, security agents reinstalled)
- Accounts and secrets (new passwords, keys, certificates)
- Network (rules and segmentation changed during containment)

Then validate:

- Compare file hashes and the FIM baseline against known-good values
- Patch **before** reconnecting to the network
- Test in an isolated environment, then reintroduce systems in phases

### 4.2 Restore of operation (consult the business unit)

Technical readiness is not enough. The business unit decides priorities and timing.

- Which services come back first (based on business impact)?
- What are the **RTO** (how fast must it be restored?) and **RPO** (how much data loss is acceptable?)?
- When is the best maintenance window?
- Who tests that the service works correctly (user acceptance testing)?
- How are users informed?

### 4.3 Monitoring

After recovery, the risk is that the attacker was missed or returns. Monitoring is heightened for a defined period (often weeks to months, depending on severity).

| Monitor | What to watch |
|---|---|
| **Statistics** | Login failure rates, bandwidth, process counts, CPU, deviations from the **baseline** |
| **Network traffic** | Connections to known-bad IPs and domains, new beaconing patterns, DNS anomalies, unusual outbound volume |
| **Logs** | Authentication logs, EDR and SIEM alerts, web server logs (for example repeated requests to a former web shell path) |

Useful additions: detection rules built from the attacker's TTPs, canary tokens left in sensitive places, and a clear process for what to do if the old behavior reappears (return to containment).

---

## 5. Post-Incident Activity

**Goal:** learn from the incident and improve. The main output is a **report**.

### 5.1 Lessons-learned meeting

Hold it soon after the incident is closed, while details are fresh, with everyone involved (IR team, IT, business, legal as needed). Keep it blameless and focused on improvement:

- What happened and how was it detected?
- What worked well, and what did not?
- Were procedures followed? Were tools and access adequate?
- What would we do differently?

### 5.2 The incident report

| Section | Contents |
|---|---|
| Executive summary | What happened, impact, status, in plain language |
| Timeline | Detection, containment, eradication, and recovery times |
| Root cause | Attack vector, vulnerability, attacker TTPs |
| Scope and impact | Systems, accounts, data, business effect |
| Actions taken | What was done, by whom, and when |
| Evidence | What was collected, hashes, chain of custody |
| Recommendations | Specific, assigned, and dated improvements |

### 5.3 Improve

- Update playbooks, detection rules, and baselines
- Fix the control gaps found (patching, MFA, logging, segmentation)
- Share IOCs with trusted partners and communities, respecting data-sharing markings such as TLP
- Track metrics, for example time to detect, time to contain, and time to recover
- Retain evidence as required by policy and law

---

## 6. End-to-End Example: A Compromised IIS Web Server

| Phase | What happens |
|---|---|
| **Detection & Analysis** | A WAF alert and IIS logs show repeated POST requests to a file in `/uploads/`. Sysmon shows `w3wp.exe` spawning `cmd.exe`. This is a **web shell** |
| **Before containment** | Check whether an insider is involved, restrict access to the server, open an incident form, classify: web compromise, impact on a public application, extent limited to one server |
| **Short-term containment** | Block the attacker's IPs, take the server out of the load balancer, add a WAF rule, and place canary tokens on the server's other file shares |
| **System backup** | Capture memory, then image the disk through a write blocker, hash the image, and copy the web shell and IIS logs |
| **Long-term containment** | Stand up a clean replacement server in parallel, rotate database credentials, and ask the ISP or CDN for upstream filtering if the attacker is still probing |
| **Eradication** | Root cause: a vulnerable file upload feature. Remove all web shells, rebuild the server from a clean image, patch the application, and rotate secrets |
| **Recovery** | Restore content from a clean backup (checked for shells), agree the go-live window with the business unit, bring the server back in phases, and monitor IIS logs and `w3wp.exe` child processes closely |
| **Post-incident** | Lessons-learned meeting, incident report, new detection rules for web shells, and a review of secure file upload practices |

---

## Conclusion

Containment, eradication, and recovery are a sequence, and each one depends on the one before it:

- **Containment** stops the damage, but it must be preceded by classification and followed by evidence preservation
- **Eradication** only works if the root cause and scope are understood
- **Recovery** is not finished at "the system is back": it ends only after a monitoring period confirms nothing evaded detection
- **Post-incident activity** turns one bad day into a stronger program

**Key takeaways**

- Classify the incident (type, impact, extent) before choosing a containment approach
- Act normally until you are ready, so you do not alert the attacker
- Short-term containment stops damage; system backup preserves evidence; long-term containment keeps things stable until eradication
- Dynamic acquisition captures volatile data; static acquisition captures non-volatile data; verify every copy with hashes
- Use write blockers, and never analyze the original evidence
- Eradication must include the root cause and every persistence mechanism, not just the visible malware
- Recovery needs the business unit and ends with monitoring against the baseline
- The incident report and lessons learned are part of the response, not an afterthought
