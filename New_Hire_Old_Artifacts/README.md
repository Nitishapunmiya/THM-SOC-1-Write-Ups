# TryHackMe — New Hire Old Artifacts 🔍



## Environment

| Field | Value |
|---|---|
| Host | DESKTOP-H1ATIJC |
| User | Finance01 |
| Log Source | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |
| SIEM | Splunk Enterprise |

---

## Investigation Walkthrough

---

### Q1 — A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? Enter the full path.

**Answer:** `C:\Users\FINANC~1\AppData\Local\Temp\11111.exe`

**Approach:**

I searched for the string "Password Viewer" across all indexes. NirSoft makes a well-known tool called **WebBrowserPassView** which is commonly abused by attackers for credential harvesting.

```spl
index=* "Password Viewer"
```

i got 27 events  i started looking at them manuallyb one by one and found this binary file 

---

### Q2 — What is listed as the company name?

**Answer:** `NirSoft`

**Approach:**

From the same search above (`index=* "Password Viewer"`), I clicked on the `Company` field in the Splunk sidebar. It showed `NirSoft` , confirming the tool's vendor identity.

---

### Q3 — Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? (format: file.xyz,file.xyz)

**Answer:** `IonicLarge.exe,PalitExplorer.exe`

**Approach:**

Since `11111.exe` was in `C:\Users\Finance01\AppData\Local\Temp\`, I searched for all process creation events (EventCode=1) from that same folder:

```spl
Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\*" EventCode=1
| table Image
```

This returned 2 results, both pointing to `IonicLarge.exe`.

I then searched for all events related to this binary:

```spl
IonicLarge.exe
```

This returned **189 events**.

Clicking on the `OriginalFileName` field in the sidebar revealed:

| OriginalFileName | Count | % |
|---|---|---|
| PalitExplorer.exe | 4 | 66.667% |
| 7zS.sfx.exe | 1 | 16.667% |
| UrlMon.dll | 1 | 16.667% |

The binary `IonicLarge.exe` had an original filename of `PalitExplorer.exe`, meaning the attacker renamed a known binary to blend in.

---

### Q4 — The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address? Enter the answer in a defang format.

**Answer:** `2[.]56[.]59[.]42`

**Approach:**

```spl
IonicLarge.exe EventCode=3
```

This produced **87 events**.
i looked at destination ports there were 3 ports 443,80, and 8888 firts i found 8888 suspicious so investigated that but ip was not suspicious then went for port 80 and found a malacious external ip 


```spl
IonicLarge.exe EventCode=3 DestinationPort=80
```

Result:

| IP | Count | % |
|---|---|---|
| 2.56.59.42 | 2 | 66.667% |
| 212.193.30.45 | 1 | 33.333% |

The IP `2.56.59.42` appeared twice and was identified as the malicious .

---

### Q5 — The same binary made changes to a registry key. What was the key path?

**Answer:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`

**Approach:**
first typed registry and then checked for eventcode 13 which is for registry value modification
```spl
IonicLarge.exe "Registry" EventCode=13
| table TargetObject
```

Registry values modified:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\
DisableRawWriteNotification
DisableIOAVProtection
DisableRealtimeMonitoring
DisableScanOnRealtimeEnable
DisableOnAccessProtection
DisableBehaviorMonitoring
DisableRoutinelyTakingAction
DisableAntiSpyware
```

The attacker attempted to weaken or disable Windows Defender protections.

---

### Q6 — Some processes were killed and associated binaries deleted. What were the names of the binaries?

**Answer:** `WvmIOrcfsuILdX6SNwIRmGOJ.exe,phcIAmLJMAIMSa9j9MpgJo1m.exe`

**Approach:**
already hint was provided that task were killed using taskkill/im so applied it as filter 

```spl
taskkill /im
| table ParentCommandLine
```

Recovered commands:

```cmd
"C:\Windows\System32\cmd.exe" /c taskkill /im "WvmIOrcfsuILdX6SNwIRmGOJ.exe" /f
& erase "C:\Users\Finance01\Pictures\Adobe Films\WvmIOrcfsuILdX6SNwIRmGOJ.exe" & exit

"C:\Windows\System32\cmd.exe" /c taskkill /im phcIAmLJMAIMSa9j9MpgJo1m.exe /f
& timeout /t 6 & del /f /q "C:\Users\Finance01\Pictures\Adobe Films\phcIAmLJMAIMSa9j9MpgJo1m.exe"
& del C:\ProgramData\*.dll & exit
```

---

### Q7 — What was the last PowerShell command used to modify Windows Defender behavior?

**Answer:**

```powershell
powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True
```

**Approach:**

```spl
powershell | table CommandLine,UtcTime | dedup CommandLine
```

The final command in the sequence whitelisted a threat ID in Defender.

---

### Q8 — What were the four Threat IDs added by the attacker?

**Answer:**

```text
2147735503,2147737010,2147737007,2147737394
```

---

### Q9 — Another malicious binary executed from AppData. What was its full path?

**Answer:**

```text
C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe
```

**Approach:**

```spl
Image="C:\\Users\\*\\AppData\\*.exe"
| table Image
| dedup Image
```

---

### Q10 — What DLLs were loaded by EasyCalc.exe?

**Answer:**

```text
ffmpeg.dll,nw.dll,nw_elf.dll
```

**Approach:**

```spl
Image="C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe" EventCode=7
| table ImageLoaded
```

These DLLs are associated with the NW.js framework.

---

## Attack Timeline Summary

```text
12/28/2021 08:06 PM → IonicLarge.exe executed
12/28/2021 08:07 PM → Connections to 2.56.59.42:80
12/28/2021 09:09 PM → 11111.exe (WebBrowserPassView) executed
12/29/2021 01:09 AM → Defender ThreatID exclusions added
12/29/2021 01:09 AM → Registry modifications to Defender
12/29/2021 02:09 AM → Malware cleanup using taskkill and file deletion
12/29/2021 02:09 AM → EasyCalc.exe executed from AppData\Roaming
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1555.003 — Credentials from Web Browsers | WebBrowserPassView |
| Execution | T1059.001 — PowerShell | WMIC commands |
| Defense Evasion | T1562.001 — Disable Security Tools | Defender registry modifications |
| Defense Evasion | T1036 — Masquerading | Renamed executables |
| Command & Control | T1071.001 — Web Protocols | HTTP traffic to C2 |
| Indicator Removal | T1070.004 — File Deletion | taskkill + delete |
| Persistence | T1547 (Possible) | BAM registry key |

---

## Key SPL Queries Used

```spl
# Find Password Viewer tool
index=* "Password Viewer"

# Find binaries executed from Temp folder
Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\*" EventCode=1
| table Image

# Network connections
IonicLarge.exe EventCode=3

# Port 80 traffic
IonicLarge.exe EventCode=3 DestinationPort=80

# Registry modifications
IonicLarge.exe "Registry" EventCode=13
| table TargetObject

# Cleanup commands
taskkill /im
| table ParentCommandLine

# PowerShell activity
powershell | table CommandLine,UtcTime | dedup CommandLine

# AppData executables
Image="C:\\Users\\*\\AppData\\*.exe"
| table Image
| dedup Image

# DLL loads
Image="C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe" EventCode=7
| table ImageLoaded
```

---

## Lessons Learned

- NirSoft tools running from Temp directories are strong indicators of credential theft.
- Sysmon's `OriginalFileName` field is useful for identifying renamed malware.
- WMIC and PowerShell are commonly abused to weaken Defender protections.
- NW.js applications can be abused to package malicious JavaScript-based malware.
- Attackers frequently stage malware in writable directories such as AppData and user folders.

---

*Writeup by [@Nitishapunmiya](https://github.com/Nitishapunmiya) | #StudentToSOC #BuildInPublic #Unhackd*The binary was **disguised with a generic numeric name** (`11111.exe`) and dropped in the `Temp` folder — classic attacker staging behavior.

