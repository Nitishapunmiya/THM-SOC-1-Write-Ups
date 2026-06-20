# TryHackMe: Investigating with Splunk



## Scenario
SOC Analyst Johny has observed some anomalous behaviours in the logs of a few Windows machines. It looks like the adversary has access to some of these machines and successfully created a backdoor. His manager has asked him to pull those logs from the suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

## Tools Used
- Splunk (Search & Reporting)
- CyberChef (Base64 decoding)

---

## Task: Investigate the Backdoor User Creation and PowerShell Activity

### 1. How many events were collected and ingested in the index `main`?

Started with a baseline search to see the full scope of ingested logs.

```spl
index=main
```

**Result:** `12,256 events`

---

### 2. On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

Windows Security Event ID `4720` logs "A user account was created" — a strong starting point for backdoor account creation.

```spl
index=main EventID=4720
```

This returned a single event on host `Micheal.Beaven`:

```
Subject:
    Account Name: James
    Account Domain: Cybertees

New Account:
    Account Name: A1berto
    Account Domain: WORKSTATION6
```

**Answer:** `A1berto`

> Note the `1` instead of `l` — a lookalike of the legitimate user `Alberto`, used to blend into normal account activity.

---

### 3. On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

Pivoted on the new username and filtered for registry value-set events (Sysmon EventCode 13):

```spl
index=main "A1berto" Category="Registry value set (rule: RegistryEvent)"
```

This returned a Sysmon event triggered by `lsass.exe`:

```
Image:        C:\windows\system32\lsass.exe
TargetObject: HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto\(Default)
```

**Answer:** `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

> SAM registry hive updates like this happen automatically whenever a new local user is created — `lsass.exe` is responsible for writing the new account into the SAM database.

---

### 4. Examine the logs and identify the user that the adversary was trying to impersonate.

While exploring the `User` field on the broader `index=main` search, four accounts stood out:

```
NT AUTHORITY\SYSTEM
Cybertees\Alberto
NT AUTHORITY\NETWORK SERVICE
Cybertees\James
```

A legitimate domain account named `Alberto` already exists in `Cybertees`. The backdoor account `A1berto` (with a numeral `1` replacing the lowercase `l`) was deliberately crafted to look like it at a glance.

**Answer:** `Alberto`

---

### 5. What is the command used to add a backdoor user from a remote computer?

Searched for the backdoor username alongside the process creation event (EventID 4688):

```spl
index=main "Alberto"
```

Found the originating event on host `James.browne`, executed by `Cybertees\James`:

```
Hostname: James.browne
Creator Subject:
    Account Name: James
    Account Domain: Cybertees

CommandLine: "C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
```

This confirms the adversary used WMIC to remotely spawn a process on `WORKSTATION6` (Micheal.Beaven's machine) and create the backdoor account.

**Answer:**
```
C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1
```

A follow-up search confirmed the corresponding local execution event on the target host:

```spl
index=main "Alberto" "net user /add" EventID=4688
```

```
Hostname:    Micheal.Beaven
CommandLine: net user /add Alberto paw0rd1
```

---

### 6. How many times was the login attempt from the backdoor user observed during the investigation?

Checked for successful logon events (EventID 4624) tied to the backdoor account:

```spl
index=main EventID="4624" "Alberto"
```

**Result:** `0 events`

**Answer:** `0`

> The backdoor account was created and configured, but the adversary never actually logged in with it during the window captured in these logs — likely caught before the account could be used.

---

## Task: Investigate the Malicious PowerShell Execution

### 7. What is the name of the infected host on which suspicious PowerShell commands were executed?

Searched broadly for any PowerShell-related activity across the index:

```spl
index=main "powershell"
```

198 events returned, all under:

```
Channel:  Windows PowerShell
Hostname: James.browne
```

Confirmed by grouping the results:

```spl
index=main "powershell"
| stats count by Hostname
```

```
Hostname        count
James.browne    187
```

**Answer:** `James.browne`

---

### 8. PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

PowerShell Script Block Logging (EventID 4104) and Module Logging (EventID 4103) capture the actual command content executed — narrower and more relevant than the general "powershell" keyword search above.

```spl
index=main EventID=4104 OR EventID=4103
```

**Result:** `79 events`

**Answer:** `79`

---

### 9. An encoded PowerShell script from the infected host initiated a web request. What is the full URL?

Extracted the encoded command from the `ContextInfo` field using a `rex` pattern, then deduplicated to isolate the unique command:

```spl
index="main" EventID="4104" OR EventID="4103"
| rex field=ContextInfo "Host Application = (?<Command>[^\r\n]+)"
| table Command
| dedup Command
```

This surfaced the full PowerShell invocation:

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc <Base64Blob>
```

Took the Base64 blob after `-enc` and decoded it in CyberChef (**From Base64** → **Remove null bytes**). The decoded script revealed an AMSI bypass routine followed by a web request:

```powershell
$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==')));$t='/news.php';
```

The script builds its callback address from a second, nested Base64 string. Decoding `aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==` separately in CyberChef gave:

```
http://10.10.10.5
```

Combined with the `$t='/news.php'` path appended by the script, the full beacon URL is:

**Answer (defanged):** `hxxp[://]10[.]10[.]10[.]5/news[.]php`

---

## Summary

| # | Question | Answer |
|---|----------|--------|
| 1 | Events ingested in index `main` | `12256` |
| 2 | Backdoor username created | `A1berto` |
| 3 | Registry key path for backdoor user | `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto` |
| 4 | User the adversary impersonated | `Alberto` |
| 5 | Remote command used to add backdoor user | `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1` |
| 6 | Login attempts observed from backdoor user | `0` |
| 7 | Infected host with malicious PowerShell | `James.browne` |
| 8 | Events logged for malicious PowerShell execution | `79` |
| 9 | Full URL contacted by encoded PowerShell script | `hxxp[://]10[.]10[.]10[.]5/news[.]php` |

## Key Takeaways
- **EventID 4720** (user account created) is a fast, reliable pivot point for spotting backdoor accounts in Windows Security logs.
- Adversaries commonly use **typosquatted usernames** (`A1berto` vs `Alberto`) to blend a malicious account into legitimate-looking activity — always compare suspicious usernames character-by-character against real accounts.
- **WMIC with `/node:`** is a classic technique for remote command execution across hosts and shows up clearly in EventID 4688 process creation logs.
- **PowerShell Script Block Logging (4104)** and **Module Logging (4103)** are essential for recovering the real content of obfuscated/encoded PowerShell commands — far more useful here than EventID 4688 alone.
- Encoded PowerShell payloads often nest multiple layers of Base64 — decode iteratively in CyberChef until you hit a human-readable IP, domain, or URL.

---
*Tags: #StudentToSOC #BuildInPublic #Unhackd #TryHackMe #Splunk #ThreatHunting #WindowsForensics*
