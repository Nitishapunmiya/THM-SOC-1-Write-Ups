# TryHackMe: It's Bitsy

**Category:** Threat Hunting / Network Log Analysis  
**Tools Used:** Kibana (Elastic), Pastebin (OSINT lookup)  


---

## Scenario

During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern `THM{________}`. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the `connection_logs` index in Kibana.

Our task in this room will be to examine the network connection logs of this user, find the link and the content of the file, and answer the questions.

---

## Investigation

### Step 1: Setting the Time Window

Opened the `connection_logs` index in Kibana Discover and set the date range to cover the period under investigation. The first attempt at typing the end date manually (`Jun 31, 2022`) failed since June only has 30 days — a good reminder to use the date picker UI instead of typing free text when possible.

Corrected the range to:

```
Mar 1, 2022 @ 00:00:00.00  →  Mar 31, 2022 @ 00:00:00.00
```

This returned:

```
1,482 hits
```

**🚩 Events returned for March 2022: `1482`**

---

### Step 2: Narrowing Down to Relevant Fields

Selected the key fields to make the log table easier to scan:

```
@timestamp, destination_ip, method, source_ip, source_port
```

With these fields selected, the traffic was still dominated by one IP making the bulk of the requests — needed a way to spot the outlier.

---

### Step 3: Finding the Suspect IP

Clicked into the `source_ip` field in the left-hand field list to pull up its **Top 5 values** breakdown:

| source_ip | % of records |
|---|---|
| 192.166.65.52 | 99.6% |
| **192.166.65.54** | **0.4%** |

`192.166.65.52` accounts for almost all traffic — likely the normal baseline for the network/proxy. `192.166.65.54`, appearing in only 0.4% of records, is the statistical outlier and the IP tied to Browne's suspicious activity.

**🚩 Suspected user IP: `192.166.65.54`**

---

### Step 4: Isolating the Suspect's Traffic

Filtered directly on the suspect IP:

```
source_ip : 192.166.65.54
```

This narrowed the entire month down to just **2 hits**, both occurring on **March 10, 2022**:

| @timestamp | destination_ip | method | source_port | destination_port | status_code | uri | user_agent |
|---|---|---|---|---|---|---|---|
| Mar 10, 2022 @ 1:53:11 | 104.23.99.190 | HEAD | 53,249 | 80 | 200 | /yTg0Ah6a | bitsadmin |
| Mar 10, 2022 @ 1:53:11 | 104.23.99.190 | GET | 53,147 | 80 | 200 | /yTg0Ah6a | bitsadmin |

Two requests stood out immediately: the `user_agent` field shows `bitsadmin` — this is the default user-agent string used by **BITSAdmin**, a legitimate, signed Windows utility (`bitsadmin.exe`) for managing Background Intelligent Transfer Service jobs. It's a classic Living-Off-The-Land Binary (LOLBin) — attackers abuse it to download payloads because it's trusted, pre-installed, and rarely flagged by AV.

**🚩 Legitimate Windows binary abused: `bitsadmin`**

---

### Step 5: Confirming the C2 Host

Applied filters for `method: GET` and `user_agent: bitsadmin` together to isolate the single download request:

```
method: GET AND user_agent: bitsadmin
```

Result — 1 hit:

```
source_ip: 192.166.65.54
destination_port: 80
status_code: 200
uri: /yTg0Ah6a
user_agent: bitsadmin
host: pastebin.com
```

The `host` field reveals the destination: **pastebin.com** — a legitimate, widely-used text-sharing site being abused here as a C2/dead-drop channel. This is a common technique since traffic to pastebin.com rarely raises suspicion and is hard to blanket-block in a corporate environment.

**🚩 Filesharing site used as C2: `pastebin.com`**

**🚩 Full C2 URL: `pastebin.com/yTg0Ah6a`**

---

### Step 6: Retrieving the Accessed File

Navigated to `pastebin.com/yTg0Ah6a` directly to see what `bitsadmin` had pulled down.

The paste was titled:

```
secret.txt
Posted by: A Guest
Date: Apr 6th, 2022
Views: 47,715
```

**🚩 File accessed: `secret.txt`**

---

### Step 7: Extracting the Secret Code

Opened the raw paste content, which contained a single line:

```
THM{SECRET_CODE}
```

This matched the malicious pattern format mentioned in the scenario (`THM{________}`), confirming this was the artifact the IDS alert was originally triggered by.

**🚩 Secret code: `THM{SECRET_CODE}`**

---

## Attack Chain Summary

```
1. User "Browne" (HR dept) machine generates anomalous traffic
   from source_ip 192.166.65.54 (0.4% of total — statistical outlier)
        ↓
2. bitsadmin.exe (legitimate Windows BITS utility) used as a LOLBin
   to issue HEAD + GET requests over HTTP
        ↓
3. Requests routed to host: pastebin.com (legit filesharing site
   abused as a low-profile C2/dead-drop channel)
        ↓
4. GET request retrieves paste at pastebin.com/yTg0Ah6a → secret.txt
        ↓
5. File contains flag/secret pattern: THM{SECRET_CODE}
   → confirms C2 communication and data exposure
```

---

## Indicators of Compromise (IOCs)

| Type | Indicator |
|---|---|
| Suspect source IP | `192.166.65.54` |
| Destination IP (Pastebin) | `104.23.99.190` |
| Abused LOLBin | `bitsadmin` (bitsadmin.exe) |
| C2 / filesharing host | `pastebin.com` |
| Full C2 URL | `pastebin.com/yTg0Ah6a` |
| Accessed file | `secret.txt` |
| Destination port | `80` (HTTP) |
| User-Agent string | `bitsadmin` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution / Defense Evasion | BITS Jobs | T1197 |
| Command and Control | Web Service (Pastebin as dead drop resolver) | T1102.001 |
| Command and Control | Application Layer Protocol (HTTP) | T1071.001 |
| Exfiltration | Exfiltration Over Web Service | T1567.002 |

---

## Key Takeaways

- **BITSAdmin abuse is sneaky precisely because it's legitimate** — `bitsadmin.exe` is a signed Microsoft binary, so its network requests often blend into normal traffic. The giveaway here was the literal `user_agent: bitsadmin` string left behind in the HTTP logs.
- **Statistical outliers matter more than raw counts** — the suspect IP wasn't found by searching for something obviously malicious; it was found by noticing it made up only 0.4% of all source IPs in an otherwise uniform traffic pattern. Anomaly hunting (top values / rare values) is a core Kibana/Splunk triage technique.
- **Legitimate filesharing sites as C2 is a known evasion pattern** — Pastebin, GitHub Gists, and similar services are frequently abused as low-cost, high-trust dead-drop resolvers since they're almost never blocked at the network/proxy level.
- **HEAD requests before GET requests** can indicate a script first checking if a resource exists/is reachable before pulling the full payload — worth noting as a small but useful behavioral pattern.
- Always pull the **raw destination URL and visit it in a sandboxed/safe way** (or via your tool of choice) when investigating C2 destinations — the actual payload often confirms the entire chain of suspicion in one step, as it did here with the `THM{}` flag.

---

*Writeup by Nitisha | #StudentToSOC #BuildInPublic #Unhackd*
