TryHackMe - IronShade Writeup
Room Overview
In this room, I investigated a compromised Linux server to identify attacker activity, persistence mechanisms, suspicious services, malicious processes, SSH activity, and installed malware.
The investigation involved:
Log analysis
User account analysis
Persistence hunting
Process analysis
Service enumeration
SSH investigation
Package investigation
---

1. Identify the Machine ID
Machine IDs uniquely identify a Linux system.
Command
```bash
cat /etc/machine-id
```
Answer
```text
dc7c8ac5c09a4bbfaf3d09d399f10d96
```
---
2. Identify Suspicious User Creation
A common attacker persistence technique is creating a new user account.
Command
```bash
cat auth.log | grep -a "useradd"
```
Output
```text
Aug  5 22:05:33 cybertees useradd[2067]: new user: name=mircoservice
```
Finding
A suspicious user account was created:
```text
mircoservice
```
---
3. Investigate User Activity
After identifying the account, I searched all authentication logs for activity associated with it.
Command
```bash
grep -a "mircoservice" auth.log*
```
Findings
User Creation
```text
new user: name=mircoservice
```

SSH Login
```text
Accepted password for mircoservice from 10.11.75.247
```
Root Access
```text
sudo: mircoservice : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/su
```
```text
session opened for user root by mircoservice(uid=0)
```
---
Analysis
The attacker:
Created a new account
Set a password
Logged in through SSH
Successfully escalated privileges to root
This strongly indicates attacker persistence.
---
4. Investigate Cron Persistence
Cron jobs are frequently used to maintain persistence.
Check User Crontab
```bash
sudo crontab -u mircoservice -l
```
Output:
```text
no crontab for mircoservice
```
Check Root Crontab
```bash
sudo crontab -u root -l
```
Finding
```bash
@reboot /home/mircoservice/printer_app
```
---
Persistence Analysis
The attacker configured a cron job that automatically launches a program whenever the machine boots.
Persistence Mechanism
```bash
@reboot /home/mircoservice/printer_app
```
Answer
```text
@reboot /home/mircoservice/printer_app
```
---
5. Investigate Running Processes
The cron job pointed to a suspicious binary.
Command
```bash
ps aux | grep "mircoservice"
```
Output
```text
root      575  0.0  0.0  /home/mircoservice/.tmp/.strokes
root      885  0.0  0.0  /home/mircoservice/printer_app
```
---
Analysis
Two suspicious processes were running from the attacker's home directory.
Suspicious Hidden Process
```text
.strokes
```
Answer
```text
.strokes
```
Number of Processes
```text
2
```
---
6. Investigate Hidden Files in Memory
The room required identifying a hidden file from the root directory.
Investigation
Enumeration of hidden files revealed:
```text
.systmd
```
Answer
```text
.systmd
```
---
7. Investigate Suspicious Services
Attackers often install services to survive reboots.
Enumeration Method
```bash
ls /sys/fs/cgroup/systemd/system.slice/
```
and
```bash
systemctl list-unit-files --type=service
```
Findings
Two suspicious services were identified:
```text
backup.service
strokes.service
```
Answer
```text
backup.service, strokes.service
```
---

8. Investigate SSH Activity
Command
```bash
grep -a "mircoservice" auth.log*
```
Finding
```text
Accepted password for mircoservice from 10.11.75.247
```
Source IP
```text
10.11.75.247
```
Answer
```text
10.11.75.247
```
---
9. Count Failed SSH Logins
Command
```bash
grep -a "Failed password" auth.log*
```
Finding
Multiple failed login attempts were observed against the backdoor account.
Answer
```text
8
```
---
Analysis
The attacker successfully authenticated several times but later generated multiple authentication failures.
Possible reasons include:
Incorrect password entry
Account modifications
Failed brute-force attempts
Operational mistakes by the attacker
---
10. Identify Malicious Package
Package investigation revealed a suspicious package.
Finding
```text
pscanner
```
Answer
```text
pscanner
```
---
11. Recover Secret Code
Metadata analysis of the malicious package revealed a hidden flag.
Answer
```text
{_tRy_Hack_ME_}
```
---
Attack Timeline
Time	Activity
Aug 5 22:05:33	User account `mircoservice` created
Aug 5 22:05:39	Password configured
Aug 5 22:10:40	SSH login from attacker IP
Aug 5 22:10:40	Session opened
Aug 5 22:14:40	Privilege escalation to root
Aug 5 22:20:57	Suspicious binary execution
Persistence	Root cron launches `printer_app` at boot
Persistence	`backup.service` installed
Persistence	`strokes.service` installed
Runtime	`.strokes` process running
Malware	`pscanner` package installed
---
Indicators of Compromise (IOCs)
User
```text
mircoservice
```
Source IP
```text
10.11.75.247
```
Processes
```text
/home/mircoservice/printer_app
/home/mircoservice/.tmp/.strokes
```
Hidden File
```text
.systmd
```
Services
```text
backup.service
strokes.service
```
Package
```text
pscanner
```
---
Key Lessons Learned
During this investigation I practiced:
Linux log analysis
Authentication log review
User creation detection
SSH activity investigation
Cron persistence hunting
Process enumeration
Service enumeration
Package investigation
Building an attack timeline
Identifying Indicators of Compromise (IOCs)
This room demonstrates how attackers maintain persistence on Linux systems using user accounts, cron jobs, hidden processes, services, and malicious packages.
