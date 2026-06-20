# TryHackMe: Sneaky Patch


## Scenario
A high-value system has been compromised. Security analysts have detected suspicious activity within the kernel, but the attacker's presence remains hidden. Traditional detection tools have failed, and the intruder has established deep persistence. Investigate a live system suspected of running a kernel-level backdoor.

## Tools Used
- Linux terminal (`cat`, `lsmod`, `modinfo`, `strings`)
- CyberChef (Hex decoding)

---

## Task: Find the Kernel-Level Backdoor

### Step 1 — Check the kernel logs

Started in `/var/log` and listed the directory to see what was available:

```bash
cd /var/log
ls
```

`kern.log` stood out immediately given the "kernel-level backdoor" framing in the scenario.

```bash
cat kern.log
```

```
2026-06-13T06:03:25.430688+00:00 tryhackme kernel: spatch: loading out-of-tree module taints kernel.
2026-06-13T06:03:25.430702+00:00 tryhackme kernel: spatch: module verification failed: signature and/or required key missing - tainting kernel
2026-06-13T06:03:25.430703+00:00 tryhackme kernel: [CIPHER BACKDOOR] Module loaded. Write data to /proc/cipher_bd
2026-06-13T06:03:25.432363+00:00 tryhackme kernel: [CIPHER BACKDOOR] Executing command: id
2026-06-13T06:03:25.438302+00:00 tryhackme kernel: [CIPHER BACKDOOR] Command Output: uid=0(root) gid=0(root) groups=0(root)
```

This single log block tells the whole story:
- An **unsigned, out-of-tree kernel module** named `spatch` was loaded (kernel tainted as a result).
- It self-identifies in logs as `[CIPHER BACKDOOR]`.
- It exposes a `/proc/cipher_bd` interface for command execution.
- It already ran `id` and got back `root` — confirming full root-level command execution via the kernel module.

---

### Step 2 — Confirm the module is loaded

```bash
lsmod
```

```
Module      Size    Used by
spatch      12288   0
...
```

Confirms `spatch` is an actively loaded kernel module.

---

### Step 3 — Pull module metadata

```bash
modinfo spatch
```

```
filename:    /lib/modules/6.8.0-1016-aws/kernel/drivers/misc/spatch.ko
description: Cipher is always root
author:      Cipher
license:     GPL
srcversion:  81BE8A2753A1D8A9F28E91E
depends:
retpoline:   Y
name:        spatch
vermagic:    6.8.0-1016-aws SMP mod_unload modversions
```

The description ("Cipher is always root") and author ("Cipher") confirm this module's sole purpose is malicious root persistence.

---

### Step 4 — Extract strings from the module binary

```bash
strings /lib/modules/6.8.0-1016-aws/kernel/drivers/misc/spatch.ko
```

Key strings recovered:

```
get_flag
cipher_bd
/tmp/cipher_output.txt
/bin/sh
%s > %s 2>&1
/root/src/spatch.c
[CIPHER BACKDOOR] Module loaded. Write data to /proc/%s
[CIPHER BACKDOOR] Executing command: %s
[CIPHER BACKDOOR] Format: echo "COMMAND" > /proc/cipher_bd
[CIPHER BACKDOOR] Here's the secret: 54484d7b73757033725f736e33346b795f643030727d0a
```

This reveals the module's full mechanism:
- It registers a `/proc/cipher_bd` entry as a command channel.
- Commands written to it (`echo "COMMAND" > /proc/cipher_bd`) are run via `/bin/sh`, with output redirected to `/tmp/cipher_output.txt`.
- There's a `get_flag` function and a hardcoded hex-encoded secret string sitting right in the binary.

---

### Step 5 — Decode the hex secret

Took the hex string and ran it through CyberChef's **From Hex** operation:

**Input:**
```
54484d7b73757033725f736e33346b795f643030727d0a
```

**Output:**
```
THM{sup3r_sn34ky_d00r}
```

---

## Flag

```
THM{sup3r_sn34ky_d00r}
```

---

## Key Takeaways
- A **tainted kernel** warning in `dmesg`/`kern.log` (`module verification failed: signature and/or required key missing`) is a major red flag — it means an unsigned, out-of-tree module was loaded, which is exactly how kernel-level rootkits/backdoors get into a system.
- Malicious kernel modules often expose a **`/proc` interface** as a simple, low-effort command-and-control channel — writing a command string to a proc file and reading the result back is a common LKM backdoor pattern.
- `lsmod` and `modinfo` are quick first checks to confirm a suspicious module is loaded and to pull its file path, author, and description.
- Running `strings` against a compiled `.ko` file can recover hardcoded log messages, file paths, and even secrets/flags left in the binary by the module author — a fast win before reaching for a disassembler.
- Always check recovered strings for encoding (hex, Base64, etc.) — CyberChef's **Magic** operation is a good first pass when the encoding isn't obvious.

---
*Tags: #StudentToSOC #BuildInPublic #Unhackd #TryHackMe #LinuxForensics #KernelRootkit #DFIR*
