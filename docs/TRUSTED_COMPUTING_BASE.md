# VEIL Trusted Computing Base (TCB) Specification (v2.3)

> **TCB Definition**: *The Trusted Computing Base (TCB) consists of the minimal set of hardware, software, and cryptographic modules critical to enforcing VEIL's zero-trust security invariants. If any component inside the TCB fails, system security is compromised. If any component outside the TCB fails or is compromised, security invariants remain strictly intact.*

---

## 1. The 8 TCB Components

The VEIL Security Kernel rigorously restricts its TCB to exactly eight tightly-coupled core components:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VEIL TCB (TRUSTED CORE)                         │
├──────────────────────────────┬─────────────────────────────────────────┤
│ Component                    │ Primary Security Invariant Enforced     │
├──────────────────────────────┼─────────────────────────────────────────┤
│ 1. Policy Decision Point     │ Invariant I2 (Mandatory Policy Binding) │
│ 2. Capability Manager        │ Invariant I3 (Cryptographic Attenuation)│
│ 3. Effect Gate               │ Invariant I1 (Single Enforcement Path)  │
│ 4. Secret Vault              │ Invariant I5 (Strict Secret Isolation)  │
│ 5. State Hasher & Verifier   │ Invariant I4 (TOCTOU & State Integrity) │
│ 6. Egress Firewall           │ Invariant I6 (Perimeter Taint Contain)  │
│ 7. Transaction Engine        │ Invariant I7 (Transactional Safety)     │
│ 8. Cryptographic Ledger      │ Invariant I8 (Tamper-Evident History)   │
└──────────────────────────────┴─────────────────────────────────────────┘
```

---

## 2. Explicitly Untrusted Components

The following modules operate strictly **outside** the TCB and are treated as potentially hostile or compromised at all times:

1. **Remote AI Reasoning Models (GPT-4o, Claude 3.5, Gemini, Local Models)**:
   - Untrusted compute.
   - May generate malicious proposals, prompt injection responses, or hallucinated payloads.
   - Has zero access to authority, capabilities, or secrets.
2. **Host Webpage DOM**:
   - Untrusted environment.
   - May attempt coordinate deception, transparent clickjacking overlays, shadow DOM traps, or rapid price mutations.
3. **Extension Content Scripts**:
   - Partially trusted boundary forwarder.
   - Even if compromised by XSS or prototype pollution in the page context, cannot forge capability HMACs or bypass the isolated background kernel.
4. **Web Workers & Service Workers**:
   - Untrusted background threads.
   - Prohibited from minting, consuming, or replaying capabilities.
5. **Client LocalStorage / SessionStorage / Cookies**:
   - Untrusted storage sinks.
   - Prohibited from receiving plaintext credentials or unencrypted high-taint tokens.

---

## 3. TCB Minimization Analysis

A critical principle of high-assurance security engineering is **TCB Minimization**:
$$\text{Security Assurance} \propto \frac{1}{\text{Lines of Code in TCB}}$$

VEIL achieves radical TCB minimization:
- **Zero External Runtime Dependencies**: The TCB components rely solely on standard cryptographic primitives (HMAC-SHA256) and pure JavaScript state machines.
- **No Browser Framework in Core**: React, Vue, Tailwind, and DOM rendering engines are completely excluded from the TCB.
- **Strict Separation of Concerns**:
  - The model reasons; it does not authorize.
  - The resolver formats; it does not evaluate policy.
  - The PDP decides; it does not mint tokens.
  - The Capability Manager mints; it does not dispatch effects.
  - The Effect Gate dispatches; it does not make policy.
