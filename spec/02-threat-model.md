# VEIL Protocol Specification: Part 02 — Threat Model & Adversarial Assumptions

**Specification Identifier**: `VEIL-SPEC-02`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Adversarial Capabilities & Threat Vectors

VEIL assumes an active, highly capable adversary operating across multiple vectors:

```
┌─────────────────────────────────────────────────────────────┐
│                     ADVERSARY VECTORS                       │
├─────────────────────────────────────────────────────────────┤
│ 1. Indirect Prompt Injection (IPI) via untrusted DOM/APIs   │
│ 2. Semantic Deception & Homoglyph spoofing in targets       │
│ 3. Time-of-Check to Time-of-Use (TOCTOU) DOM/state swaps    │
│ 4. Side-Channel Exfiltration (Image beacons, DNS, CSS leak) │
│ 5. Capability Token Forgery, Replay, and Nonce reuse        │
│ 6. Mid-flight Transaction Aborts & Rollback Sabotage        │
│ 7. Verification Denial via Algorithmic Complexity attacks   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Attacker Knowledge Model: Black-Box vs. Gray-Box

- **Black-Box Attacker**:
  The adversary observes only the public web environment, agent goal, and tool interface. Has zero knowledge of internal kernel components, state hashes, or HMAC secrets.
- **Gray-Box Attacker**:
  The adversary understands the VEIL protocol specification, open-source schemas, and verification algorithms, but lacks access to the private signing secret and host kernel memory.

---

## 3. Explicit Security Boundaries (Out-of-Scope)

VEIL does **not** protect against:
1. **Malicious Host Operating System**: Compromised OS kernel, ring-0 rootkits, or physical hardware tampering.
2. **Host Browser Binary Corruption**: Modified Chromium binaries that bypass extension runtime sandboxes.
3. **Compromised User Input Device**: Keyloggers or hardware Trojans on the user's physical input peripheral.
4. **Coerced Human Approvals**: A user intentionally authorizing a fraudulent action via the Out-of-Band UI despite explicit high-risk warnings.
