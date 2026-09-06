# VEIL Protocol Specification: Part 07 — State Commitment & TOCTOU Resilience

**Specification Identifier**: `VEIL-SPEC-07`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. The Time-of-Check to Time-of-Use (TOCTOU) Challenge

In web and agent environments, DOM trees and API endpoints are inherently dynamic and asynchronous. Between the moment an action is verified ($t_0$) and the moment it physically mutates state ($t_1$), a malicious script can mutate the DOM (e.g., swapping a "Pay $1" button target into "Wire $10,000").

---

## 2. Cryptographic State Commitment Protocol

VEIL eliminates TOCTOU vulnerabilities via a two-phase commitment protocol:

```
t0: PROPOSAL EVALUATION
    1. Resolve target node S
    2. Compute canonical digest: H(S_pre) = SHA-256(Canonicalize(S))
    3. Bind H(S_pre) into Capability Token C

t1: EXECUTION MEDIATION (Atomic Guard)
    1. Re-resolve target node S'
    2. Compute current digest: H(S_current) = SHA-256(Canonicalize(S'))
    3. Assert: H(S_current) == C.preStateHash
    4. If mismatch: ABORT FAIL-CLOSED (ERR_STATE_DESYNCHRONIZATION)
    5. If match: Execute mutation S' -> S_post
    6. Compute post-state digest: H(S_post) = SHA-256(Canonicalize(S_post))
    7. Commit (H(S_pre), H(S_post)) to Action Receipt
```

---

## 3. Canonical State Properties

The canonical digest includes:
1. Exact CSS selector path and tag name.
2. Normalized text content (Unicode NFKC).
3. Critical attributes (`href`, `src`, `action`, `method`, `value`, `disabled`).
4. Bounding box coordinates and visibility flags.
5. Child node structural fingerprint.
