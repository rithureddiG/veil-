# VEIL Transaction Engine Specification

> **Specification Identifier**: `veil.spec.transaction/v1`  
> **Axiom**: $\text{Action} \ne \text{Success}$. Agent interactions execute within a formal transactional lifecycle with postcondition verification and compensation rollback.

---

## 1. Formal 9-Stage Lifecycle

```
BEGIN ➔ OBSERVE ➔ PLAN ➔ PREVIEW ➔ AUTHORIZE ➔ CAPABILITY ➔ EXECUTE ➔ VERIFY ➔ COMMIT | ABORT
```

1. **BEGIN**: Generates unique `txnId` and anchors initial state hash $H_{\text{init}}$.
2. **OBSERVE**: Perceives environment via VEIL-IR v2 through the Context Firewall.
3. **PLAN**: Assembles step sequence with reversibility classifications (`REVERSIBLE` vs `IRREVERSIBLE`).
4. **PREVIEW**: Emits structured preview to human user if high-risk actions are planned.
5. **AUTHORIZE**: Records approver signature (OOB user or autonomous policy).
6. **CAPABILITY**: Derives state-bound, single-use CapabilityTokens for planned steps.
7. **EXECUTE**: Dispatches effects through `effect-gate.js`.
8. **VERIFY**: Tests observed DOM postconditions against expected state transitions.
9. **COMMIT / ABORT**:
   - On pass: emits `VEIL_ACTION_RECEIPT` and commits to ledger.
   - On fail: executes compensation rollback across reversible steps (LIFO order).
