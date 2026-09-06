# VEIL Conformance Specification (VEIL-SPEC-009)

**Specification Version**: 2.4.0  
**Status**: Stable Reference Standard  
**Subject**: Third-Party Implementation & Independent Verification Conformance Criteria

---

## 1. Scope & Objective

This specification defines the mandatory criteria for an implementation or verification tool to claim conformance to the **VEIL Zero-Trust Security Runtime Specification (VEIL-SPEC v2.4)**.

Any third-party auditor, academic researcher, or security engine vendor can achieve certified VEIL Conformance by satisfying the levels defined herein.

---

## 2. Conformance Levels

VEIL defines three hierarchical tiers of conformance:

```
┌────────────────────────────────────────────────────────┐
│  Level 3: Full Kernel Conformance (VEIL-K3)            │
│  - Executes runtime state machine                      │
│  - Enforces all 14 protected effects                   │
│  - Satisfies zero-bypass and refinement bisimulation   │
├────────────────────────────────────────────────────────┤
│  Level 2: Differential Policy & IR Conformance (VEIL-P2)│
│  - Evaluates VPL AST and compiles bytecode/IR          │
│  - Passes all differential decision oracle test suites │
├────────────────────────────────────────────────────────┤
│  Level 1: Offline Receipt Verification Conformance (VEIL-V1)
│  - Validates VEIL Action Receipts independently        │
│  - Verifies cryptographic hash chains and HMACs        │
│  - Zero dependency on VEIL execution engine            │
└────────────────────────────────────────────────────────┘
```

---

## 3. Level 1: Offline Receipt Verification Conformance (VEIL-V1)

To achieve **VEIL-V1** certification, an independent verification tool (e.g., Python, Rust, Go, or Java CLI) MUST:

1. **Schema Validation**:
   - Parse and validate receipts conforming to `veil.action_receipt/v2` (`receipt-schema.json`).
   - Reject any malformed receipt missing required fields (`receiptId`, `timestamp`, `action`, `verdict`, `integrity`).

2. **Canonical Serialization & Hash Verification**:
   - Implement recursive key-sorted lexicographic JSON serialization identical to RFC 8785 / VEIL canonical JSON rules.
   - Compute SHA-256 over canonical representations of:
     - `canonical(action)` $\to$ matching `integrity.actionHash`
     - `canonical(evidence)` $\to$ matching `integrity.evidenceHash`
     - `canonical(preStateCommitment)` $\to$ matching `integrity.preStateHash`
     - `canonical(postStateCommitment)` $\to$ matching `integrity.postStateHash`

3. **Merkle Proof / Leaf Integrity**:
   - Verify `integrity.receiptHash = SHA-256(actionHash || evidenceHash || preStateHash || postStateHash)`.

4. **Cryptographic Signature Verification**:
   - If an HMAC secret is supplied, compute `HMAC-SHA256(receiptHash, secret)` and assert constant-time equality with `integrity.signature`.

5. **Chain Continuity Validation**:
   - When verifying a ledger sequence $\{R_0, R_1, \dots, R_k\}$, assert:
     $$\forall i > 0, \quad R_i.\text{integrity}.\text{previousReceiptHash} = R_{i-1}.\text{integrity}.\text{receiptHash}$$
   - Any gap, reordering, or fork must yield immediate failure code `ERR_LEDGER_CHAIN_FORK`.

---

## 4. Level 2: Differential Policy & IR Conformance (VEIL-P2)

To achieve **VEIL-P2** certification, an implementation MUST:

1. **Deterministic VPL Evaluation**:
   - Evaluate any valid VPL rule syntax `ALLOW|BLOCK|CONFIRM action_pattern [WHEN predicate]` to an identical verdict (`ALLOW`, `BLOCK`, `CONFIRM`) across 100% of benchmark test vectors.
2. **Deterministic Taint Propagation**:
   - Propagate taint tags along the data-flow graph conforming to `spec/information-flow.md`.
   - Never allow untrusted or tainted inputs to downgrade without explicit sanitization proof.
3. **Equivalence with Mathematical Reference Kernel**:
   - Execute side-by-side with `reference/reference-model/reference-kernel.js` on $\ge 1,000$ generated action envelopes with zero verdict divergence.

---

## 5. Level 3: Full Kernel Conformance (VEIL-K3)

To achieve **VEIL-K3** certification, a runtime MUST satisfy all constraints of Level 1 and Level 2, plus:

1. **Exhaustive Side Effect Mediation**:
   - Enforce mediation over all 14 protected effect primitives defined in `spec/effect-model.md`.
   - No path around the kernel can execute DOM modifications, network requests, credential access, navigation, or financial operations without an authorized Capability Token.
2. **Refinement Bisimulation**:
   - Formally bisimulate the transition system $(\mathcal{S}_{ref}, \to_{ref})$:
     $$\forall s \in \mathcal{S}_{prod}, \quad \alpha(s) \sim s_{ref}$$
3. **Mutation Resistance**:
   - When tested against the reference mutant suite (`reference/mutants/`), achieve **100% mutant kill rate**.
   - Any mutant that weakens policy, skips validation, or leaks side effects MUST fail verification.
4. **State Commitment Binding**:
   - Execute all mutations strictly under pre-state validation:
     $$\text{validate}(s_{pre}) \land \text{mutate}(s_{pre}) \to s_{post} \land \text{commit}(s_{post})$$
   - Rollback atomically via LIFO compensation if any invariant check fails.

---

## 6. Test Suites & Certification Harness

Vendors claiming VEIL conformance must execute and pass the following automated test suites:

| Suite Name | Target Tier | Location | Pass Threshold |
| :--- | :---: | :--- | :---: |
| **Receipt Verification Suite** | VEIL-V1 | `external-verifier/node/verify_receipt.js` | 100% (25/25 vectors) |
| **Python Offline Verifier** | VEIL-V1 | `external-verifier/python/verify_receipt.py` | 100% (25/25 vectors) |
| **Differential Conformance** | VEIL-P2 | `benchmark/test-differential-conformance.js` | 100% (zero divergence) |
| **Canonicalization Suite** | VEIL-V1/P2 | `benchmark/test-canonicalization.js` | 100% (zero divergence) |
| **Reference Mutation Test** | VEIL-K3 | `benchmark/test-mutation-coverage.js` | 100% (all mutants killed) |
| **Authority Isolation Fuzz** | VEIL-K3 | `benchmark/test-concurrency-and-isolation.js` | 100% (zero race leaks) |

---

## 7. Versioning & Compliance Seals

An implementation passing these suites may publish compliance receipts with the header:
```json
{
  "standard": "VEIL-SPEC",
  "version": "2.4.0",
  "conformanceLevel": "VEIL-K3",
  "verificationHash": "sha256-..."
}
```
Any modification to kernel invariants or cryptographic algorithms requires incrementing the specification version and re-evaluating the complete differential test matrix.
