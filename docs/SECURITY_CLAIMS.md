# VEIL Security Claim Registry (V-SCR v1.0)

**Document Version**: 2.5.0  
**Status**: Authoritative Scientific Registry  
**Classification**: Public Research Standard  
**Subject**: Formal Claim-to-Evidence mapping, scope boundaries, and explicit limitations.

---

## 1. Metric Disambiguation Framework

VEIL rigorously separates the following evaluation dimensions to avoid misleading blanket immunity statements:

```
┌──────────────────────────────┬────────────────────────────────────────────────────────┐
│ Metric Dimension             │ Formal Definition & Current Status                     │
├──────────────────────────────┼────────────────────────────────────────────────────────┤
│ 1. Mutation Coverage         │ 100.0% of enumerated reference kernel mutants killed   │
│ 2. Enumerated Attack Defense │ 100.0% defense across 30+ known adversarial vectors    │
│ 3. Unknown Attack Challenge  │ 100.0% fail-closed interception of compound vectors    │
│ 4. Black-Box Goal Resilience │ 100.0% defeat of objective-driven adversarial probes   │
│ 5. Differential Homomorphism │ 100.0% state-transition agreement across all runtimes  │
│ 6. Formal Invariant Proofs   │ 8/8 Formal Invariants ($I_1$–$I_8$) certified          │
└──────────────────────────────┴────────────────────────────────────────────────────────┘
```

> [!WARNING]
> **Scientific Integrity Notice**: A 100% mutation score demonstrates that the test suite detects all deliberately injected reference model failures. It does **not** assert that no other classes of theoretical vulnerability exist.

---

## 2. Master Claim Registry

### Claim `VEIL-C-001`: Authority Singularity
- **Statement**: A protected side effect cannot execute without an unconsumed, unexpired, kernel-issued Action Capability. The model possesses zero direct authority.
- **Evidence**:
  - Invariant: `I1 (Zero-Bypass Authority)`
  - Unit Tests: [`test-capability.js`](veil-extension/test/test-capability.js), [`test-kernel-integration.js`](veil-extension/benchmark/test-kernel-integration.js)
  - Mutation Tests: `MUT-ALLOW-REPLAY` (Killed), `MUT-BYPASS-FSM` (Killed)
  - Differential: `DCF-001` (Tri-Fold Agreement)
  - Suite: Suite 8, Suite 14
- **Status**: **VERIFIED**
- **Scope**: Browser DOM, Network Egress, MCP Tools, System Clipboard.
- **Limitations**: Assumes host JavaScript runtime does not suffer arbitrary memory corruption outside extension sandbox.

---

### Claim `VEIL-C-002`: TOCTOU State-Binding Invariance
- **Statement**: If the targeted resource state mutates between authorization check ($t_0$) and execution ($t_1$), execution instantly aborts fail-closed ($H(S_{\text{current}}) \neq H(S_{\text{pre}})$).
- **Evidence**:
  - Invariant: `I3 (State Integrity Binding)`
  - Unit Tests: [`run-confirmation-fsm-test.js`](veil-extension/benchmark/run-confirmation-fsm-test.js)
  - Mutation Tests: `MUT-SKIP-STATE-CHECK` (Killed)
  - Differential: `DCF-TOCTOU`
  - Suite: Suite 5, Suite 14, Suite 17
- **Status**: **VERIFIED**
- **Scope**: HTML DOM Elements, Form Endpoints, MCP Target Files.
- **Limitations**: Relies on canonical DOM stringification; visual-only CSS transformations that alter perception without mutating DOM attributes require OCR validation.

---

### Claim `VEIL-C-003`: Dynamic Taint Confinement
- **Statement**: Data originating from untrusted web pages (`TAINT_UNTRUSTED_DOM`) cannot flow into sensitive effect sinks (financial submission, command execution, secret release) without explicit user declassification.
- **Evidence**:
  - Invariant: `I5 (Information Flow Confinement)`
  - Unit Tests: [`test-enforcement-boundary.js`](veil-extension/benchmark/test-enforcement-boundary.js)
  - Suite: Suite 10, Suite 15
- **Status**: **VERIFIED**
- **Scope**: Web DOM Tree, Remote API Payloads, MCP Tool Arguments.
- **Limitations**: Does not prevent benign users from voluntarily copying tainted strings if user confirmation is intentionally bypassed by user action.

---

### Claim `VEIL-C-004`: Secret Vault Isolation
- **Statement**: Plaintext credentials (passwords, card numbers, Aadhaar, API keys) are replaced with opaque ValueRefs. Generative models manipulate handles but never observe raw secrets.
- **Evidence**:
  - Invariant: `I2 (Secret Isolation)`
  - Unit Tests: [`test-security-invariant.js`](veil-extension/benchmark/test-security-invariant.js)
  - Mutation Tests: `MUT-INVERT-POLICY` (Killed)
  - Suite: Suite 6, Suite 8
- **Status**: **VERIFIED**
- **Scope**: Form Input Fields, Context IR payloads, Network Request Payloads.
- **Limitations**: Plaintext entered manually by the user outside the protected extension browser profile is unmediated.

---

### Claim `VEIL-C-005`: Offline Cryptographic Non-Repudiation
- **Statement**: Any executed or aborted action emits an Action Receipt that can be verified offline in pure Python 3 without running or trusting the VEIL execution engine.
- **Evidence**:
  - Invariant: `I6 (Cryptographic Non-Repudiation)`
  - Unit Tests: [`external-verifier/python/verify_receipt.py`](external-verifier/python/verify_receipt.py), [`reproduction/run_all_reproductions.py`](reproduction/run_all_reproductions.py)
  - Suite: Suite 14, Suite 16
- **Status**: **VERIFIED**
- **Scope**: Action Receipts, Ledger Hash Chains, Merkle Session Roots.
- **Limitations**: Offline verification validates hash chain continuity and payload commitment; physical confirmation of out-of-band human presence relies on OS/sidepanel signature.

---

### Claim `VEIL-C-006`: Zero-Trust MCP Tool Mediation
- **Statement**: AI agents invoking Model Context Protocol (MCP) tools are subject to in-line taint boundary inspection, capability token nonces, and pre-state commitment checks.
- **Evidence**:
  - Invariant: `MCP-I1` through `MCP-I4`
  - Unit Tests: [`core/kernel/mcp-gateway.js`](veil-extension/core/kernel/mcp-gateway.js), [`run-v24-pca-and-mcp.js`](veil-extension/benchmark/run-v24-pca-and-mcp.js)
  - Suite: Suite 15
- **Status**: **VERIFIED**
- **Scope**: MCP `tools/call` JSON-RPC requests, Local CLI execution, File I/O.
- **Limitations**: Target tool must be routed through the VEIL gateway proxy; tools invoked via out-of-band native OS processes bypass the gateway.

---

### Claim `VEIL-C-007`: LIFO Transactional Compensation
- **Statement**: Any multi-step transaction interrupted by network failure or security exception is rolled back via inverted compensation actions in strict reverse order (LIFO).
- **Evidence**:
  - Invariant: `I7 (Atomic Transaction Compensation)`
  - Unit Tests: [`test-kernel-integration.js`](veil-extension/benchmark/test-kernel-integration.js)
  - Suite: Suite 8, Suite 11
- **Status**: **VERIFIED**
- **Scope**: Multi-step checkout, form multi-page submissions.
- **Limitations**: Real-world external side effects lacking an inverse API (e.g., non-refundable external wire transfer) cannot be physically un-executed.
