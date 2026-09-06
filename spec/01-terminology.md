# VEIL Protocol Specification: Part 01 — Terminology & Definitions

**Specification Identifier**: `VEIL-SPEC-01`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Core Terminology

### 1.1. Autonomous Agent ($\mathcal{A}$)
A non-human computational entity driven by a generative model (LLM/VLM) capable of multi-step planning, environmental observation, and tool/action invocation. Agents are classified as **Untrusted Compute** within the VEIL security model.

### 1.2. Action Intent ($I$)
A semantic declaration produced by an agent expressing a desired objective (e.g., `checkout_cart`, `read_balance`, `navigate_url`). An intent possesses **zero execution authority**.

### 1.3. Action Proposal ($P$)
A structured request submitted by an agent to the VEIL kernel:
$$P = \langle \text{intent}, \text{actionType}, \text{target}, \text{parameters}, \text{contextRef} \rangle$$

### 1.4. Protected Side Effect ($e \in \mathcal{E}$)
An irreversible or state-altering primitive interaction with the external environment, browser DOM, network, file system, credential store, or financial instrument. VEIL enumerates 14 protected effect primitives.

### 1.5. Capability Token ($\mathcal{C}$)
A cryptographically signed, single-use, time-bounded, and state-bound credential minted exclusively by the VEIL Capability Manager. Without a valid $\mathcal{C}$, no protected side effect can execute.

### 1.6. State Commitment ($H_S$)
A canonical cryptographic digest of the targeted resource state immediately prior to authorization ($H(S_{\text{pre}})$) and immediately after execution ($H(S_{\text{post}})$):
$$H_S = \text{SHA-256}(\text{Canonicalize}(S))$$

### 1.7. ValueRef
An opaque cryptographic handle pointing to a sensitive credential stored within the VEIL Secret Vault. Models reason over and manipulate ValueRefs without ever observing plaintext secrets.

### 1.8. Action Receipt ($\mathcal{R}$)
A non-repudiable, hash-chained cryptographic proof emitted upon completion or abortion of an action, enabling independent offline verification without runtime execution.

### 1.9. Trusted Computing Base (TCB)
The minimal set of hardware, operating system, and VEIL kernel components whose correctness is strictly required to enforce the security policy. In VEIL, the TCB is explicitly bounded to 8 kernel modules.
