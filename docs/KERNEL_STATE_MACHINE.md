# VEIL Kernel State Machine & Mathematical Specification (v2.2)

> **Mathematical Foundation**: *The VEIL Security Kernel specifies a formal trusted computing base (TCB) governing all interactions between untrusted AI agents, hostile web environments, and browser side effects.*

---

## 1. Formal State Machine Definition

Let the VEIL Kernel State Machine be a 6-tuple:

$$\mathcal{M} = \langle \mathcal{S}, \Sigma, \mathcal{C}, \delta, s_0, \mathcal{F} \rangle$$

Where:
- $\mathcal{S}$ is the set of Kernel States:
  $$\mathcal{S} = \{ \text{IDLE}, \text{REQUESTED}, \text{EVALUATING}, \text{AUTHORIZED}, \text{CAPABILITY\_ISSUED}, \text{EXECUTING}, \text{VERIFYING}, \text{COMMITTED}, \text{ABORTED} \}$$
- $\Sigma$ is the input alphabet consisting of:
  - Agent Action Proposals: $p = \langle \text{actor}, \text{type}, \text{target}, \text{origin}, \text{payload} \rangle$
  - Policy Rules: $\mathcal{R}$
  - Out-of-Band Human Decisions: $h \in \{ \text{APPROVE}, \text{DENY} \}$
  - DOM State Observations: $\sigma \in \mathcal{D}$
- $\mathcal{C}$ is the set of single-use cryptographic capability tokens:
  $$c = \langle \text{capId}, \text{origin}, \text{actionType}, \text{fingerprint}, \text{stateHash}, \text{ttl}, \text{consumed}, \text{HMAC} \rangle$$
- $\delta: \mathcal{S} \times \Sigma \to \mathcal{S}$ is the transition function.
- $s_0 = \text{IDLE}$ is the initial state.
- $\mathcal{F} = \{ \text{COMMITTED}, \text{ABORTED} \}$ is the set of terminal states.

```
                    ┌─────────────┐
                    │    IDLE     │
                    └──────┬──────┘
                           │ Agent Proposal p
                           ▼
                    ┌─────────────┐
                    │  REQUESTED  │
                    └──────┬──────┘
                           │ Begin PDP Evaluation
                           ▼
                    ┌─────────────┐
            ┌───────┤  EVALUATING ├───────┐
            │       └─────────────┘       │
      Deny  │                             │ Policy Allow
            ▼                             ▼
     ┌─────────────┐               ┌─────────────┐
     │   ABORTED   │               │ AUTHORIZED  │
     └─────────────┘               └──────┬──────┘
                                          │ Mint Capability Token c
                                          ▼
                                   ┌──────────────────────┐
                                   │  CAPABILITY_ISSUED   │
                                   └──────┬───────────────┘
                                          │ Consume c & Dispatch Effect
                                          ▼
                                   ┌─────────────┐
                                   │  EXECUTING  │
                                   └──────┬──────┘
                                          │ Native Boundary Execution
                                          ▼
                                   ┌─────────────┐
                           ┌───────┤  VERIFYING  ├───────┐
                           │       └─────────────┘       │
        Postcondition Fail │                             │ Postcondition Pass
                           ▼                             ▼
                    ┌─────────────┐               ┌─────────────┐
                    │   ABORTED   │               │  COMMITTED  │
                    │(Compensate) │               │(Emit Receipt│
                    └─────────────┘               └─────────────┘
```

---

## 2. Core Security Theorems & Mathematical Invariants

### Theorem 1 (Safety — No Unauthorized Side Effects):
Every protected execution $e$ must have an authorized, verified capability $c$:
$$\forall e \in \mathcal{E}_{\text{protected}}: \quad \text{Executed}(e) \implies \exists c \in \mathcal{C}: \text{Valid}(c) \land \text{Binds}(c, e) \land \text{Consume}(c)$$

### Theorem 2 (Confidentiality — Secret Isolation):
For all secret credentials $s \in \mathcal{S}_{\text{vault}}$, no reasoning model observation $O_M$ contains $s$:
$$\forall s \in \mathcal{S}_{\text{vault}}, \forall O_M \in \mathcal{O}_{\text{model}}: \quad s \not\subseteq O_M$$
*Corollary*: Models perceive strictly opaque Value References:
$$O_M(s) = \text{ValueRef}(s) = \text{credential://}\langle \text{origin} \rangle/\langle \text{field} \rangle/\langle \text{id} \rangle$$

### Theorem 3 (State Integrity — TOCTOU Elimination):
An action approved at state $\sigma_{\text{plan}}$ cannot execute if the DOM state $\sigma_{\text{exec}}$ has mutated:
$$\text{stateHash}(\sigma_{\text{plan}}) \ne \text{stateHash}(\sigma_{\text{exec}}) \implies \delta(\text{EXECUTING}) = \text{ABORTED}$$

### Theorem 4 (Replay Resistance):
Once a capability token $c$ has been consumed at time $t$, all future attempts to execute using $c$ fail closed:
$$\forall t' > t: \quad \text{Consume}(c, t) \implies \text{Valid}(c, t') = \text{false}$$

### Theorem 5 (Egress Safety & Taint Flow):
Data with taint level $\tau(d)$ cannot flow to network destination $dst$ unless permitted by the security lattice and destination whitelist:
$$\tau(d) \ge \text{SENSITIVE} \land dst \notin \text{Whitelist} \implies \text{EgressVerdict}(d, dst) = \text{BLOCKED}$$

### Theorem 6 (Ledger Tamper Evidence):
For any ledger history $H = [e_1, e_2, \dots, e_n]$, modifying any event $e_k$ ($1 \le k \le n$) invalidates all subsequent hashes:
$$e_k \ne e_k' \implies \text{Hash}(e_n) \ne \text{RecomputedHeadHash}(H')$$

---

## 3. The 10 Certification Gates ($C_1$ to $C_{10}$)

1. **$C_1$ Unified Enforcement Path**: All 14 protected effects pass through `effect-gate.js`. Direct execution fails closed.
2. **$C_2$ Zero Model Authority**: AI agent cannot forge HMAC-SHA256 capability tokens.
3. **$C_3$ Single-Use Replay Resistance**: Consumed tokens are irrevocably invalidated.
4. **$C_4$ Multi-Axis State Binding**: Token binds `(origin, actionType, targetFingerprint, stateHash)`.
5. **$C_5$ Secret Isolation**: Plaintext credentials injected strictly at native DOM boundary via `secret-release-gate.js`.
6. **$C_6$ Provenance Egress Control**: Tainted secrets cannot leak via fetch, XHR, WebSockets, or clipboard.
7. **$C_7$ Verifiable Action Receipts**: Emits canonical, signed `VEIL ACTION RECEIPT` verifiable offline.
8. **$C_8$ Adversarial Resilience**: 100% defense rate across enumerated & mutational adversarial attacks.
9. **$C_9$ Fuzzing Invariant Integrity**: Zero invariant breaches across 1,000+ randomized fuzzing iterations.
10. **$C_{10}$ Formal State Machine**: Implementation strictly conforms to the verified state machine $\mathcal{M}$.
