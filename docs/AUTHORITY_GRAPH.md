# VEIL Authority Graph & Singularity Specification (v2.3)

> **Central Theorem**: *There exists exactly one authority capable of authorizing each protected side effect: the VEIL Security Kernel. No entity outside the TCB may mint, delegate, or execute authority.*

---

## 1. The Formal Authority Graph

The Authority Graph maps all entities in the agent execution runtime, annotating each node with its **Authority Level**, **Trust Classification**, and **Permitted Privileges**.

```
                           ┌─────────────────────────┐
                           │      AI / MODEL         │
                           │ Authority: PROPOSE      │
                           │ Trust:     UNTRUSTED    │
                           │ Priv:      NONE         │
                           └────────────┬────────────┘
                                        │ Proposal Only (No Authority)
                                        ▼
                           ┌─────────────────────────┐
                           │    RESOLVER / CONTEXT   │
                           │ Authority: SANITIZE     │
                           │ Trust:     PARTIALLY    │
                           │ Priv:      READ-ONLY    │
                           └────────────┬────────────┘
                                        │ Sanitized Proposal
                                        ▼
    ┌────────────────────────────────────────────────────────────────────────┐
    │                        VEIL TRUSTED COMPUTING BASE                     │
    │                                                                        │
    │  ┌──────────────────────┐              ┌────────────────────────────┐  │
    │  │ POLICY DECISION PT   │              │ CAPABILITY MANAGER         │  │
    │  │ Authority: DECIDE    │              │ Authority: AUTHORIZE       │  │
    │  │ Trust:     TCB       │              │ Trust:     TCB             │  │
    │  │ Priv:      SIGNATURE │              │ Priv:      HMAC MINT       │  │
    │  └──────────┬───────────┘              └─────────────┬──────────────┘  │
    │             │                                        │                 │
    │             └───────────────────┬────────────────────┘                 │
    │                                 │ Signed CapabilityToken               │
    │                                 ▼                                      │
    │                    ┌───────────────────────────┐                       │
    │                    │        EFFECT GATE        │                       │
    │                    │ Authority: MEDIATE        │                       │
    │                    │ Trust:     TCB            │                       │
    │                    │ Priv:      KERNEL GATE    │                       │
    │                    └────────────┬──────────────┘                       │
    │                                 │ Dispatches To Sub-Gate               │
    │                                 ▼                                      │
    │                    ┌───────────────────────────┐                       │
    │                    │    ACTION EXECUTOR        │                       │
    │                    │ Authority: EXECUTE        │                       │
    │                    │ Trust:     TCB            │                       │
    │                    │ Priv:      NATIVE DISPATCH│                       │
    │                    └───────────────────────────┘                       │
    └─────────────────────────────────┬──────────────────────────────────────┘
                                      │ Verified Effect
                                      ▼
                           ┌─────────────────────────┐
                           │ HOST BROWSER RUNTIME    │
                           │ Authority: DISPATCH     │
                           │ Trust:     UNTRUSTED    │
                           │ Priv:      DOM/NET/IO   │
                           └─────────────────────────┘
```

---

## 2. Node Classification Matrix

| Node | Classification | Authority Level | Permitted Privileges | Invariant Enforced |
| :--- | :--- | :--- | :--- | :--- |
| **AI Reasoning Model** | `UNTRUSTED` | `PROPOSE` | None | May perceive VEIL-IR and propose actions; cannot authorize or execute. |
| **Host Webpage DOM** | `UNTRUSTED` | `NONE` | DOM Mutation | Subject to TOCTOU and Coordinate Deception defenses. Zero authority. |
| **Extension Content Script** | `PARTIALLY_TRUSTED` | `FORWARD` | DOM Read / Intercept | Forwards proposals; cannot issue capabilities or sign ledger events. |
| **Web Workers / Service Workers** | `UNTRUSTED` | `NONE` | Background Compute | Cannot hold or delegate action capabilities. |
| **Action Resolver** | `PARTIALLY_TRUSTED` | `SANITIZE` | Structural Parsing | Normalizes requests into canonical proposals. Cannot mint tokens. |
| **Policy Decision Point (PDP)** | `TCB` | `DECIDE` | Policy Evaluation | Evaluates security rules; issues immutable signed `PolicyDecision`. |
| **Capability Manager** | `TCB` | `AUTHORIZE` | HMAC Minting | Sole entity with access to `KERNEL_SECRET`. Issues `CapabilityToken`. |
| **State Verifier / Hasher** | `TCB` | `ANCHOR` | Cryptographic Hashing | Binds capabilities to live DOM snapshot. Cancels on state mutation. |
| **Secret Vault** | `TCB` | `ISOLATE` | In-Memory Vault | Injects secrets exclusively at native DOM boundary. Zero model visibility. |
| **Egress Firewall** | `TCB` | `FILTER` | Perimeter Network Gate | Evaluates outbound traffic, canary detection, and taint lattice sinks. |
| **Effect Gate** | `TCB` | `MEDIATE` | Boundary Enforcement | Universal gateway mediating all 14 protected primitives. |
| **Transaction Engine** | `TCB` | `COORDINATE` | Lifecycle & Compensation | Enforces $\text{Action} \ne \text{Success}$ and executes rollback on abort. |
| **Security Ledger** | `TCB` | `AUDIT` | Immutable Hash Chain | Records tamper-evident event sequence and checkpoint session roots. |
| **Privileged Side Panel UI** | `TCB` | `ROOT_AUTH` | Human Authorization | Out-of-band user approval for irreversible and high-risk effects. |

---

## 3. The Authority Singularity Proof

### Theorem (Authority Singularity):
$$\forall e \in \mathcal{E}_{\text{protected}}, \quad |\text{AuthoritiesCapableOfAuthorizing}(e)| = 1 \quad (\text{VEIL Capability Manager})$$

**Proof by Contradiction:**
1. Assume there exists an alternate execution pathway $P_{\text{alt}}$ capable of dispatching protected side effect $e$ without a valid `CapabilityToken` issued by the Capability Manager.
2. Under $C_1$ (Unified Enforcement Path), all native browser primitives (`click`, `submit`, `type`, `fetch`, `storage`, `clipboard`, `navigate`) are mediated by `effect-gate.js`.
3. In `effect-gate.js`, any invocation targeting an irreversible or sensitive effect without a valid token signed by `KERNEL_SECRET` fails closed with status `BLOCKED`.
4. Therefore, $P_{\text{alt}}$ cannot execute $e$.
5. Hence, no alternate authority exists. $\blacksquare$
