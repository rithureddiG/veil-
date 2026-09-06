# VEIL Formal Security Model Specification (v2.4)

> **Specification Identifier**: `veil.spec.security/v1`  
> **Core Axiom**: *Intelligence is separable from authority. Remote generative AI reasoning models operate strictly outside the Trusted Computing Base (TCB). The model may propose; only VEIL can authorize.*

---

## 1. System Participants & Trust Boundary

$$\mathcal{P} = \{ \mathcal{M}_{\text{model}}, \mathcal{D}_{\text{dom}}, \mathcal{S}_{\text{script}}, \mathcal{K}_{\text{veil}}, \mathcal{U}_{\text{user}} \}$$

1. **AI Reasoning Model ($\mathcal{M}_{\text{model}}$)**:
   - Untrusted entity.
   - May generate arbitrary semantic proposals $p \in \mathcal{P}_{\text{prop}}$.
   - Zero execution authority.
2. **Host DOM Environment ($\mathcal{D}_{\text{dom}}$)**:
   - Untrusted execution surface.
   - Subject to Coordinate Deception, TOCTOU state mutations, and clickjacking.
3. **VEIL Security Kernel ($\mathcal{K}_{\text{veil}}$)**:
   - Trusted Computing Base (TCB).
   - Comprises PDP, Capability Manager, Effect Gate, Secret Vault, State Hasher, Egress Firewall, Transaction Engine, and Security Ledger.
4. **User Root Authority ($\mathcal{U}_{\text{user}}$)**:
   - Out-of-Band (OOB) Root of Trust via Privileged Side Panel UI.

---

## 2. Invariant Theorems

1. **Invariant I1 (Authority Singularity)**: No protected side effect $e \in \mathcal{E}_{\text{protected}}$ can execute without a single-use `CapabilityToken` issued exclusively by the VEIL Capability Manager.
2. **Invariant I2 (Mandatory Policy Binding)**: Capabilities cannot be issued without a signed `PolicyDecision` from the Policy Decision Point.
3. **Invariant I3 (Cryptographic HMAC Attenuation)**: Every capability is authenticated via HMAC-SHA256 over `(capabilityId, actionType, target, origin, stateHash, ttl, nonce)`.
4. **Invariant I4 (State Integrity & TOCTOU Immunity)**: A capability bound to state $H_{\text{plan}}$ cannot execute if the live DOM state at execution time $H_{\text{exec}} \ne H_{\text{plan}}$.
5. **Invariant I5 (Secret Isolation & Zero-Leakage)**: Decrypted credentials never enter model reasoning context or client event loops. Injected exclusively at the native DOM boundary.
6. **Invariant I6 (Perimeter Egress Containment)**: Tainted secrets cannot cross network or clipboard boundaries without explicit capability and destination matching.
7. **Invariant I7 (Transactional Postcondition Verification)**: Execution of an action does not imply success ($\text{Action} \ne \text{Success}$). Operations must verify expected postconditions and support compensation rollback on abort.
8. **Invariant I8 (Tamper-Evident Ledger Integrity)**: All privileged perceptions, decisions, and side effects are committed to an immutable SHA-256 hash chain with periodic Merkle checkpoints.
