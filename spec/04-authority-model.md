# VEIL Protocol Specification: Part 04 — Authority Model & Singularity Theorem

**Specification Identifier**: `VEIL-SPEC-04`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Theorem of Authority Singularity ($T_1$)

Let $\mathcal{E}$ be the set of protected side-effect primitives, and let $\mathcal{U}$ be the set of computational entities within the system.

$$\forall e \in \mathcal{E}, \quad |\text{Authorities}(e)| = 1 \quad \text{and} \quad \text{Authorities}(e) = \text{VEIL\_KERNEL}$$

### 1.1. Corollary of Agent Impotence
An autonomous agent $\mathcal{A}$ has strictly zero authority:
$$\forall e \in \mathcal{E}, \quad \text{Authority}(\mathcal{A}, e) = \emptyset$$

The model proposes; VEIL decides:
$$\mathcal{A}(S) \to \text{Proposal}(P)$$
$$\text{VEIL}(P, S, \Pi) \to \{\text{ALLOW}(\mathcal{C}), \text{CONFIRM}, \text{BLOCK}\}$$

---

## 2. Authority Graph Invariants

1. **Cycle-Free Delegation**: Authority cannot be recursively delegated in loops. The authority graph is a directed acyclic graph (DAG) rooted at the User / Policy engine.
2. **Monotonic Attenuation**: Any sub-capability minted from a parent capability cannot grant permissions exceeding the parent ($\mathcal{C}_{\text{child}} \subseteq \mathcal{C}_{\text{parent}}$).
3. **Atomic Consumption**: An authority capability $\mathcal{C}$ can transition from `MINTED` to `CONSUMED` exactly once:
   $$\text{Execute}(e, \mathcal{C}) \implies \text{Consumed}(\mathcal{C}) \leftarrow \text{True}$$
   Any concurrent or subsequent invocation with $\mathcal{C}$ aborts immediately.
