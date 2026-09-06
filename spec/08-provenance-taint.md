# VEIL Protocol Specification: Part 08 — Dynamic Taint Tracking & Information Flow

**Specification Identifier**: `VEIL-SPEC-08`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Dynamic Taint Lattice

VEIL defines a partially ordered security lattice $(\mathcal{T}, \sqsubseteq)$ over data provenance:

```
                  TAINT_UNTRUSTED_DOM
                 ▲                   ▲
                ╱                     ╲
      TAINT_INDIRECT_PROMPT       TAINT_REMOTE_API
                ▲                     ▲
                 ╲                   ╱
                  TAINT_USER_CONFIRMED
                            ▲
                            │
                       TAINT_CLEAN
```

- $\text{TAINT\_CLEAN}$: Data originated directly from trusted local configuration or safe schema templates.
- $\text{TAINT\_USER\_CONFIRMED}$: Data explicitly reviewed and approved by user via OOB UI.
- $\text{TAINT\_UNTRUSTED\_DOM}$: Data parsed from third-party web pages, iframes, or untrusted documents.
- $\text{TAINT\_INDIRECT\_PROMPT}$: High-risk text flagged by classifier containing imperative override tokens.

---

## 2. Information Flow Control (IFC) Law

Let $\tau(x)$ be the taint tag of variable $x$, and let $\text{Risk}(e)$ be the risk level of effect $e$:

$$\forall e \in \mathcal{E}, \quad \text{Risk}(e) \ge \text{HIGH} \land \tau(\text{params}(e)) \sqsupseteq \text{TAINT\_UNTRUSTED\_DOM} \implies \text{Verdict} = \text{BLOCK}$$

Untrusted data cannot flow into high-authority sinks (command execution, payment submission, credential release) without explicit declassification.

---

## 3. Bounded Information Gain & Inference Defense

To prevent correlational re-identification:
$$\Delta H(U) = H(U \mid \text{ObservedContext}) - H(U) \le \epsilon$$
When multiple quasi-identifiers (zip code, birth month, partial phone) are requested simultaneously, the Inference Firewall automatically coarsens granularities to enforce $k$-anonymity ($k \ge 5$).
