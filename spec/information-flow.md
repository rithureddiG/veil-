# VEIL Information Flow Control (IFC) Specification

> **Specification Identifier**: `veil.spec.ifc/v1`  
> **Axiom**: *Information carries provenance, not merely sensitivity. Privacy is bounded information gain.*

---

## 1. Security Lattice

$$\mathcal{L} = \langle \mathcal{T}, \sqsubseteq, \sqcup, \sqcap \rangle$$

$$\text{PUBLIC } (0) \sqsubseteq \text{INTERNAL } (1) \sqsubseteq \text{PERSONAL } (2) \sqsubseteq \text{SENSITIVE } (3) \sqsubseteq \text{FINANCIAL\_SECRET } (4) \sqsubseteq \text{CREDENTIAL } (5)$$

---

## 2. Provenance Object Schema

Every tracked value carries complete provenance lineage:

```json
{
  "level": 4,
  "name": "FINANCIAL_SECRET",
  "origin": "https://bank.example/checkout",
  "owner": "user_primary",
  "purpose": "ticket_purchase",
  "allowedDestinations": ["https://bank.example/api/pay"],
  "transformations": ["mask", "synthetic_ref"],
  "derivedFrom": ["vault_sec_89"],
  "timestamp": 1725619200000,
  "policyConstraints": {}
}
```

---

## 3. Sink Flow Theorem

$$\forall \tau \in \mathcal{T}, \forall s \in \mathcal{S}_{\text{sinks}}: \quad \text{FlowAllowed}(\tau, s) \iff \tau \sqsubseteq \text{MaxLevel}(s) \lor \text{AuthorizedCapability}(\tau, s)$$

- **Cloud Model Sink**: $\text{MaxLevel} = \text{PUBLIC } (0)$.
- **Remote Network Egress**: $\text{MaxLevel} = \text{INTERNAL } (1)$.
- **Security Ledger Sink**: $\text{MaxLevel} = \text{SENSITIVE } (3)$. Plaintext secrets scrubbed before hashing.
