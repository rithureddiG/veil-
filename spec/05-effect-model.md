# VEIL Protocol Specification: Part 05 — Protected Effect Model

**Specification Identifier**: `VEIL-SPEC-05`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. The 14 Protected Effect Primitives

Every interaction that can modify persistent state, dispatch network packets, access credentials, or execute external tools is classified under one of 14 protected effect primitives:

| ID | Primitive Name | Category | Risk Level | Target Subsystem |
| :---: | :--- | :--- | :---: | :--- |
| `E01` | `EFFECT_INTERACT_CLICK` | DOM Interaction | MEDIUM | `DOMEffectGate` |
| `E02` | `EFFECT_INTERACT_TYPE` | DOM Interaction | MEDIUM | `DOMEffectGate` |
| `E03` | `EFFECT_INTERACT_SUBMIT` | DOM Interaction | HIGH | `DOMEffectGate` |
| `E04` | `EFFECT_NAVIGATE_URL` | Browser Navigation | HIGH | `NavigationGate` |
| `E05` | `EFFECT_NAVIGATE_HISTORY` | Browser Navigation | LOW | `NavigationGate` |
| `E06` | `EFFECT_NETWORK_FETCH` | Network Egress | HIGH | `NetworkEffectGate` |
| `E07` | `EFFECT_NETWORK_XHR` | Network Egress | HIGH | `NetworkEffectGate` |
| `E08` | `EFFECT_STORAGE_WRITE` | Local Persistence | HIGH | `StorageGate` |
| `E09` | `EFFECT_STORAGE_DELETE` | Local Persistence | CRITICAL | `StorageGate` |
| `E10` | `EFFECT_CLIPBOARD_WRITE` | System Clipboard | HIGH | `ClipboardGate` |
| `E11` | `EFFECT_SECRET_RELEASE` | Credential Vault | CRITICAL | `SecretReleaseGate` |
| `E12` | `EFFECT_FINANCIAL_TRANSACT`| Monetary Action | CRITICAL | `PolicyDecisionPoint` |
| `E13` | `EFFECT_TOOL_DISPATCH` | MCP / OS Tools | HIGH/CRIT | `McpGateway` |
| `E14` | `EFFECT_STATE_REVERT` | Transaction Engine | LOW | `TransactionEngine` |

---

## 2. Mediation Completeness Requirement

For every primitive $e \in \mathcal{E}$, there exists an interception boundary $\mathcal{B}_e$ such that:
$$\text{Invoked}(e) \implies \text{MediatedBy}(\mathcal{B}_e, e)$$
If an unmediated code path attempts execution of $e$, the native browser / OS execution environment traps and aborts the execution thread.
