# VEIL Protocol Specification: Part 13 — Security Considerations & The Minimal TCB

**Specification Identifier**: `VEIL-SPEC-13`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. The Fundamental Question: "Who Verifies the Verifier?"

In any security architecture, recursive verification must terminate at an axiomatic foundation:
$$\text{VEIL Runtime} \xrightarrow{\text{bisimulates}} \text{Reference Kernel} \xrightarrow{\text{audited by}} \text{Independent Verifier} \xrightarrow{\text{conforms to}} \text{Formal Specification}$$

The chain terminates at the **VEIL Formal Specification** and its mathematical invariants.

---

## 2. Minimal Trusted Computing Base (TCB) Boundary

The VEIL TCB is strictly bounded to 8 tightly-coupled core components:

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED COMPUTING BASE                   │
├─────────────────────────────────────────────────────────────┤
│ 1. Policy Decision Point (PDP)                              │
│ 2. Capability Manager (Token minter & nonce registry)       │
│ 3. State Hasher (Canonical state commitment)                │
│ 4. Dynamic Taint Engine (Provenance tracking)               │
│ 5. Unified Effect Gate (Mediation boundary)                 │
│ 6. Secret Vault (ValueRef resolution)                       │
│ 7. Transaction Engine (LIFO rollback coordinator)           │
│ 8. Security Ledger (Cryptographic receipt chain)            │
└─────────────────────────────────────────────────────────────┘
```

### Components Explicitly Excluded from TCB:
- **The Generative Model / LLM / VLM** (100% Untrusted Compute).
- **The Browser DOM Tree & Web Pages** (100% Hostile World).
- **Content Scripts & Web Workers** (Outside kernel privilege boundary).
- **Remote MCP Tool Servers** (Mediated external entities).
- **Network Gateways / CDNs** (Untrusted transport).

---

## 3. Assumptions and Residual Vulnerabilities

1. **Hardware & OS Integrity**: The host operating system kernel and CPU are assumed to execute instructions faithfully without memory corruption.
2. **Cryptographic Primitives**: SHA-256 is assumed collision-resistant; HMAC-SHA256 is assumed unforgeable under chosen-message attacks.
3. **Privileged User Channel**: The extension side panel and native OS dialogs are assumed isolated from web page DOM injection by browser security architecture.
