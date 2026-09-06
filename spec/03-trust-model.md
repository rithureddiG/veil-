# VEIL Protocol Specification: Part 03 — Three-Domain Trust Architecture

**Specification Identifier**: `VEIL-SPEC-03`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. The Three Trust Domains

```
   DOMAIN A: UNTRUSTED COMPUTE        DOMAIN B: UNTRUSTED WORLD
   ┌───────────────────────────┐      ┌───────────────────────────┐
   │ • LLM / VLM Reasoning    │      │ • Third-Party Web DOM     │
   │ • Planner / Model Weights │      │ • Remote MCP Tool Servers │
   │ • Intermediate Chains     │      │ • External Network Hosts  │
   └─────────────┬─────────────┘      └─────────────┬─────────────┘
                 │ Proposals                        │ Raw Perceptions
                 ▼                                  ▼
   ══════════════════════════════════════════════════════════════════
                   SECURITY BOUNDARY (Fail-Closed)
   ══════════════════════════════════════════════════════════════════
                                    ▲
                                    │
                       DOMAIN C: TRUSTED COMPUTING BASE
                       ┌───────────────────────────────┐
                       │ • VEIL Security Kernel        │
                       │ • Capability Manager          │
                       │ • Effect Gates                │
                       │ • Secret Vault                │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       DOMAIN D: ROOT OF TRUST
                       ┌───────────────────────────────┐
                       │ • User Out-of-Band (OOB) UI   │
                       └───────────────────────────────┘
```

---

## 2. Trust Axioms

1. **Axiom 1 (Untrusted Intelligence)**: No generative model output is ever trusted with direct execution authority.
2. **Axiom 2 (Hostile World)**: All incoming DOM content, network data, and API payloads are assumed to be potentially malicious.
3. **Axiom 3 (Kernel Invariant Enforcement)**: All state-altering side effects must traverse the trusted kernel.
4. **Axiom 4 (Human Root Authority)**: High-risk and irreversible operations strictly require explicit user confirmation through an isolated UI channel that cannot be simulated or overlaid by web scripts.
