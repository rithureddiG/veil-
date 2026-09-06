# VEIL Protocol Specification: Part 12 — Implementation Conformance Criteria

**Specification Identifier**: `VEIL-SPEC-12`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Conformance Tiers

```
┌────────────────────────────────────────────────────────┐
│  Tier 3: Full Kernel Conformance (VEIL-K3)             │
│  - Executes runtime state machine                      │
│  - Enforces all 14 protected effects                   │
│  - Satisfies zero-bypass and refinement bisimulation   │
├────────────────────────────────────────────────────────┤
│  Tier 2: Differential Policy & IR Conformance (VEIL-P2)│
│  - Evaluates VPL AST and compiles bytecode/IR          │
│  - Passes all differential decision oracle test suites │
├────────────────────────────────────────────────────────┤
│  Tier 1: Offline Receipt Verification Conformance (VEIL-V1)
│  - Validates VEIL Action Receipts independently        │
│  - Verifies cryptographic hash chains and HMACs        │
│  - Zero dependency on VEIL execution engine            │
└────────────────────────────────────────────────────────┘
```

---

## 2. Certification Suites

An engine or auditor claiming conformance to VEIL-SPEC must pass:

1. **Receipt Verification**: 100% pass on 25 golden vectors without VEIL runtime.
2. **Chain Continuity**: Detects 100% of injected hash breaks, forks, and reorderings.
3. **Mutation Resistance**: 100% kill rate against the official reference mutant suite.
4. **State-Transition Homomorphism**: 100% agreement on full transition tuples ($\text{State}_0 \xrightarrow{\text{Action}} \text{State}_1$) across all test vectors.
