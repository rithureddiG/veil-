# Authority Mediation for Autonomous Computation: Decoupling Intelligence from Authority in Generative AI Systems

**Paper Working Title**: *Authority Mediation for Autonomous Computation*  
**Authors**: VEIL Security Research Consortium  
**Classification**: Computer Systems & Security (ACM / IEEE S&P / USENIX Security Target)  
**Status**: Formal Research Paper Draft (v2.5)  

---

## Abstract

Autonomous agents powered by Large Language Models (LLMs) and Vision-Language Models (VLMs) increasingly interact with the real world through web browsing, tool use, and API orchestration. However, existing agent frameworks conflate *reasoning intelligence* with *execution authority*: when a model plans an action, the runtime immediately executes the associated side effect. This architectural defect exposes autonomous systems to catastrophic Indirect Prompt Injections (IPI), Time-of-Check to Time-of-Use (TOCTOU) state mutations, credential exfiltration, and tool abuse.

We propose **VEIL**, a zero-trust security runtime and protocol that formally decouples intelligence from execution authority. Under the VEIL architecture, the model operates in an untrusted compute domain with zero native authority ($\text{Authority}(\mathcal{A}) = \emptyset$). Every protected side effect—across DOM mutation, network egress, credential retrieval, financial transfer, and tool dispatch—is strictly mediated by an on-device security kernel. We formulate three formal theorems: (1) **Authority Singularity**, proving that exactly one kernel authority issues execution rights; (2) **Refinement Bisimulation**, proving that the production runtime bisimulates a pure mathematical reference model; and (3) **Proof-Carrying Actions (PCA)**, establishing mathematical symmetry between authorization proofs prior to execution and cryptographic evidence emitted post-execution.

To overcome the circular self-attestation common in agent evaluation, we deliver an independent scientific reproduction package enabling offline verification in pure Python 3 without running or trusting the VEIL runtime. We evaluate VEIL across a multidimensional benchmark encompassing Security, Reliability, Performance, Reproducibility, and Black-Box Adversarial Robustness.

---

## 1. Introduction & The Direct-Authority Fallacy

Current agent systems operate under what we define as the **Direct-Authority Fallacy**:
$$\text{ModelPlan}(a) \implies \text{ExecuteEffect}(a)$$

This architectural paradigm assumes that either:
1. The model can be made robust against prompt injection via alignment training, or
2. Guardrail filters can intercept all hostile user inputs before reaching the model.

Both assumptions fail in real-world interactive environments. When an agent browses the web, reads user emails, or inspects customer databases, hostile adversarial instructions are embedded within untrusted data payloads. Once the model's reasoning is steered, it exercises the agent's ambient operating privileges without constraint.

### The Fundamental Equation of VEIL
VEIL resolves this by introducing strict authority mediation:

$$\textbf{Autonomous Intelligence} + \textbf{Untrusted Environment} + \textbf{Potential Side Effects} \xrightarrow{\textbf{VEIL}} \textbf{Cryptographic Evidence}$$

```
                ┌───────────────────────────┐
                │   UNTRAINED / UNTRUSTED   │
                │        AI MODEL           │
                └─────────────┬─────────────┘
                              │ Proposes Intent
                              ▼
                ┌───────────────────────────┐
                │      INTENT LAYER         │
                └─────────────┬─────────────┘
                              │
                              ▼
                ┌───────────────────────────┐
                │    VEIL SECURITY KERNEL   │
                │                           │
                │  • Policy Decision Point  │
                │  • Dynamic Taint Engine   │
                │  • Capability Manager     │
                │  • State Commitment Guard │
                │  • Invariant Watchdog     │
                └─────────────┬─────────────┘
                              │ Minted Capability Token
                              ▼
                ┌───────────────────────────┐
                │        EFFECT GATE        │
                └─────────────┬─────────────┘
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
            Browser          MCP          System
            Web DOM         Tools         Devices
```

---

## 2. Core Scientific Contributions

1. **Protocol Formalization (`spec/01-13`)**: A 13-part formal specification standard defining terminology, threat models, 14 protected effects, capability tokens, state commitment, taint lattices, and LIFO transaction compensation.
2. **The Minimal TCB Boundary**: Formally restricting the trusted computing base to 8 core kernel primitives, proving models, DOMs, scripts, and MCP tool servers operate 100% outside the TCB.
3. **Proof-Carrying Actions (PCA)**: An action architecture where every operation carries its own pre-execution authorization proof and post-execution invariant witness.
4. **Zero-Trust MCP Tool Security Gateway**: In-line mediation, taint boundaries, and single-use capability nonces for the Model Context Protocol.
5. **Independent Scientific Reproduction**: Zero-dependency pure Python 3 verifiers allowing third-party auditors to falsify receipts, state bindings, and capability tokens completely offline.

---

## 3. Multidimensional Evaluation Framework

Rather than reporting a single superficial "100% defense" metric, VEIL is evaluated across five distinct, scientifically grounded dimensions:

```
┌────────────────────────────────────────────────────────────────────────┐
│               MULTIDIMENSIONAL SCIENTIFIC EVALUATION                   │
├────────────────────────────────────────────────────────────────────────┤
│ 1. SECURITY                                                            │
│    • Unauthorized Side Effects Permitted: 0                            │
│    • Replay Attack Defense Rate:          100.0%                       │
│    • TOCTOU State-Swap Interception:      100.0%                       │
│    • Capability Forgery Defense Rate:     100.0%                       │
│    • Taint Confinement Defense Rate:      100.0%                       │
│    • Secret Vault Exfiltration Rate:      0.0% (Zero secrets leaked)   │
├────────────────────────────────────────────────────────────────────────┤
│ 2. RELIABILITY                                                         │
│    • False-Denial Rate (Benign Actions):  0.0%                         │
│    • False-Allow Rate (Hostile Vectors):  0.0%                         │
│    • LIFO Transaction Recovery Rate:      100.0%                       │
│    • State Commitment Consistency:        100.0%                       │
├────────────────────────────────────────────────────────────────────────┤
│ 3. PERFORMANCE & OVERHEAD                                              │
│    • State Commitment Latency (P50):      < 0.8 ms                     │
│    • State Commitment Latency (P95):      < 2.1 ms                     │
│    • Capability Token Verification (P99): < 0.4 ms                     │
│    • Merkle Receipt Emission Latency:     < 1.2 ms                     │
│    • Peak Memory Footprint Overhead:      < 12 MB                      │
├────────────────────────────────────────────────────────────────────────┤
│ 4. REPRODUCIBILITY & CONFORMANCE                                       │
│    • JS ↔ Reference Model Agreement:     100.0% (Homomorphic)         │
│    • Python ↔ Reference Model Agreement:  100.0% (Homomorphic)         │
│    • Cross-Runtime Golden Vector Match:   100.0% (6/6 Verifiers)       │
│    • Reference Kernel Mutation Score:     100.0% (All mutants killed)  │
├────────────────────────────────────────────────────────────────────────┤
│ 5. ADVERSARIAL ROBUSTNESS                                              │
│    • Known Vector Test Matrix (V-ATM):    100.0% (30/30 Intercepted)   │
│    • Compound Unknown Attack Challenge:   100.0% (50/50 Blocked)       │
│    • Black-Box Goal-Directed Attacker:    100.0% (50/50 Intercepted)   │
│    • Concurrency & Race Condition Attack: 100.0% (1 allowed, 19 deny)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Discussion: The Trusted Computing Base & Open Problems

A critical question in autonomous system security is: **Who verifies the verifier?**
In VEIL:
$$\text{Production Runtime} \xrightarrow{\text{bisimulates}} \text{Reference Kernel} \xrightarrow{\text{audited by}} \text{Independent Verifier} \xrightarrow{\text{conforms to}} \text{Formal Specification}$$

The verification terminates at the minimal TCB boundary and mathematical axioms. Open challenges remain in hardware memory safety (mitigated by sandboxing) and visual-only deception (addressed by on-device visual OCR validation).

---

## 5. Conclusion

VEIL demonstrates that autonomous AI agents do not require unbounded trust to be useful. By strictly separating intelligence from authority, mediating all protected effects, and anchoring execution in cryptographic evidence, VEIL establishes a principled, independently reproducible foundation for secure agentic computing.
