# VEIL Protocol Specification: Part 10 — Transaction Semantics & LIFO Compensation

**Specification Identifier**: `VEIL-SPEC-10`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Transactional Action Sequences

Multi-step agent operations (e.g., e-commerce order checkout, multi-page form filling) are grouped into an atomic transaction $\mathcal{T} = [a_1, a_2, \dots, a_k]$.

---

## 2. Invariants of Transaction Engine

### 2.1. Inverted Compensation Stack (LIFO)
For each executed action $a_i$, the kernel registers a compensating inverse action $c_i = a_i^{-1}$:
$$\text{Stack} \leftarrow [c_1, c_2, \dots, c_i]$$

### 2.2. Atomic Rollback on Exception
If step $a_j$ ($j \le k$) fails, throws an unhandled error, or triggers an invariant breach, the transaction engine immediately executes compensation actions in reverse order:
$$\text{Rollback}(\mathcal{T}) = c_j \circ c_{j-1} \circ \dots \circ c_1$$
Restoring the target state to pre-transaction baseline $S_0$.

### 2.3. Postcondition Verification
Execution success is distinct from action success:
$$\text{Status}(a_i) = \text{SUCCESS} \iff \text{ExitCode}(a_i) == 0 \land \text{VerifyPostcondition}(S_{\text{post}})$$
If the post-condition fails, the step is declared failed and rollback begins.
