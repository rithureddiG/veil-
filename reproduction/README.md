# VEIL v2.5 — Independent Scientific Reproduction Package

This package provides everything required for an independent security researcher, academic reviewer, or auditor to independently verify and reproduce all mathematical and cryptographic claims of VEIL **with zero dependencies on the VEIL runtime**.

---

## 1. Zero-Dependency Reproduction (Python 3.10+)

All verification scripts are authored strictly from the **VEIL Protocol Specification (`spec/`)** and require only the standard Python library (`hashlib`, `hmac`, `json`, `sys`, `time`).

### Run All Verifications:
```bash
python run_all_reproductions.py
```

### Individual Verifiers:
```bash
# 1. Verify Action Receipt Cryptographic Integrity & Session Root
python verify_receipt.py expected-results/golden-vectors.json

# 2. Verify Monotonic Ledger Chain Continuity & Fork Detection
python verify_chain.py expected-results/golden-vectors.json

# 3. Verify Capability Token Ephemerality & Signature
python verify_capability.py expected-results/golden-vectors.json VEIL_REPRODUCTION_KEY_1234567890

# 4. Verify State Commitment & TOCTOU Trap
python verify_state.py 0x_expected_hash target_state.json

# 5. Verify Standalone Policy Engine & Taint Confinement Law
python verify_policy.py proposal.json rules.json

# 6. Verify Proof-Carrying Action (PCA) Lifecycle Bundle
python verify_pca.py expected-results/golden-vectors.json VEIL_REPRODUCTION_KEY_1234567890
```

---

## 2. Docker Clean-Machine Reproduction

To guarantee an isolated, clean-room evaluation environment:

```bash
docker build -t veil-reproduction reproduction/
docker run --rm veil-reproduction
```
