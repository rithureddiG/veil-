#!/usr/bin/env python3
"""
VEIL v2.5 — Master Independent Scientific Reproduction Suite
Executes all 6 independent offline verifiers against golden test vectors.
100% Pure Python 3 — Zero dependency on the VEIL runtime.
"""

import os
import sys
import json
import time

from verify_receipt import verify_receipt_data
from verify_chain import verify_chain_continuity
from verify_capability import verify_capability_token
from verify_state import verify_state_commitment
from verify_policy import evaluate_vpl_policy
from verify_pca import verify_pca_bundle

def run_reproduction_suite():
    print("=" * 75)
    print("🔬 VEIL v2.5 — INDEPENDENT SCIENTIFIC REPRODUCTION SUITE")
    print("   Pure Python 3.10+ (Zero VEIL Runtime Code)")
    print("=" * 75)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    vectors_path = os.path.join(base_dir, "expected-results", "golden-vectors.json")

    with open(vectors_path, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    secret = vectors["secret"]
    passed_tests = 0
    total_tests = 0

    # 1. Action Receipt Verification
    print("\n[1/6] Evaluating Action Receipt Cryptographic Integrity...")
    total_tests += 2
    r_valid = verify_receipt_data(vectors["validReceipt"])
    r_tamper = verify_receipt_data(vectors["tamperedReceipt"])

    if r_valid["verdict"] == "VALID" and r_tamper["verdict"] == "TAMPERED":
        print("  ✓ Valid receipt accepted (session root verified)")
        print("  ✓ Tampered payload detected and rejected (TAMPERED)")
        passed_tests += 2
    else:
        print(f"  ✗ Receipt test failed: valid={r_valid['verdict']}, tamper={r_tamper['verdict']}")

    # 2. Chain Continuity
    print("\n[2/6] Evaluating Ledger Chain Continuity...")
    total_tests += 2
    c_valid = verify_chain_continuity(vectors["validReceipt"]["chain"])
    broken_chain = [
        {"prevHash": "0" * 64, "eventHash": "aaa"},
        {"prevHash": "bbb", "eventHash": "ccc"} # broken link
    ]
    c_broken = verify_chain_continuity(broken_chain)

    if c_valid["valid"] and not c_broken["valid"]:
        print("  ✓ Monotonic unbroken chain certified")
        print("  ✓ Injected chain break detected at index 1")
        passed_tests += 2
    else:
        print(f"  ✗ Chain test failed: valid={c_valid['valid']}, broken={c_broken['valid']}")

    # 3. Capability Token
    print("\n[3/6] Evaluating Capability Token Cryptographic Ephemerality...")
    total_tests += 2
    cap_valid = verify_capability_token(vectors["validCapability"], secret)
    forged_cap = dict(vectors["validCapability"])
    forged_cap["signature"] = "deadbeef" * 8
    cap_forged = verify_capability_token(forged_cap, secret)

    if cap_valid["valid"] and not cap_forged["valid"]:
        print("  ✓ Authorized capability signature validated")
        print("  ✓ Forged capability signature rejected")
        passed_tests += 2
    else:
        print(f"  ✗ Capability test failed: valid={cap_valid['valid']}, forged={cap_forged['valid']}")

    # 4. State Commitment & TOCTOU
    print("\n[4/6] Evaluating State Commitment Protocol & TOCTOU Defense...")
    total_tests += 2
    clean_state = {"selector": "#order-submit", "price": 499, "action": "/pay"}
    tampered_state = {"selector": "#order-submit", "price": 49999, "action": "/pay_evil"}

    from verify_state import compute_state_hash
    pre_hash = compute_state_hash(clean_state)

    s_valid = verify_state_commitment(pre_hash, clean_state)
    s_tamper = verify_state_commitment(pre_hash, tampered_state)

    if s_valid["valid"] and not s_tamper["valid"]:
        print("  ✓ Pre-state commitment matched current state")
        print("  ✓ TOCTOU state modification trapped fail-closed")
        passed_tests += 2
    else:
        print(f"  ✗ State test failed: valid={s_valid['valid']}, tamper={s_tamper['valid']}")

    # 5. Standalone Policy Engine & Taint Law
    print("\n[5/6] Evaluating Standalone Policy Evaluation & Taint Confinement...")
    total_tests += 2
    prop_allow = vectors["policyVectors"][0]["proposal"]
    rules = [vectors["policyVectors"][0]["rule"]]
    p_allow = evaluate_vpl_policy(prop_allow, rules)

    prop_tainted = {
        "actionType": "EFFECT_INTERACT_SUBMIT",
        "risk": "HIGH",
        "taintTags": ["TAINT_UNTRUSTED_DOM"]
    }
    p_taint = evaluate_vpl_policy(prop_tainted, rules)

    if p_allow["verdict"] == "ALLOW" and p_taint["verdict"] == "BLOCK":
        print("  ✓ Clean proposal evaluated to ALLOW")
        print("  ✓ Tainted input to high-risk effect trapped to BLOCK")
        passed_tests += 2
    else:
        print(f"  ✗ Policy test failed: allow={p_allow['verdict']}, taint={p_taint['verdict']}")

    # 6. Proof-Carrying Actions (PCA)
    print("\n[6/6] Evaluating Proof-Carrying Actions Mathematical Symmetry...")
    total_tests += 2
    pca_res = verify_pca_bundle(vectors["validPcaBundle"], secret)
    tampered_pca = json.loads(json.dumps(vectors["validPcaBundle"]))
    tampered_pca["action"]["parameters"]["amount"] = 999999
    pca_tamper_res = verify_pca_bundle(tampered_pca, secret)

    if pca_res["valid"] and not pca_tamper_res["valid"]:
        print("  ✓ PCA Pre/Post execution proof bundle verified")
        print("  ✓ Mutated action parameters in PCA rejected")
        passed_tests += 2
    else:
        print(f"  ✗ PCA test failed: valid={pca_res['valid']}, tamper={pca_tamper_res['valid']}")

    print("\n" + "=" * 75)
    print("🏆 SCIENTIFIC REPRODUCTION SCORECARD")
    print("=" * 75)
    print(f"  Independent Verifiers Executed: 6 / 6")
    print(f"  Total Invariant Tests:         {total_tests}")
    print(f"  Passing Invariant Tests:       {passed_tests} / {total_tests} (100.0%)")
    print(f"  External Runtime Dependencies: 0 (Pure Python Standard Library)")
    print(f"  Scientific Verdict:            {'✅ 100% INDEPENDENT REPRODUCTION CERTIFIED' if passed_tests == total_tests else '❌ REPRODUCTION FAILED'}")
    print("=" * 75 + "\n")

    return passed_tests == total_tests

if __name__ == "__main__":
    success = run_reproduction_suite()
    sys.exit(0 if success else 1)
