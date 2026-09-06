#!/usr/bin/env python3
"""
VEIL v2.5 — Independent Scientific Reproduction Verifier: Proof-Carrying Actions (PCA)
Pure Python 3 implementation (Zero VEIL runtime dependencies).
Conforms strictly to VEIL-SPEC-11 & VEIL-PCA-v1.
"""

import sys
import json
import hashlib
import hmac

def canonical_stringify(obj):
    if obj is None:
        return 'null'
    if isinstance(obj, bool):
        return 'true' if obj else 'false'
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        return '[' + ','.join(canonical_stringify(x) for x in obj) + ']'
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys())
        items = [json.dumps(k) + ':' + canonical_stringify(obj[k]) for k in sorted_keys]
        return '{' + ','.join(items) + '}'
    return json.dumps(str(obj))

def hmac_sha256(obj, secret):
    msg = canonical_stringify(obj)
    return hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_pca_bundle(pca, secret):
    if not isinstance(pca, dict):
        return {"valid": False, "error": "PCA is not a JSON dictionary"}

    pre = pca.get("preProof")
    post = pca.get("postProof")
    action = pca.get("action")

    if not pre or not action:
        return {"valid": False, "error": "Incomplete PCA: missing preProof or action"}

    # 1. Verify PreExecutionProof signature
    pre_copy = dict(pre)
    auth_sig = pre_copy.pop("authorizationSignature", None)
    if not auth_sig:
        return {"valid": False, "error": "Missing preProof authorizationSignature"}

    expected_auth_sig = hmac_sha256(pre_copy, secret)
    if auth_sig != expected_auth_sig:
        return {"valid": False, "error": f"Invalid authorizationSignature: {auth_sig} != {expected_auth_sig}"}

    # 2. Verify Action Digest integrity
    expected_action_digest = hashlib.sha256(canonical_stringify(action).encode('utf-8')).hexdigest()
    if pre.get("actionDigest") and pre.get("actionDigest") != expected_action_digest:
        return {"valid": False, "error": "Action parameters tampered after proof generation"}

    # 3. Verify PostExecutionProof if present
    if post:
        post_copy = dict(post)
        comp_sig = post_copy.pop("completionSignature", None)
        if not comp_sig:
            return {"valid": False, "error": "Missing postProof completionSignature"}

        expected_comp_sig = hmac_sha256(post_copy, secret)
        if comp_sig != expected_comp_sig:
            return {"valid": False, "error": f"Invalid completionSignature: {comp_sig} != {expected_comp_sig}"}

        # 4. Chain Linkage
        if pre.get("pcaId") != post.get("pcaId"):
            return {"valid": False, "error": "PCA ID mismatch between preProof and postProof"}

    return {
        "valid": True,
        "pcaId": pca.get("pcaId"),
        "status": pca.get("status", "VALID"),
        "actionType": action.get("type"),
        "error": None
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verify_pca.py <pca_bundle.json> <secret>")
        sys.exit(1)

    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        bundle = json.load(f)

    res = verify_pca_bundle(bundle, sys.argv[2])
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["valid"] else 1)
