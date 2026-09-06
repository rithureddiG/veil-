#!/usr/bin/env python3
"""
VEIL v2.5 — Independent Scientific Reproduction Verifier: Capability Token
Pure Python 3 implementation (Zero VEIL runtime dependencies).
Conforms strictly to VEIL-SPEC-06 (Capability Model & Ephemerality).
"""

import sys
import json
import hashlib
import hmac
import time

def sha256_canonical(obj, secret):
    # Canonical token payload string
    # Format: capabilityId:actionType:stateHash:secret
    msg = f"{obj.get('capabilityId')}:{obj.get('actionType')}:{obj.get('stateHash')}:{secret}"
    return hashlib.sha256(msg.encode('utf-8')).hexdigest()

def verify_capability_token(token, secret, current_time_ms=None, consumed_nonces=None):
    if not isinstance(token, dict):
        return {"valid": False, "error": "Token is not a JSON object"}

    if consumed_nonces is None:
        consumed_nonces = set()

    cap_id = token.get("capabilityId")
    action_type = token.get("actionType")
    state_hash = token.get("stateHash")
    nonce = token.get("nonce")
    expires_at = token.get("expiresAt")
    sig = token.get("signature")

    if not all([cap_id, action_type, state_hash, nonce, sig]):
        return {"valid": False, "error": "Missing mandatory capability token fields"}

    # 1. Signature Check
    expected_sig = sha256_canonical(token, secret)
    if sig != expected_sig:
        return {"valid": False, "error": f"Invalid HMAC signature: expected {expected_sig}, got {sig}"}

    # 2. Expiration Check
    now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)
    if expires_at and now_ms > expires_at:
        return {"valid": False, "error": f"Capability expired at {expires_at} (current {now_ms})"}

    # 3. Nonce Replay Check
    if nonce in consumed_nonces:
        return {"valid": False, "error": f"Nonce replay detected: '{nonce}' already consumed"}

    return {
        "valid": True,
        "capabilityId": cap_id,
        "actionType": action_type,
        "stateHash": state_hash,
        "nonce": nonce,
        "error": None
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verify_capability.py <token.json> <secret>")
        sys.exit(1)

    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        tok = json.load(f)

    res = verify_capability_token(tok, sys.argv[2])
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["valid"] else 1)
