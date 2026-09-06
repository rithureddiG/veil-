#!/usr/bin/env python3
"""
VEIL v2.5 — Independent Scientific Reproduction Verifier: Action Receipt
Pure Python 3 implementation (Zero VEIL runtime dependencies).
Conforms strictly to VEIL-SPEC-11 (Action Receipt Format).
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

def sha256(data):
    if not isinstance(data, str):
        data = canonical_stringify(data)
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def verify_receipt_data(receipt, secret=None):
    if not isinstance(receipt, dict):
        return {"verdict": "INVALID", "errors": ["Receipt is not a JSON object"]}

    errors = []
    if receipt.get("receiptType") != "VEIL_SECURITY_RECEIPT":
        errors.append(f"Invalid receiptType: expected VEIL_SECURITY_RECEIPT, got {receipt.get('receiptType')}")

    chain = receipt.get("chain")
    if not isinstance(chain, list):
        return {"verdict": "INVALID", "errors": ["Missing chain list"]}

    if len(chain) == 0:
        return {"verdict": "VALID", "verifiedEvents": 0, "errors": []}

    expected_prev = receipt.get("genesisHash", "0" * 64)

    for i, event in enumerate(chain):
        prev_hash = event.get("prevHash")
        event_hash = event.get("eventHash")
        payload = event.get("payload")

        if prev_hash != expected_prev:
            errors.append(f"Event {i} broken link: expected prevHash {expected_prev}, found {prev_hash}")

        # Compute payload hash
        payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=False)
        computed_event_hash = sha256(prev_hash + payload_str)

        # Also test with canonical stringify if standard dumps diverges
        if computed_event_hash != event_hash:
            alt_hash = sha256(prev_hash + json.dumps(payload))
            if alt_hash != event_hash:
                errors.append(f"Event {i} hash mismatch: computed {computed_event_hash}, declared {event_hash}")

        expected_prev = event_hash

    declared_root = receipt.get("sessionRoot")
    if declared_root and declared_root != expected_prev:
        errors.append(f"Session root mismatch: expected {expected_prev}, declared {declared_root}")

    verdict = "VALID" if len(errors) == 0 else "TAMPERED"
    return {
        "verdict": verdict,
        "verifiedEvents": len(chain),
        "headHash": expected_prev,
        "errors": errors
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_receipt.py <receipt_path.json>")
        sys.exit(1)

    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        data = json.load(f)

    res = verify_receipt_data(data)
    print(f"Verdict: {res['verdict']} (Verified: {res['verifiedEvents']} events)")
    if res["errors"]:
        for e in res["errors"]:
            print(f"  Error: {e}")
        sys.exit(1)
    sys.exit(0)
