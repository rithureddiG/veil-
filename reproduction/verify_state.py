#!/usr/bin/env python3
"""
VEIL v2.5 — Independent Scientific Reproduction Verifier: State Commitment & TOCTOU
Pure Python 3 implementation (Zero VEIL runtime dependencies).
Conforms strictly to VEIL-SPEC-07 (State Commitment Protocol).
"""

import sys
import json
import hashlib

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

def compute_state_hash(state_obj):
    canonical = canonical_stringify(state_obj)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

def verify_state_commitment(pre_state_hash, current_state_obj):
    computed_hash = compute_state_hash(current_state_obj)
    matches = (computed_hash == pre_state_hash)

    return {
        "valid": matches,
        "preStateHash": pre_state_hash,
        "currentStateHash": computed_hash,
        "error": None if matches else "ERR_STATE_DESYNCHRONIZATION: Target state modified after check"
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verify_state.py <expected_pre_hash> <state_object.json>")
        sys.exit(1)

    expected = sys.argv[1]
    with open(sys.argv[2], 'r', encoding='utf-8') as f:
        state = json.load(f)

    res = verify_state_commitment(expected, state)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["valid"] else 1)
