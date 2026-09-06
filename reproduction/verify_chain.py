#!/usr/bin/env python3
"""
VEIL v2.5 — Independent Scientific Reproduction Verifier: Ledger Chain Continuity
Pure Python 3 implementation (Zero VEIL runtime dependencies).
Conforms strictly to VEIL-SPEC-11 (Action Receipt & Ledger Continuity).
"""

import sys
import json
import hashlib

def verify_chain_continuity(chain_events):
    if not isinstance(chain_events, list):
        return {"valid": False, "error": "Input must be an array of chain events"}

    if len(chain_events) <= 1:
        return {"valid": True, "eventCount": len(chain_events), "error": None}

    for i in range(1, len(chain_events)):
        prev_evt = chain_events[i - 1]
        curr_evt = chain_events[i]

        expected_prev = prev_evt.get("eventHash")
        actual_prev = curr_evt.get("prevHash")

        if expected_prev != actual_prev:
            return {
                "valid": False,
                "error": f"Chain broken at event index {i}: expected prevHash '{expected_prev}', got '{actual_prev}'",
                "brokenIndex": i
            }

    return {
        "valid": True,
        "eventCount": len(chain_events),
        "genesis": chain_events[0].get("prevHash"),
        "tip": chain_events[-1].get("eventHash"),
        "error": None
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_chain.py <events.json>")
        sys.exit(1)

    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        data = json.load(f)

    events = data.get("chain", data) if isinstance(data, dict) else data
    res = verify_chain_continuity(events)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["valid"] else 1)
