#!/usr/bin/env python3
"""
VEIL v2.5 — Independent Scientific Reproduction Verifier: Standalone Policy Engine
Pure Python 3 implementation (Zero VEIL runtime dependencies).
Conforms strictly to VEIL-SPEC-04 & VEIL-SPEC-08 (Policy & Taint Law).
"""

import sys
import json

def evaluate_vpl_policy(proposal, rules):
    action_type = proposal.get("actionType")
    intent = proposal.get("intent", "")
    taint_tags = proposal.get("taintTags", [])
    risk = proposal.get("risk", "LOW")

    # Invariant Law: Untrusted taint cannot invoke high-risk or secret release actions
    has_untrusted_taint = any(t in ["TAINT_UNTRUSTED_DOM", "TAINT_INDIRECT_PROMPT"] for t in taint_tags)
    if has_untrusted_taint and (risk in ["HIGH", "CRITICAL"] or "SECRET" in action_type):
        return {
            "verdict": "BLOCK",
            "reason": "TAINT_PROPAGATION_VIOLATION: Untrusted web content cannot flow into sensitive effect sink"
        }

    # Match rules in priority order
    for rule in rules:
        rule_action = rule.get("action")
        if rule_action == action_type or rule_action == "*":
            if not rule.get("allow", True):
                return {
                    "verdict": "BLOCK",
                    "reason": f"Explicit deny rule matched: {rule_action}"
                }

            if rule.get("requireConfirmation", False) or risk == "CRITICAL":
                return {
                    "verdict": "CONFIRM",
                    "reason": "High risk action requires user out-of-band confirmation"
                }

            return {
                "verdict": "ALLOW",
                "reason": "Rule permits action"
            }

    # Fail-closed default
    return {
        "verdict": "BLOCK",
        "reason": "DEFAULT_FAIL_CLOSED: No policy rule authorized proposal"
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verify_policy.py <proposal.json> <rules.json>")
        sys.exit(1)

    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        prop = json.load(f)
    with open(sys.argv[2], 'r', encoding='utf-8') as f:
        rul = json.load(f)

    res = evaluate_vpl_policy(prop, rul)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["verdict"] == "ALLOW" else 1)
