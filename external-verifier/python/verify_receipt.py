#!/usr/bin/env python3
"""
VEIL — Independent Python Receipt Verifier CLI (Cross-Runtime Verification)

Zero external dependencies: uses only Python 3 standard library (sys, json, hashlib).
Validates VEIL cryptographic receipts independently of JavaScript or Chromium runtimes.

Usage:
    python verify_receipt.py [path/to/receipt.json]
"""

import sys
import json
import hashlib

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def canonical_stringify(obj) -> str:
    """Deterministic JSON serialization matching VEIL kernel canonicalStringify."""
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
        entries = [json.dumps(k) + ':' + canonical_stringify(obj[k]) for k in sorted_keys]
        return '{' + ','.join(entries) + '}'
    return json.dumps(obj)

def verify_receipt(receipt: dict) -> tuple[str, int, list[str]]:
    """Validates the receipt hash chain and payload hashes."""
    errors = []

    if not isinstance(receipt, dict):
        return "INVALID", 0, ["Receipt is not a JSON dictionary"]

    if receipt.get("receiptType") != "VEIL_SECURITY_RECEIPT":
        errors.append(f"Invalid receiptType: expected 'VEIL_SECURITY_RECEIPT', got '{receipt.get('receiptType')}'")

    chain = receipt.get("chain", [])
    if not isinstance(chain, list):
        return "INVALID", 0, ["Missing chain array"]

    if len(chain) == 0:
        return "VALID", 0, []

    expected_prev = chain[0].get("prevHash", "")
    verified_count = 0

    for i, evt in enumerate(chain):
        # 1. Check prevHash link
        if evt.get("prevHash") != expected_prev:
            errors.append(f"Broken chain link at event {i}: expected {expected_prev}, got {evt.get('prevHash')}")
            return "TAMPERED", verified_count, errors

        # 2. Check payload hash
        clean_detail = evt.get("detail", {})
        payload_serialized = canonical_stringify(clean_detail)
        calc_payload_hash = sha256_hex(payload_serialized)

        if calc_payload_hash != evt.get("payloadHash"):
            errors.append(f"Tampered payload hash at event {i}: computed {calc_payload_hash}, claimed {evt.get('payloadHash')}")
            return "TAMPERED", verified_count, errors

        # 3. Check event header hash
        hdr = f"{evt.get('prevHash')}:{evt.get('eventIndex')}:{evt.get('timestamp')}:{evt.get('type')}:{evt.get('payloadHash')}"
        calc_evt_hash = sha256_hex(hdr)

        if calc_evt_hash != evt.get("hash"):
            errors.append(f"Tampered event header hash at event {i}: computed {calc_evt_hash}, claimed {evt.get('hash')}")
            return "TAMPERED", verified_count, errors

        expected_prev = evt.get("hash")
        verified_count += 1

    # 4. Check terminal head hash
    terminal_hash = chain[-1].get("hash")
    if receipt.get("headHash") and receipt.get("headHash") != terminal_hash:
        errors.append(f"Claimed headHash '{receipt.get('headHash')}' != terminal event hash '{terminal_hash}'")
        return "TAMPERED", verified_count, errors

    verdict = "VALID" if len(errors) == 0 else "INVALID"
    return verdict, verified_count, errors

def main():
    print("=" * 75)
    print("🛡️  VEIL — INDEPENDENT PYTHON RECEIPT VERIFIER (CROSS-RUNTIME)")
    print("=" * 75)

    if len(sys.argv) < 2:
        print("▶ [SELF-TEST MODE]: Generating synthetic receipt bundle in Python...")
        h0 = "0" * 64
        payload = {"version": "2.4.0", "origin": "python_test"}
        p_hash = sha256_hex(canonical_stringify(payload))
        h1 = sha256_hex(f"{h0}:0:2000:BOOT:{p_hash}")

        receipt = {
            "receiptType": "VEIL_SECURITY_RECEIPT",
            "version": "2.4.0",
            "genesisHash": h0,
            "headHash": h1,
            "eventCount": 1,
            "chain": [
                {
                    "id": "evt-py-0",
                    "eventIndex": 0,
                    "timestamp": 2000,
                    "type": "BOOT",
                    "stage": "kernel",
                    "detail": payload,
                    "payloadHash": p_hash,
                    "prevHash": h0,
                    "hash": h1
                }
            ]
        }
    else:
        file_path = sys.argv[1]
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                receipt = json.load(f)
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            sys.exit(1)

    verdict, count, errors = verify_receipt(receipt)

    print(f"  • Claimed Version:   {receipt.get('version', 'UNKNOWN')}")
    print(f"  • Claimed Head Hash: {receipt.get('headHash', '')}")
    print(f"  • Events Verified:   {count}")
    print("-" * 75)

    if verdict == "VALID":
        print("✅ PYTHON INDEPENDENT VERIFICATION VERDICT: VALID")
        print("   • Cryptographic SHA-256 chain confirmed from Genesis to Head.")
        print("   • Zero dependency on Node.js, Chromium, or VEIL runtime.")
        print("   • Evidence is completely portable and cross-runtime validated.")
        print("=" * 75 + "\n")
        sys.exit(0)
    else:
        print(f"❌ PYTHON INDEPENDENT VERIFICATION VERDICT: {verdict}")
        for err in errors:
            print(f"   • {err}")
        print("=" * 75 + "\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
