# VEIL Protocol Specification: Part 11 — Action Receipt & Ledger Format

**Specification Identifier**: `VEIL-SPEC-11`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Action Receipt Schema (`veil.action_receipt/v2`)

```json
{
  "$schema": "veil.action_receipt/v2",
  "receiptId": "rec_1725619200_9b8a7c",
  "timestamp": 1725619200000,
  "action": {
    "type": "EFFECT_INTERACT_CLICK",
    "target": "#confirm-order",
    "parameters": { "orderId": 88319 }
  },
  "verdict": "ALLOW",
  "evidence": {
    "intent": "confirm_order",
    "policyRuleId": "VPL-ORDER-ALLOW-01",
    "caller": "ecommerce_agent",
    "taintLevel": "TAINT_CLEAN"
  },
  "commitments": {
    "preStateHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "postStateHash": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
  },
  "integrity": {
    "actionHash": "a1b2c3d4...",
    "evidenceHash": "e5f6a7b8...",
    "preStateHash": "e3b0c442...",
    "postStateHash": "ca978112...",
    "receiptHash": "4d5e6f7a...",
    "previousReceiptHash": "0000000000000000000000000000000000000000000000000000000000000000",
    "signature": "8899aabbccddeeff..."
  }
}
```

---

## 2. Canonical Hashing Rules (RFC 8785)

1. Objects are serialized with keys in ascending lexicographic Unicode order.
2. Arrays preserve exact element order.
3. Whitespace outside JSON tokens is completely omitted.
4. Floats are serialized without unnecessary trailing zeros.
5. The `receiptHash` is computed as:
   $$\text{receiptHash} = \text{SHA-256}(\text{actionHash} \mathbin{\Vert} \text{evidenceHash} \mathbin{\Vert} \text{preStateHash} \mathbin{\Vert} \text{postStateHash})$$
