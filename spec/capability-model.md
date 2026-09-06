# VEIL Capability Model Specification (`veil.cap/v1`)

> **Protocol Version**: `veil.cap/v1`  
> **Schema Definition**: JSON-based cryptographic capability token with HMAC-SHA256 non-repudiation.

---

## 1. Token Structure

```json
{
  "schema": "veil.cap/v1",
  "capabilityId": "cap_1725619200_a9f8b1c",
  "actionType": "PURCHASE",
  "targetFingerprint": "button#buy-now[data-action='buy']",
  "origin": "https://shop.example",
  "stateHash": "a1b2c3d4e5f6...64hex",
  "purpose": "user_authorized_checkout",
  "secretId": null,
  "attenuation": "SCOPE_ELEMENT",
  "maxUses": 1,
  "usesRemaining": 1,
  "issuedAt": 1725619200000,
  "expiresAt": 1725619205000,
  "ttlMs": 5000,
  "nonce": "k9z2m8q4",
  "humanApproved": true,
  "signature": "e7c4f1...64hex"
}
```

---

## 2. Canonical Signature Construction

The HMAC-SHA256 signature is computed strictly over the canonical delimiter-separated payload:

$$\text{Payload} = \text{capabilityId} \parallel \text{actionType} \parallel \text{targetFingerprint} \parallel \text{origin} \parallel \text{stateHash} \parallel \text{attenuation} \parallel \text{maxUses} \parallel \text{expiresAt} \parallel \text{nonce} \parallel \text{KERNEL\_SECRET}$$

$$\text{Signature} = \text{SHA-256}(\text{Payload})$$

---

## 3. Attenuation Hierarchy

Capabilities can be attenuated into strictly narrower scopes:
1. `SCOPE_PAGE`: Action permitted anywhere on the verified origin page.
2. `SCOPE_FORM`: Action permitted only within the target `<form>` container.
3. `SCOPE_ELEMENT`: Action permitted strictly on the element matching `targetFingerprint`.

Attenuated tokens cannot exceed parent TTL or permit actions outside parent scopes.
