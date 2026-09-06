# VEIL Protocol Specification: Part 06 — Capability Model & Cryptographic Ephemerality

**Specification Identifier**: `VEIL-SPEC-06`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Capability Token Data Structure

A valid Capability Token $\mathcal{C}$ is represented by the canonical schema:

```json
{
  "capabilityId": "cap_1725619200_a8f9c2",
  "schema": "veil.capability/v2",
  "actionType": "EFFECT_INTERACT_CLICK",
  "targetSelector": "#checkout-submit-btn",
  "origin": "https://trusted-merchant.com",
  "preStateHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "nonce": "nonce_1725619200_918234",
  "createdAt": 1725619200000,
  "expiresAt": 1725619210000,
  "signature": "c9284fa981e7d483b4..."
}
```

---

## 2. Invariants of Cryptographic Capabilities

### 2.1. Signature Authenticity
The signature is computed using HMAC-SHA256 over the canonical JSON serialization of the token body excluding `signature`:
$$\text{sig} = \text{HMAC-SHA256}(\text{Canonicalize}(\mathcal{C}_{\text{body}}), K_{\text{VEIL}})$$

### 2.2. Strict Ephemerality
The capability token is valid for a maximum duration $T_{\text{valid}} \le 15.0 \text{ seconds}$:
$$\text{now}() \le \mathcal{C}.\text{expiresAt}$$

### 2.3. Nonce Singularity
Every capability carries a globally unique monotonic nonce:
$$\mathcal{C}.\text{nonce} \notin \text{ConsumedNonces}$$
Re-submitting an identical capability token results in instant fail-closed rejection.
