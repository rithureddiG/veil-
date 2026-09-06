# VEIL Intermediate Representation Specification (`veil.ir/v2`)

> **Protocol Version**: `veil.ir/v2`  
> **Axiom**: *The AI reasoning model never observes the raw browser DOM. It observes strictly VEIL-IR v2: a purpose-filtered, formally constrained intermediate representation cryptographically anchored to stateHash.*

---

## 1. Schema Structure

```json
{
  "schema": "veil.ir/v2",
  "version": "2.4.0",
  "purpose": "product_search",
  "origin": "https://shop.example",
  "stateHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp": 1725619200000,
  "isoTime": "2026-09-06T06:40:00.000Z",
  "totalElementsPerceived": 24,
  "accessibleElements": 22,
  "protectedElements": 2,
  "elements": [
    {
      "id": "el-1",
      "tag": "div",
      "role": "heading",
      "name": "GeForce RTX 4090 GPU",
      "fingerprint": "div:heading:el-1",
      "state": { "enabled": true, "visible": true, "filled": false },
      "sensitivity": "PUBLIC",
      "accessibleToModel": true
    },
    {
      "id": "el-14",
      "tag": "input",
      "role": "password",
      "name": "[PROTECTED_PASSWORD_FIELD]",
      "fingerprint": "input:password:el-14",
      "state": { "enabled": true, "visible": true, "filled": false },
      "sensitivity": "RESTRICTED_SECRET",
      "valueRef": "credential://shop.example/password/el-14",
      "accessibleToModel": false
    }
  ]
}
```

---

## 2. Invariant Rules
1. **Zero Raw Secret Values**: No `.value` attribute is permitted inside `elements`.
2. **Deterministic Fingerprints**: Elements must carry structural fingerprints bound to role, tag, and DOM tree coordinates.
3. **Purpose-Bound Masking**: Attributes unaligned with declared purpose are transformed into opaque `valueRef` handles.
