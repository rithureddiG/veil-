# VEIL Policy Language Specification (`veil.policy/v1`)

> **Protocol Version**: `veil.policy/v1`  
> **Schema Definition**: Declarative policy definition compiled into canonical Policy ASTs.

---

## 1. Declarative Syntax

```yaml
policy: ecommerce_checkout_policy

actor:
  type: autonomous_agent

action:
  allow:
    - CLICK
    - SELECT
    - TYPE
    - SCROLL
  confirm:
    - PURCHASE
    - TRANSFER
  deny:
    - DELETE
    - CHANGE_SETTING

data:
  deny:
    - CREDENTIAL
    - FINANCIAL_SECRET

network:
  allow:
    - "shop.example"
    - "api.shop.example"

secrets:
  allow:
    - credential://shop.example/payment

constraints:
  max_transaction: 50000
  capability_ttl: 3000
```

---

## 2. Canonical AST Representation

The policy compiles into a deterministic AST with alphabetized keys and integer constraints:

```json
{
  "schema": "veil.policy.ast/v1",
  "name": "ecommerce_checkout_policy",
  "actor": { "type": "autonomous_agent" },
  "rules": {
    "allowedActions": ["CLICK", "SCROLL", "SELECT", "TYPE"],
    "confirmActions": ["PURCHASE", "TRANSFER"],
    "deniedActions": ["CHANGE_SETTING", "DELETE"],
    "deniedDataTaints": ["CREDENTIAL", "FINANCIAL_SECRET"],
    "allowedOrigins": ["api.shop.example", "shop.example"],
    "allowedSecrets": ["credential://shop.example/payment"],
    "constraints": {
      "maxTransaction": 50000,
      "capabilityTtl": 3000
    }
  }
}
```
