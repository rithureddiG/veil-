# VEIL Security Receipt Specification (`veil.receipt/v1`)

> **Protocol Version**: `veil.receipt/v1`  
> **Purpose**: Enables independent, offline cryptographic verification of agent transactions and ledger history with zero dependency on the VEIL extension runtime.

---

## 1. Hash-Chain Construction

The ledger forms a strictly sequential, tamper-evident SHA-256 hash chain:

$$H_0 = 0^{64} \quad (\text{Genesis Hash})$$

$$H_i = \text{SHA-256}(H_{i-1} : i : \text{timestamp}_i : \text{type}_i : \text{SHA-256}(\text{CanonicalJSON}(\text{detail}_i)))$$

### Checkpointing & Session Root:
A cryptographic checkpoint is committed every $N = 10$ events:
$$\text{CP}_k = \text{SHA-256}(\text{"CP"} : k : \text{eventIndex} : H_{\text{head}})$$
$$\text{SessionRoot} = \text{SHA-256}(\text{"SESSION\_ROOT"} : H_{\text{head}} : \text{CP}_0 : \dots : \text{CP}_m : \text{totalEvents})$$

---

## 2. Receipt JSON Schema

```json
{
  "receiptType": "VEIL_SECURITY_RECEIPT",
  "version": "2.4.0",
  "genesisHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "headHash": "b5a7c9...64hex",
  "sessionRoot": "f1d2e3...64hex",
  "eventCount": 42,
  "checkpoints": [ ... ],
  "chain": [
    {
      "id": "evt-0-1725619200",
      "eventIndex": 0,
      "timestamp": 1725619200000,
      "type": "TRANSACTION_BEGUN",
      "stage": "transaction_engine",
      "detail": { "intent": "checkout", "origin": "https://shop.example" },
      "payloadHash": "d8e4...64hex",
      "prevHash": "0000000000000000000000000000000000000000000000000000000000000000",
      "hash": "c4b1...64hex"
    }
  ],
  "exportedAt": 1725619205000
}
```
