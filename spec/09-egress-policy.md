# VEIL Protocol Specification: Part 09 — Egress Policy & Network Confinement

**Specification Identifier**: `VEIL-SPEC-09`  
**Status**: Authoritative Protocol Standard  
**Document Version**: 2.5.0  

---

## 1. Network Boundary Isolation

The Network Effect Gate mediates all outbound network requests (`fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, image/CSS load pings).

---

## 2. Egress Invariant Rules

### 2.1. Same-Origin Default
Outbound requests must match the origin of the active validated session:
$$\text{DestinationOrigin}(r) == \text{SessionOrigin}(S) \implies \text{ALLOW\_EGRESS}$$

### 2.2. Cross-Origin Taint Confinement
If any payload parameter carries $\tau \sqsupseteq \text{TAINT\_UNTRUSTED\_DOM}$, cross-origin egress is strictly blocked:
$$\text{DestinationOrigin}(r) \neq \text{SessionOrigin}(S) \land \tau(\text{body}(r)) \neq \text{CLEAN} \implies \text{BLOCK}$$

### 2.3. Covert Channel Neutralization
1. **Image Ping Blocking**: URLs matching known tracking pixel patterns or containing base64-encoded query parameters are intercepted and stripped.
2. **DNS Tunneling Defense**: Maximum domain name length and subdomain entropy checks prevent data exfiltration via DNS lookups.
