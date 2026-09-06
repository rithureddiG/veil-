# VEIL Protected Side-Effect Model Specification

> **Specification Identifier**: `veil.spec.effects/v1`  
> **Axiom**: *There is NO unmediated path to privileged host execution. All side effects pass through dedicated enforcement gates.*

---

## 1. Taxonomy of 14 Protected Primitives

| Primitive | Category | Reversibility | Default Risk | Mandatory Human Auth | Interceptor Gate |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `CLICK` | INTERACTION | REVERSIBLE | SAFE | No | `dom-effect-gate.js` |
| `TYPE` | INTERACTION | REVERSIBLE | SAFE | No | `dom-effect-gate.js` |
| `SUBMIT` | INTERACTION | IRREVERSIBLE | SENSITIVE | Yes (Forms) | `dom-effect-gate.js` |
| `SELECT` | INTERACTION | REVERSIBLE | SAFE | No | `dom-effect-gate.js` |
| `SCROLL` | INTERACTION | REVERSIBLE | SAFE | No | `dom-effect-gate.js` |
| `NAVIGATE` | NAVIGATION_IO | REVERSIBLE | SENSITIVE | No | `navigation-gate.js` |
| `DOWNLOAD` | NAVIGATION_IO | IRREVERSIBLE | HIGH_RISK | Yes | `effect-gate.js` |
| `UPLOAD` | NAVIGATION_IO | IRREVERSIBLE | HIGH_RISK | Yes | `effect-gate.js` |
| `CLIPBOARD_WRITE` | NAVIGATION_IO | REVERSIBLE | SENSITIVE | No | `clipboard-gate.js` |
| `STORAGE_WRITE` | NAVIGATION_IO | REVERSIBLE | SENSITIVE | No | `storage-gate.js` |
| `PURCHASE` | CRITICAL_IRREVERSIBLE | IRREVERSIBLE | HIGH_RISK | Yes | `effect-gate.js` |
| `TRANSFER` | CRITICAL_IRREVERSIBLE | IRREVERSIBLE | HIGH_RISK | Yes | `effect-gate.js` |
| `DELETE` | CRITICAL_IRREVERSIBLE | IRREVERSIBLE | HIGH_RISK | Yes | `effect-gate.js` |
| `SECRET_RELEASE` | EGRESS_SECRET | IRREVERSIBLE | HIGH_RISK | Yes | `secret-release-gate.js` |
