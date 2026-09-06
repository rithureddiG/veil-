# VEIL Security Boundary Matrix (v2.2)

> **Core Invariant**: *There is NO privileged browser execution path that does not pass through the VEIL Kernel Enforcement Boundary.*  
> **Authority Separation**: *Untrusted agents, hostile scripts, and remote reasoning models have ZERO capability to dispatch native side effects directly.*

---

## 1. Protected Side-Effect Execution Matrix

The following matrix documents all 14 protected browser primitives recognized by the VEIL Security Kernel, their intercepted host APIs, required capabilities, policy rules, and verification artifacts.

| # | Protected Effect | Browser Primitive API | VEIL Interceptor Gate | Capability Required | Policy Decision Point (PDP) Rule | Audit Ledger Event | Verification Suite |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `CLICK` | `HTMLElement.click`, `dispatchEvent(MouseEvent)`, `PointerEvent` | `core/kernel/enforcement/dom-effect-gate.js` | `CAP_CLICK` (Scoped to Element Fingerprint) | Allow if safe element & non-mutated state; Deny coordinate deception | `DOM_CLICK_DISPATCHED` | Suite 8 & Suite 10 |
| **2** | `TYPE` | `element.value`, `InputEvent`, `change` | `core/kernel/enforcement/dom-effect-gate.js` | `CAP_TYPE` (Required for sensitive targets) | Plaintext input allowed only for public fields; Sensitive fields mandate Secret Release | `DOM_TYPE_DISPATCHED` | Suite 6 & Suite 10 |
| **3** | `SUBMIT` | `HTMLFormElement.submit`, `submit` event | `core/kernel/enforcement/dom-effect-gate.js` | `CAP_SUBMIT` (Irreversible effect) | Requires form state hash validation; blocks unanchored submissions | `DOM_SUBMIT_DISPATCHED` | Suite 8 & Suite 10 |
| **4** | `SELECT` | `HTMLSelectElement.selectedIndex`, `change` | `core/kernel/enforcement/dom-effect-gate.js` | `CAP_SELECT` | Allowed if target option exists in verified DOM | `DOM_SELECT_DISPATCHED` | Suite 8 |
| **5** | `SCROLL` | `element.scrollIntoView`, `window.scrollTo` | `core/kernel/enforcement/dom-effect-gate.js` | None (Safe read-only viewport action) | Always permitted unless targeting out-of-bounds hidden geometry | `VIEWPORT_SCROLLED` | Suite 1 |
| **6** | `NAVIGATE` | `window.location.href`, `window.open`, `location.assign` | `core/kernel/enforcement/navigation-gate.js` | `CAP_NAVIGATE` (Mandatory for Cross-Origin) | Blocks `javascript:`, `data:`, and unlisted cross-origin redirection | `NAVIGATION_EVALUATED` | Suite 8 & Suite 10 |
| **7** | `DOWNLOAD` | `<a download>`, `URL.createObjectURL`, Blob stream | `core/kernel/enforcement/effect-gate.js` | `CAP_DOWNLOAD` (High-Risk Irreversible) | Mandates Out-of-Band Human Authorization (`OOB_AUTH`) | `DOWNLOAD_INTERCEPTED` | Suite 9 & Suite 10 |
| **8** | `UPLOAD` | `<input type="file">`, `FormData.append(File)` | `core/kernel/enforcement/effect-gate.js` | `CAP_UPLOAD` (High-Risk Irreversible) | Mandates Out-of-Band Human Authorization (`OOB_AUTH`) | `UPLOAD_INTERCEPTED` | Suite 9 & Suite 10 |
| **9** | `CLIPBOARD_WRITE` | `navigator.clipboard.writeText`, `copy` event | `core/kernel/enforcement/clipboard-gate.js` | `CAP_CLIPBOARD` | Blocks exfiltration of tainted data (`FINANCIAL_SECRET`, `CREDENTIAL`) | `CLIPBOARD_WRITE_PERMITTED` | Suite 10 |
| **10** | `STORAGE_WRITE` | `localStorage.setItem`, `sessionStorage.setItem`, `document.cookie` | `core/kernel/enforcement/storage-gate.js` | `CAP_STORAGE` | Blocks storing plaintext credentials or high-taint tokens in client storage | `STORAGE_WRITE_PERMITTED` | Suite 10 |
| **11** | `PURCHASE` | Checkout triggers, payment gateway forms, card charges | `core/kernel/enforcement/effect-gate.js` | `CAP_PURCHASE` (High-Risk Irreversible) | **Strict Out-of-Band Human Approval Required**; price TOCTOU check | `PURCHASE_AUTHORIZED` | Suite 5 & Suite 8 |
| **12** | `TRANSFER` | Banking fund transfer, wire submission, wallet debit | `core/kernel/enforcement/effect-gate.js` | `CAP_TRANSFER` (High-Risk Irreversible) | **Strict Out-of-Band Human Approval Required**; recipient verification | `TRANSFER_AUTHORIZED` | Suite 8 & Suite 9 |
| **13** | `DELETE` | Account deletion, cloud resource destruction, database wipe | `core/kernel/enforcement/effect-gate.js` | `CAP_DELETE` (High-Risk Irreversible) | **Strict Out-of-Band Human Approval Required** | `RESOURCE_DELETE_AUTHORIZED` | Suite 8 & Suite 9 |
| **14** | `SECRET_RELEASE` | Decrypted credential injection into native password/card field | `core/kernel/enforcement/secret-release-gate.js` | `CAP_SECRET_RELEASE` (Single-Use Token) | Domain match + field name match + human unlock; Secret NEVER seen by model | `SECRET_RELEASED_TO_DOM` | Suite 6 & Suite 10 |

---

## 2. Information Flow Control (IFC) Lattice Mapping

The kernel enforces strict non-interference across data classifications:

```
[Level 0] PUBLIC
    │
[Level 1] INTERNAL
    │
[Level 2] PERSONAL (Email, Phone, Name)
    │
[Level 3] SENSITIVE (Government ID, Healthcare Diagnosis)
    │
[Level 4] FINANCIAL_SECRET (Credit Card, CVV, Account Number, Balance)
    │
[Level 5] CREDENTIAL (Password, API Key, PIN, Session Token)
```

### Flow Safety Theorem:
$$\forall \text{data } d \in D, \forall \text{sink } s \in S: \quad \text{Flow}(d, s) \iff \text{LatticeLevel}(d) \le \text{MaxAllowedLevel}(s) \lor \text{AuthorizedCapability}(d, s)$$

- **Cloud Model Sink**: $\text{MaxAllowedLevel} = \text{PUBLIC} (0)$. Personal, sensitive, financial, and credential data are **strictly forbidden**.
- **Remote Network Egress**: $\text{MaxAllowedLevel} = \text{INTERNAL} (1)$. High-taint data requires cryptographic capability and domain whitelisting.
- **Audit Ledger**: Plaintext secrets are scrubbed before computing HMAC and SHA-256 event hashes.
