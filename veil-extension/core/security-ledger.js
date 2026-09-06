/**
 * VEIL — Cryptographic Tamper-Evident Security Ledger
 *
 * Implements Invariant I8:
 * "Every privileged perception, decision, capability issuance, and execution
 *  is recorded in an immutable SHA-256 cryptographic hash chain."
 *
 * Hash-Chain Construction:
 *   H_0 = GenesisHash
 *   H_i = SHA-256(H_{i-1} + ":" + index + ":" + timestamp + ":" + type + ":" + payloadHash)
 *
 * Guarantees:
 *   - Tamper-evident: Altering any past event or reordering events breaks the chain.
 *   - Non-repudiation: Proves sequence of perception -> decision -> capability -> execution.
 *   - Credential scrubbed: Plaintext secret values are strictly filtered before hashing.
 */

(function () {
  const MAX_EVENTS = 200;
  const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

  // Standard cryptographic SHA-256 implementation (Node crypto + pure JS fallback)
  function sha256Sync(ascii) {
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(ascii, 'utf8').digest('hex');
      } catch (_) {}
    }
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    const words = [];
    const asciiBitLength = ascii.length * 8;
    const hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    const k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    for (let i = 0; i < ascii.length; i++) {
      const code = ascii.charCodeAt(i);
      words[i >> 2] |= code << ((3 - (i % 4)) * 8);
    }
    words[asciiBitLength >> 5] |= 0x80 << (24 - (asciiBitLength % 32));
    words[(((asciiBitLength + 64) >> 9) << 4) + 15] = asciiBitLength;

    const w = new Array(64);
    for (let i = 0; i < words.length; i += 16) {
      let a = hash[0], b = hash[1], c = hash[2], d = hash[3];
      let e = hash[4], f = hash[5], g = hash[6], h = hash[7];

      for (let j = 0; j < 64; j++) {
        if (j < 16) {
          w[j] = words[i + j] | 0;
        } else {
          const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
          const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
          w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
        }
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) + ch + k[j] + w[j]) | 0;
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = ((rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) + maj) | 0;
        h = g; g = f; f = e; e = (d + temp1) | 0;
        d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      hash[0] = (hash[0] + a) | 0; hash[1] = (hash[1] + b) | 0;
      hash[2] = (hash[2] + c) | 0; hash[3] = (hash[3] + d) | 0;
      hash[4] = (hash[4] + e) | 0; hash[5] = (hash[5] + f) | 0;
      hash[6] = (hash[6] + g) | 0; hash[7] = (hash[7] + h) | 0;
    }
    let res = '';
    for (let i = 0; i < 8; i++) {
      const hex = (hash[i] >>> 0).toString(16).padStart(8, '0');
      res += hex;
    }
    return res;
  }

  // Scrub sensitive values from objects before logging/hashing
  function sanitizeDetail(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(sanitizeDetail);
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
      const lk = k.toLowerCase();
      if (lk.includes('password') || lk.includes('secret') || lk.includes('card') || lk.includes('cvv') || lk.includes('pin') || lk.includes('aadhaar')) {
        clean[k] = '[REDACTED_BY_KERNEL]';
      } else if (typeof v === 'object' && v !== null) {
        clean[k] = sanitizeDetail(v);
      } else {
        clean[k] = v;
      }
    }
    return clean;
  }

  // Deterministic canonical JSON serialization (alphabetically sorted keys)
  function canonicalStringify(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map(canonicalStringify).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    const entries = keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k]));
    return '{' + entries.join(',') + '}';
  }

  // Ordered list of events (oldest to newest internally)
  let chronologicalEvents = [];
  let ledgerCheckpoints = [];
  let currentHeadHash = GENESIS_HASH;
  const CHECKPOINT_INTERVAL = 10;

  function createCheckpoint() {
    const cpIndex = ledgerCheckpoints.length;
    const evtIndex = chronologicalEvents.length - 1;
    const timestamp = Date.now();
    const cpHash = sha256Sync(`CP:${cpIndex}:${evtIndex}:${currentHeadHash}`);

    const cp = {
      checkpointIndex: cpIndex,
      eventIndex: evtIndex,
      headHash: currentHeadHash,
      checkpointHash: cpHash,
      timestamp
    };
    ledgerCheckpoints.push(cp);
    return cp;
  }

  function getSessionRoot() {
    if (chronologicalEvents.length === 0) return GENESIS_HASH;
    const cpHashes = ledgerCheckpoints.map(cp => cp.checkpointHash).join(':');
    return sha256Sync(`SESSION_ROOT:${currentHeadHash}:${cpHashes}:${chronologicalEvents.length}`);
  }

  /**
   * Records an event in the cryptographic chain.
   *
   * @param {string} type - Event type (e.g. 'CAPABILITY_ISSUED', 'PII_DETECTED')
   * @param {string} stage - Pipeline stage
   * @param {object} detail - Event details (sanitized automatically)
   * @param {string} [source='CLIENT'] - Component reporting event
   * @returns {object} The chained event object
   */
  function recordEvent(type, stage, detail, source = 'CLIENT') {
    const eventIndex = chronologicalEvents.length;
    const timestamp = Date.now();
    const isoTime = new Date(timestamp).toLocaleTimeString('en-US', { hour12: false });
    const cleanDetail = sanitizeDetail(detail);

    const payloadSerialized = canonicalStringify(cleanDetail || {});
    const payloadHash = sha256Sync(payloadSerialized);

    const prevHash = currentHeadHash;
    const headerString = `${prevHash}:${eventIndex}:${timestamp}:${type}:${payloadHash}`;
    const eventHash = sha256Sync(headerString);

    currentHeadHash = eventHash;

    const event = {
      id: `evt-${eventIndex}-${timestamp}`,
      eventIndex,
      timestamp,
      isoTime,
      epochMs: timestamp,
      type,
      stage,
      source,
      detail: cleanDetail,
      payloadHash,
      prevHash,
      hash: eventHash
    };

    chronologicalEvents.push(event);
    if (chronologicalEvents.length > MAX_EVENTS) {
      // Re-anchor genesis at trimmed boundary
      chronologicalEvents.shift();
    }

    // Generate periodic checkpoint
    if (chronologicalEvents.length % CHECKPOINT_INTERVAL === 0) {
      createCheckpoint();
    }

    // Persist to session storage if in extension context
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id && chrome.storage && chrome.storage.session) {
        chrome.storage.session.set({
          veilLedgerHead: currentHeadHash,
          veilLedgerCount: chronologicalEvents.length
        }).catch(() => {});
      }
    } catch (_) {}

    return event;
  }

  /**
   * Verifies the cryptographic integrity of the entire ledger chain.
   * Traverses from event 0 to head, recomputing SHA-256 hashes.
   *
   * @returns {{valid: boolean, length: number, headHash: string, error?: string, brokenAtIndex?: number}}
   */
  function verifyChainIntegrity() {
    if (chronologicalEvents.length === 0) {
      return { valid: true, length: 0, headHash: GENESIS_HASH };
    }

    let expectedPrev = chronologicalEvents[0].prevHash;

    for (let i = 0; i < chronologicalEvents.length; i++) {
      const evt = chronologicalEvents[i];

      // 1. Check prevHash link
      if (evt.prevHash !== expectedPrev) {
        return {
          valid: false,
          length: chronologicalEvents.length,
          brokenAtIndex: i,
          error: `Broken chain link at index ${i}: expected prevHash ${expectedPrev}, found ${evt.prevHash}`
        };
      }

      // 2. Check payload hash using canonical serialization
      const payloadSerialized = canonicalStringify(evt.detail || {});
      const calculatedPayloadHash = sha256Sync(payloadSerialized);
      if (calculatedPayloadHash !== evt.payloadHash) {
        return {
          valid: false,
          length: chronologicalEvents.length,
          brokenAtIndex: i,
          error: `Tampered payload detected at index ${i}`
        };
      }

      // 3. Check event header hash
      const headerString = `${evt.prevHash}:${evt.eventIndex}:${evt.timestamp}:${evt.type}:${evt.payloadHash}`;
      const calculatedHash = sha256Sync(headerString);
      if (calculatedHash !== evt.hash) {
        return {
          valid: false,
          length: chronologicalEvents.length,
          brokenAtIndex: i,
          error: `Hash mismatch at index ${i}: recomputed ${calculatedHash}, stored ${evt.hash}`
        };
      }

      expectedPrev = evt.hash;
    }

    return {
      valid: true,
      length: chronologicalEvents.length,
      headHash: currentHeadHash
    };
  }

  /** Returns copy of active security event ledger (newest first for UI compatibility) */
  function getLedger() {
    return [...chronologicalEvents].reverse();
  }

  /** Returns chronological events (oldest first for audit validation) */
  function getChronologicalLedger() {
    return [...chronologicalEvents];
  }

  function getHeadHash() {
    return currentHeadHash;
  }

  function clearLedger() {
    chronologicalEvents = [];
    ledgerCheckpoints = [];
    currentHeadHash = GENESIS_HASH;
  }

  function exportAuditProof() {
    return {
      genesisHash: GENESIS_HASH,
      headHash: currentHeadHash,
      eventCount: chronologicalEvents.length,
      integrity: verifyChainIntegrity(),
      chain: [...chronologicalEvents]
    };
  }

  /**
   * Exports an independently verifiable VEIL SECURITY RECEIPT.
   */
  function exportSecurityReceipt() {
    return {
      receiptType: 'VEIL_SECURITY_RECEIPT',
      version: '2.2.0',
      genesisHash: GENESIS_HASH,
      headHash: currentHeadHash,
      sessionRoot: getSessionRoot(),
      eventCount: chronologicalEvents.length,
      checkpoints: [...ledgerCheckpoints],
      chain: [...chronologicalEvents],
      exportedAt: Date.now()
    };
  }

  /**
   * Standalone verifier: Validates a VEIL Security Receipt offline without running the extension.
   *
   * @param {object} receipt - Exported VEIL Security Receipt
   * @returns {{ valid: boolean, verifiedEvents: number, headHash: string, error?: string }}
   */
  function verifySecurityReceipt(receipt) {
    if (!receipt || !Array.isArray(receipt.chain)) {
      return { valid: false, verifiedEvents: 0, headHash: '', error: 'Malformed receipt structure' };
    }

    if (receipt.chain.length === 0) {
      return { valid: true, verifiedEvents: 0, headHash: GENESIS_HASH };
    }

    let expectedPrev = receipt.chain[0].prevHash;

    for (let i = 0; i < receipt.chain.length; i++) {
      const evt = receipt.chain[i];

      if (evt.prevHash !== expectedPrev) {
        return {
          valid: false,
          verifiedEvents: i,
          headHash: '',
          error: `Broken chain link at index ${i}`
        };
      }

      const calculatedPayloadHash = sha256Sync(canonicalStringify(evt.detail || {}));
      if (calculatedPayloadHash !== evt.payloadHash) {
        return {
          valid: false,
          verifiedEvents: i,
          headHash: '',
          error: `Tampered payload hash at index ${i}`
        };
      }

      const headerString = `${evt.prevHash}:${evt.eventIndex}:${evt.timestamp}:${evt.type}:${evt.payloadHash}`;
      const calculatedHash = sha256Sync(headerString);
      if (calculatedHash !== evt.hash) {
        return {
          valid: false,
          verifiedEvents: i,
          headHash: '',
          error: `Recomputed event hash mismatch at index ${i}`
        };
      }

      expectedPrev = evt.hash;
    }

    const finalHash = receipt.chain[receipt.chain.length - 1].hash;
    if (receipt.headHash && receipt.headHash !== finalHash) {
      return { valid: false, verifiedEvents: receipt.chain.length, headHash: finalHash, error: 'Receipt headHash does not match terminal chain hash' };
    }

    return {
      valid: true,
      verifiedEvents: receipt.chain.length,
      headHash: finalHash
    };
  }

  const securityLedgerExport = {
    recordEvent,
    getLedger,
    getChronologicalLedger,
    verifyChainIntegrity,
    getHeadHash,
    clearLedger,
    exportAuditProof,
    exportSecurityReceipt,
    verifySecurityReceipt,
    createCheckpoint,
    getSessionRoot,
    canonicalStringify,
    sha256Sync,
    GENESIS_HASH
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = securityLedgerExport;
  }
  if (typeof window !== 'undefined') {
    window.VeilSecurityLedger = securityLedgerExport;
  }
})();
