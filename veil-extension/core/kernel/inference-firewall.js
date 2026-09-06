/**
 * VEIL — Inference Firewall & Bounded Information Gain (v2.3)
 *
 * Implements Invariant I5 & Theorem T6:
 * "Privacy is NOT merely regex redaction. Privacy is BOUNDED INFORMATION GAIN.
 *  The Inference Firewall prevents remote models from reconstructing identity or secrets
 *  via correlational signals (partial account numbers, exact timestamps, balance deltas)."
 *
 * Pipeline:
 *   RAW STATE ➔ VEIL-IFC ➔ CONTEXT FIREWALL ➔ INFERENCE RISK ➔ COARSENING ➔ MODEL
 */

(function () {
  const securityLedger = typeof require !== 'undefined'
    ? require('../security-ledger.js')
    : (typeof window !== 'undefined' ? window.VeilSecurityLedger : null);

  const MAX_PERMITTED_INFERENCE_SCORE = 0.65;

  /**
   * Quasi-identifier weights determining information entropy reduction.
   */
  const QUASI_IDENTIFIER_WEIGHTS = {
    partial_account_number: 0.35, // e.g. ****4821
    exact_currency_delta: 0.30,   // e.g. ₹12,450.00
    exact_subsecond_timing: 0.25, // e.g. 14:02:44.291
    unique_merchant_id: 0.20,     // e.g. MID-98412
    email_domain_org: 0.20,       // e.g. @isro.gov.in
    geo_coordinate_micro: 0.40    // exact lat/long
  };

  class InferenceFirewall {
    constructor(maxRisk = MAX_PERMITTED_INFERENCE_SCORE) {
      this.maxRisk = maxRisk;
    }

    /**
     * Evaluates the cumulative inference risk across perceived textual or structured context.
     *
     * @param {string|object} context - Text or object to analyze
     * @returns {{ riskScore: number, quasiIdentifiersFound: Array<string>, shouldCoarsen: boolean }}
     */
    evaluateInferenceRisk(context) {
      const text = typeof context === 'string' ? context : JSON.stringify(context || {});
      const detected = [];
      let totalRisk = 0;

      // 1. Detect partial account / card numbers (e.g. ****1234 or ending in 4821)
      if (/\b(?:\*{4}|\d{4})[- ]?\d{4}\b|ending in \d{4}|\*{4}\d{4}/i.test(text)) {
        detected.push('partial_account_number');
        totalRisk += QUASI_IDENTIFIER_WEIGHTS.partial_account_number;
      }

      // 2. Detect high-precision monetary amounts
      if (/(?:₹|\$|€|£)\s?\d{1,3}(?:,\d{3})*\.\d{2}\b/i.test(text)) {
        detected.push('exact_currency_delta');
        totalRisk += QUASI_IDENTIFIER_WEIGHTS.exact_currency_delta;
      }

      // 3. Detect high-precision timestamps (down to seconds or milliseconds)
      if (/\d{2}:\d{2}:\d{2}(?:\.\d{3})?/i.test(text)) {
        detected.push('exact_subsecond_timing');
        totalRisk += QUASI_IDENTIFIER_WEIGHTS.exact_subsecond_timing;
      }

      // 4. Detect institutional email domains
      if (/@(?:[a-z0-9-]+\.)+(?:gov|mil|edu|corp|isro)\b/i.test(text)) {
        detected.push('email_domain_org');
        totalRisk += QUASI_IDENTIFIER_WEIGHTS.email_domain_org;
      }

      // Bound score between 0.0 and 1.0
      const riskScore = Math.min(1.0, parseFloat(totalRisk.toFixed(3)));
      const shouldCoarsen = riskScore > this.maxRisk;

      return {
        riskScore,
        quasiIdentifiersFound: detected,
        shouldCoarsen
      };
    }

    /**
     * Applies differential coarsening to bound information gain before context transmission.
     *
     * @param {string} text - Raw perceived text
     * @returns {{ sanitizedText: string, coarsened: boolean, originalRisk: number, finalRisk: number }}
     */
    coarsenContext(text = '') {
      const evalRes = this.evaluateInferenceRisk(text);
      if (!evalRes.shouldCoarsen) {
        return {
          sanitizedText: text,
          coarsened: false,
          originalRisk: evalRes.riskScore,
          finalRisk: evalRes.riskScore
        };
      }

      let coarsenedText = text;

      // 1. Coarsen partial account numbers
      coarsenedText = coarsenedText.replace(/\b(?:\*{4}|\d{4})[- ]?\d{4}\b|ending in \d{4}|\*{4}\d{4}/gi, '[ACCOUNT_MASKED]');

      // 2. Coarsen high-precision monetary amounts to rounded order-of-magnitude ranges
      coarsenedText = coarsenedText.replace(/(?:₹|\$|€|£)\s?(\d+)(?:,\d{3})*(?:\.\d{2})?/g, (match, base) => {
        const num = parseInt(base, 10);
        if (num > 1000) {
          const lower = Math.floor(num / 1000) * 1000;
          return `₹${lower} - ₹${lower + 1000}`;
        }
        return '[AMOUNT_COARSENED]';
      });

      // 3. Coarsen high-precision timing to hour
      coarsenedText = coarsenedText.replace(/\d{2}:\d{2}:\d{2}(?:\.\d{3})?/g, '[TIME_COARSENED]');

      const postEval = this.evaluateInferenceRisk(coarsenedText);

      if (securityLedger && securityLedger.recordEvent) {
        securityLedger.recordEvent('INFERENCE_FIREWALL_COARSENED', 'inference_firewall', {
          originalRisk: evalRes.riskScore,
          finalRisk: postEval.riskScore,
          quasiIdentifiersFound: evalRes.quasiIdentifiersFound
        });
      }

      return {
        sanitizedText: coarsenedText,
        coarsened: true,
        originalRisk: evalRes.riskScore,
        finalRisk: postEval.riskScore
      };
    }
  }

  const defaultInferenceFirewall = new InferenceFirewall();

  const exportObj = {
    InferenceFirewall,
    defaultInferenceFirewall,
    evaluateInferenceRisk: (ctx) => defaultInferenceFirewall.evaluateInferenceRisk(ctx),
    coarsenContext: (txt) => defaultInferenceFirewall.coarsenContext(txt)
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilInferenceFirewall = exportObj;
  }
})();
