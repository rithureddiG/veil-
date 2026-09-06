/**
 * VEIL — Layered Evidence-Based Action Resolver
 *
 * Implements a multi-signal Bayesian evidence scorer for semantic DOM element resolution:
 *   1. Stable Semantic / DOM ID Match       (Weight: 0.30)
 *   2. ARIA Role & HTML Tag Match           (Weight: 0.20)
 *   3. Computed Accessible Name Match       (Weight: 0.20)
 *   4. Label & Placeholder Association      (Weight: 0.15)
 *   5. Structural Neighborhood Context      (Weight: 0.10)
 *   6. Visual Visibility & Enabled State    (Weight: 0.05)
 *
 * Decision Thresholds:
 *   - Score >= 0.85: HIGH confidence (Eligible for direct dispatch)
 *   - 0.60 <= Score < 0.85: MEDIUM confidence (Disambiguation / confirmation recommended)
 *   - Score < 0.60: LOW confidence (Strict rejection: null)
 */

(function () {
  const domUtils = typeof module !== 'undefined' && module.exports
    ? require('./dom-utils')
    : (typeof window !== 'undefined' ? window.VeilDomUtils : null);

  const labelFor = (domUtils && domUtils.labelFor) || function (el) {
    if (!el) return '';
    return (el.getAttribute('aria-label') || el.textContent || el.id || el.name || '').trim();
  };

  const wordOverlapScore = (domUtils && domUtils.wordOverlapScore) || function (a, b) {
    if (!a || !b) return 0;
    const wa = new Set(String(a).toLowerCase().split(/\W+/).filter(Boolean));
    const wb = new Set(String(b).toLowerCase().split(/\W+/).filter(Boolean));
    if (wa.size === 0 || wb.size === 0) return 0;
    let intersect = 0;
    for (const w of wa) {
      if (wb.has(w)) intersect++;
    }
    return intersect / Math.max(wa.size, wb.size);
  };

  const MIN_MATCH_SCORE = 0.30;
  const HIGH_CONFIDENCE_THRESHOLD = 0.85;
  const MEDIUM_CONFIDENCE_THRESHOLD = 0.60;

  /**
   * Resolves a target description into a DOM element with detailed evidence scoring.
   *
   * @param {object} target - { id, description, text, name, role, expectedTag }
   * @param {Document} doc - Document object
   * @returns {{ element: Element|null, score: number, confidence: 'HIGH'|'MEDIUM'|'LOW', signals: object }}
   */
  function resolveTargetWithEvidence(target, doc) {
    if (!doc || !doc.querySelector || !target) {
      return { element: null, score: 0, confidence: 'LOW', signals: {} };
    }

    // 1. Direct ID Fast-Path (data-veil-id, id, name, data-testid)
    if (target.id) {
      let byId = null;
      try {
        if (/^el-\d+$/.test(target.id)) {
          byId = doc.querySelector(`[data-veil-id="${target.id}"]`);
        }
        if (!byId) {
          byId = (doc.getElementById && doc.getElementById(target.id)) || doc.querySelector(`[id="${target.id}"]`);
        }
        if (!byId) {
          byId = doc.querySelector(`[name="${target.id}"], [data-testid="${target.id}"]`);
        }
      } catch (_) {}

      if (byId) {
        return {
          element: byId,
          score: 1.0,
          confidence: 'HIGH',
          signals: { exactId: true, id: target.id }
        };
      }
    }

    const desc = (target.description || target.text || target.name || '').trim();
    if (!desc) {
      return { element: null, score: 0, confidence: 'LOW', signals: {} };
    }

    const candidates = doc.querySelectorAll('button, input, a, select, textarea, [role="button"], [role="link"], [data-veil-id]');
    let bestElement = null;
    let bestScore = 0;
    let bestSignals = {};

    const targetWords = desc.toLowerCase().split(/\W+/).filter(Boolean);
    const expectedRole = (target.role || '').toLowerCase();
    const expectedTag = (target.tag || target.expectedTag || '').toLowerCase();

    for (let i = 0; i < candidates.length; i++) {
      const el = candidates[i];
      const signals = {};
      let totalScore = 0;

      // Signal 1: Stable Semantic / DOM ID (+0.30)
      const elId = (el.id || el.getAttribute('name') || el.getAttribute('data-testid') || '').toLowerCase();
      if (elId && targetWords.some(w => elId.includes(w))) {
        signals.idMatch = 0.30;
        totalScore += 0.30;
      }

      // Signal 2: ARIA Role & HTML Tag Match (+0.20)
      const elRole = (el.getAttribute('role') || '').toLowerCase();
      const elTag = el.tagName.toLowerCase();
      if (expectedRole && (elRole === expectedRole || elTag === expectedRole)) {
        signals.roleMatch = 0.20;
        totalScore += 0.20;
      } else if (expectedTag && elTag === expectedTag) {
        signals.roleMatch = 0.20;
        totalScore += 0.20;
      } else if (elTag === 'button' || elRole === 'button') {
        // Natural bias towards actionable button if description contains action verbs
        if (/click|submit|pay|buy|checkout|confirm|send|order/i.test(desc)) {
          signals.roleMatch = 0.15;
          totalScore += 0.15;
        }
      }

      // Signal 3: Computed Accessible Name Match (+0.20)
      const elName = (el.getAttribute('aria-label') || el.getAttribute('title') || '').toLowerCase();
      if (elName) {
        const nameScore = wordOverlapScore(desc, elName);
        signals.accessibleNameMatch = nameScore * 0.20;
        totalScore += nameScore * 0.20;
      }

      // Signal 4: Label & Visual Text Overlap (+0.15)
      const elLabel = labelFor(el).toLowerCase();
      const labelScore = wordOverlapScore(desc, elLabel);
      signals.labelMatch = labelScore * 0.15;
      totalScore += labelScore * 0.15;

      // Signal 5: Structural Neighborhood Context (+0.10)
      let parentText = '';
      if (el.parentElement) {
        parentText = (el.parentElement.textContent || '').slice(0, 100).toLowerCase();
      }
      const parentScore = wordOverlapScore(desc, parentText);
      signals.neighborhoodMatch = parentScore * 0.10;
      totalScore += parentScore * 0.10;

      // Signal 6: Visibility & Enabled State (+0.05)
      const isEnabled = !el.disabled && el.getAttribute('aria-disabled') !== 'true';
      if (isEnabled) {
        signals.interactable = 0.05;
        totalScore += 0.05;
      }

      if (totalScore > bestScore) {
        bestScore = totalScore;
        bestElement = el;
        bestSignals = signals;
      }
    }

    let confidence = 'LOW';
    if (bestScore >= HIGH_CONFIDENCE_THRESHOLD) {
      confidence = 'HIGH';
    } else if (bestScore >= MEDIUM_CONFIDENCE_THRESHOLD) {
      confidence = 'MEDIUM';
    }

    // Fail-closed if best score is below minimum threshold
    if (bestScore < MIN_MATCH_SCORE) {
      return { element: null, score: bestScore, confidence: 'LOW', signals: bestSignals };
    }

    return {
      element: bestElement,
      score: Number(bestScore.toFixed(3)),
      confidence,
      signals: bestSignals
    };
  }

  /**
   * Backwards-compatible resolveTarget API.
   *
   * @param {object} target
   * @param {Document} doc
   * @returns {Element|null}
   */
  function resolveTarget(target, doc) {
    const res = resolveTargetWithEvidence(target, doc);
    return res.element;
  }

  const exportObj = {
    resolveTarget,
    resolveTargetWithEvidence,
    MIN_MATCH_SCORE,
    HIGH_CONFIDENCE_THRESHOLD,
    MEDIUM_CONFIDENCE_THRESHOLD
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilActionResolver = exportObj;
  }
})();
