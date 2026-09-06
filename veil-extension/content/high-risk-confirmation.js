/**
 * VEIL — Privileged Out-of-Band Action Confirmation Gate
 *
 * Implements Invariant I2:
 * "Security decisions and human confirmation dialogs must NEVER render inside the untrusted page DOM.
 *  All authorization takes place via privileged extension UI (Side Panel, Popup, or native extension dialogs)."
 *
 * Architecture:
 *   - The content script dispatches a request to the extension runtime.
 *   - The user reviews the action outside the webpage context (preventing clickjacking, CSS spoofing, and DOM tampering).
 *   - Upon approval, the Kernel emits a signed single-use Action Capability.
 *   - If no privileged channel is available, fails closed safely.
 */

(function () {
  const CONFIRMATION_TIMEOUT_MS = 30000;
  let customConfirmationHandler = null;

  /**
   * Allows test runners and headless suites to hook an authorization callback.
   */
  function setPrivilegedConfirmationHandler(handlerFn) {
    customConfirmationHandler = handlerFn;
  }

  /**
   * Requests explicit human authorization for a HIGH_RISK action through a privileged channel.
   *
   * @param {{
   *   action: object,
   *   targetElement?: Element|null,
   *   targetFingerprint?: string,
   *   riskInfo?: object,
   *   origin?: string,
   *   stateHash?: string
   * }} details
   * @returns {Promise<boolean>}
   */
  async function requestConfirmation(details = {}) {
    // 1. Check for custom/test authorization hook (e.g. during headless CI)
    if (typeof customConfirmationHandler === 'function') {
      try {
        const approved = await customConfirmationHandler(details);
        return Boolean(approved);
      } catch (_) {
        return false;
      }
    }

    // 2. Dispatch to Privileged Chrome Extension Runtime (Side Panel / Background Service Worker)
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      return new Promise((resolve) => {
        const timeoutTimer = setTimeout(() => {
          resolve(false); // Fail closed on timeout
        }, CONFIRMATION_TIMEOUT_MS);

        try {
          chrome.runtime.sendMessage({
            type: 'VEIL_REQUEST_PRIVILEGED_CONFIRMATION',
            payload: {
              action: details.action,
              targetFingerprint: details.targetFingerprint || (details.targetElement && details.targetElement.id) || 'unknown',
              origin: details.origin || (typeof location !== 'undefined' ? location.origin : 'localhost'),
              stateHash: details.stateHash || 'unanchored',
              riskInfo: details.riskInfo || { level: 'HIGH_RISK' },
              timestamp: Date.now()
            }
          }, (response) => {
            clearTimeout(timeoutTimer);
            if (chrome.runtime.lastError) {
              // Extension disconnected or side panel closed -> fail closed safely
              resolve(false);
            } else {
              resolve(Boolean(response && response.approved));
            }
          });
        } catch (_) {
          clearTimeout(timeoutTimer);
          resolve(false);
        }
      });
    }

    // 3. Strict Fail-Closed Security Boundary:
    // Invariant I2: NEVER render in-page dialogs or use window.confirm() fallbacks.
    // Untrusted page DOM contexts cannot provide trustworthy authorization.
    // If no privileged extension runtime or out-of-band handler is available -> Fail Closed.
    return Promise.resolve(false);
  }

  const exportObj = {
    requestConfirmation,
    setPrivilegedConfirmationHandler,
    CONFIRMATION_TIMEOUT_MS
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (typeof window !== 'undefined') {
    window.VeilHighRiskConfirmation = exportObj;
  }
})();
