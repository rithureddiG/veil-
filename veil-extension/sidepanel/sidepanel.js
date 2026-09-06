/**
 * VEIL — Privileged Side Panel Controller
 *
 * Runs exclusively in the extension's privileged origin (chrome-extension://).
 * Isolated from the untrusted webpage DOM.
 */

(function () {
  let pendingConfirmationId = null;

  const authPanel = document.getElementById('auth-panel');
  const authAction = document.getElementById('auth-action');
  const authTarget = document.getElementById('auth-target');
  const authOrigin = document.getElementById('auth-origin');
  const btnApprove = document.getElementById('btn-approve');
  const btnDeny = document.getElementById('btn-deny');
  const stateText = document.getElementById('state-text');
  const stateHashText = document.getElementById('state-hash');
  const ledgerList = document.getElementById('ledger-list');
  const ledgerStatus = document.getElementById('ledger-status');

  // Listen for privileged confirmation requests from content scripts / background
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message && message.type === 'VEIL_REQUEST_PRIVILEGED_CONFIRMATION') {
        const payload = message.payload || {};
        pendingConfirmationId = payload.timestamp;

        authAction.textContent = ((payload.action && payload.action.type) || 'ACTION').toUpperCase();
        authTarget.textContent = payload.targetFingerprint || (payload.action && payload.action.target && payload.action.target.description) || 'Target Element';
        authOrigin.textContent = payload.origin || 'Unknown Origin';
        if (payload.stateHash) {
          stateHashText.textContent = payload.stateHash.slice(0, 16) + '...';
        }

        authPanel.style.display = 'block';
        stateText.textContent = 'AWAITING_HUMAN_APPROVAL';

        btnApprove.onclick = () => {
          authPanel.style.display = 'none';
          stateText.textContent = 'EXECUTING';
          sendResponse({ approved: true });
        };

        btnDeny.onclick = () => {
          authPanel.style.display = 'none';
          stateText.textContent = 'ACTION_DENIED';
          sendResponse({ approved: false });
        };

        return true; // Keep response channel open for async click
      }

      if (message && message.type === 'VEIL_STATE_UPDATE') {
        if (message.state) stateText.textContent = message.state;
        if (message.stateHash) stateHashText.textContent = message.stateHash.slice(0, 16) + '...';
      }

      if (message && message.type === 'VEIL_LEDGER_UPDATE') {
        renderLedger(message.events || []);
      }
    });
  }

  function renderLedger(events) {
    if (!ledgerList) return;
    ledgerList.innerHTML = '';
    for (const evt of events.slice(0, 15)) {
      const item = document.createElement('div');
      item.className = 'ledger-item';
      item.innerHTML = `
        <span class="ledger-type">${evt.type || 'EVENT'}</span> · ${evt.stage || 'kernel'}
        <div class="ledger-hash">hash: ${(evt.hash || '').slice(0, 18)}...</div>
      `;
      ledgerList.appendChild(item);
    }
  }

  // Load session storage if available
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
    chrome.storage.session.get(['veilLedger', 'veilStateHash'], (res) => {
      if (res.veilStateHash) stateHashText.textContent = res.veilStateHash.slice(0, 16) + '...';
      if (res.veilLedger && Array.isArray(res.veilLedger)) {
        renderLedger(res.veilLedger);
      }
    });
  }
})();
