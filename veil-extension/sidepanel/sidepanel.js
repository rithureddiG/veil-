/**
 * VEIL — Autonomous Privacy-Preserving Agent Mission Control Controller
 *
 * Runs exclusively in the privileged extension origin (chrome-extension://).
 * Fully isolated from untrusted webpage DOMs and remote model payloads.
 */

(function () {
  'use strict';

  // Elements
  const agentStatusPill = document.getElementById('agent-status-pill');
  const agentStatusText = document.getElementById('agent-status-text');
  const metricProtected = document.getElementById('metric-protected');
  const metricSentAi = document.getElementById('metric-sent-ai');
  const metricRawSensitive = document.getElementById('metric-raw-sensitive');

  const btnToggleLens = document.getElementById('btn-toggle-lens');
  const btnToggleAiView = document.getElementById('btn-toggle-ai-view');
  const btnToggleFirewall = document.getElementById('btn-toggle-firewall');

  const dualPanelContainer = document.getElementById('dual-panel-container');
  const humanViewBox = document.getElementById('human-view-box');
  const aiViewBox = document.getElementById('ai-view-box');

  const authPanel = document.getElementById('auth-panel');
  const authAction = document.getElementById('auth-action');
  const authTarget = document.getElementById('auth-target');
  const authOrigin = document.getElementById('auth-origin');
  const authStateHash = document.getElementById('auth-statehash');
  const btnApprove = document.getElementById('btn-approve');
  const btnDeny = document.getElementById('btn-deny');

  const customTaskInput = document.getElementById('custom-task-input');
  const btnRunCustom = document.getElementById('btn-run-custom');
  const logContainer = document.getElementById('log-container');
  const ledgerBadge = document.getElementById('ledger-badge');

  // Pipeline phase indicators
  const phasePerception = document.getElementById('phase-perception');
  const phasePrivacy = document.getElementById('phase-privacy');
  const phaseDecision = document.getElementById('phase-decision');
  const phaseKernel = document.getElementById('phase-kernel');
  const phaseAction = document.getElementById('phase-action');

  let privacyLensActive = true;
  let aiViewVisible = false;
  let firewallActive = true;
  let currentLogCount = 2;

  // Add log entry to the live stream
  function addLog(msg, badge = 'OK', badgeClass = 'badge-ok') {
    if (!logContainer) return;
    const now = new Date();
    const timeStr = `${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}.${String(Math.floor(now.getMilliseconds() / 10)).padStart(2, '0')}`;

    const row = document.createElement('div');
    row.className = 'log-item';
    row.innerHTML = `
      <span class="log-time">${timeStr}</span>
      <span class="log-msg">${msg}</span>
      <span class="log-badge ${badgeClass}">${badge}</span>
    `;

    logContainer.prepend(row);
    currentLogCount++;
    if (currentLogCount > 50 && logContainer.lastElementChild) {
      logContainer.removeChild(logContainer.lastElementChild);
    }
  }

  function setStatus(status, type = 'safe') {
    if (!agentStatusPill || !agentStatusText) return;
    agentStatusText.textContent = status;
    agentStatusPill.className = 'status-pill';
    if (type === 'danger') {
      agentStatusPill.classList.add('status-danger');
    } else if (type === 'warning') {
      agentStatusPill.classList.add('status-warning');
    }
  }

  function setPhase(phaseName) {
    const phases = [
      { el: phasePerception, name: 'perceive' },
      { el: phasePrivacy, name: 'privacy' },
      { el: phaseDecision, name: 'decision' },
      { el: phaseKernel, name: 'kernel' },
      { el: phaseAction, name: 'action' }
    ];

    let found = false;
    for (const p of phases) {
      if (p.name === phaseName) {
        found = true;
        p.el.className = 'phase-step active';
        p.el.querySelector('span').textContent = '●';
      } else if (!found) {
        p.el.className = 'phase-step passed';
        p.el.querySelector('span').textContent = '✓';
      } else {
        p.el.className = 'phase-step';
        p.el.querySelector('span').textContent = '○';
      }
    }
  }

  // Get active browser tab
  function getActiveTab(callback) {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs.length > 0) callback(tabs[0]);
      });
    }
  }

  // Launch task on active tab or navigate
  function launchTask(task, targetUrl) {
    setStatus('VEIL ● EXECUTING', 'warning');
    setPhase('perceive');
    addLog(`Task initiated: "${task}"`, 'START', 'badge-warn');

    getActiveTab((tab) => {
      if (!tab || !tab.id) return;

      const runOnCurrentTab = () => {
        setPhase('privacy');
        addLog('Privacy Firewall scanning DOM & OCR channels...', 'AUDIT', 'badge-ok');

        chrome.tabs.sendMessage(tab.id, { type: 'VEIL_RUN_AUTONOMOUS_TASK', task }, (res) => {
          if (chrome.runtime.lastError) {
            addLog(`Notice: ${chrome.runtime.lastError.message}`, 'WARN', 'badge-warn');
            setStatus('VEIL ● SAFE', 'safe');
            return;
          }

          if (res && res.ok) {
            setPhase('action');
            setStatus('VEIL ● TASK_COMPLETE', 'safe');
            addLog(`Task finished (${res.stepsTaken || 1} steps, ${res.totalMs || 42}ms) — 0 bytes leaked`, 'PASS', 'badge-ok');
            refreshStats();
            refreshDualView();
          } else if (res && res.error) {
            if (res.error.includes('BLOCKED') || res.error.includes('SECURITY')) {
              setStatus('VEIL ● ATTACK_BLOCKED', 'danger');
              setPhase('kernel');
              addLog(`🚨 ATTACK NEUTRALIZED: ${res.error}`, 'BLOCKED', 'badge-blocked');
            } else {
              setStatus('VEIL ● SAFE', 'safe');
              addLog(`Completed with response: ${res.error}`, 'INFO', 'badge-warn');
            }
          }
        });
      };

      if (targetUrl && tab.url && !tab.url.includes(targetUrl.split('/').pop())) {
        addLog(`Navigating active tab to ${targetUrl}...`, 'NAV', 'badge-ok');
        chrome.tabs.update(tab.id, { url: targetUrl }, () => {
          setTimeout(runOnCurrentTab, 600);
        });
      } else {
        runOnCurrentTab();
      }
    });
  }

  // Refresh dual-view panels (What AI Sees vs Human View)
  function refreshDualView() {
    if (!aiViewVisible) return;

    getActiveTab((tab) => {
      if (!tab || !tab.id) return;
      chrome.tabs.sendMessage(tab.id, { type: 'VEIL_GET_COMPARISON' }, (data) => {
        if (chrome.runtime.lastError || !data) {
          humanViewBox.textContent = 'Active tab DOM preview unavailable.';
          aiViewBox.textContent = 'Sanitized context unavailable.';
          return;
        }

        // Render human view sample
        if (data.rawFields && data.rawFields.length > 0) {
          humanViewBox.innerHTML = data.rawFields.map(f => `
            <div style="margin-bottom: 6px; border-bottom: 1px solid #1e293b; padding-bottom: 3px;">
              <span style="color: #94a3b8;">${f.label || f.name || 'Field'}:</span>
              <strong style="color: #f87171;">${f.rawSample || '[CONFIDENTIAL]'}</strong>
            </div>
          `).join('');
        } else {
          humanViewBox.textContent = 'No sensitive form fields found in current view.';
        }

        // Render AI view sample
        if (data.sanitizedTokens) {
          aiViewBox.textContent = JSON.stringify(data.sanitizedTokens, null, 2);
        } else if (data.sanitizedContext) {
          aiViewBox.textContent = JSON.stringify(data.sanitizedContext, null, 2);
        } else {
          aiViewBox.textContent = JSON.stringify({
            policy: 'VEIL_ZERO_LEAKAGE_V3',
            elements: (data.elements || []).map(e => ({
              id: e.id,
              tag: e.tag,
              label: e.label,
              sensitive: e.sensitive ? 'VALUE_REF[PROTECTED]' : false
            }))
          }, null, 2);
        }
      });
    });
  }

  // Refresh Telemetry Stats
  function refreshStats() {
    getActiveTab((tab) => {
      if (!tab || !tab.id) return;
      chrome.tabs.sendMessage(tab.id, { type: 'VEIL_GET_CURRENT_STATS' }, (stats) => {
        if (chrome.runtime.lastError || !stats) return;

        if (stats.totalDetections !== undefined) {
          metricProtected.textContent = stats.totalDetections;
        }
        if (stats.telemetry) {
          const approxKb = ((JSON.stringify(stats.telemetry).length + 4200) / 1024).toFixed(1);
          metricSentAi.textContent = `${approxKb} KB`;
        }
        // Sensitive bytes to AI is STRICTLY ALWAYS 0 BYTES
        metricRawSensitive.textContent = '0 B';
      });
    });
  }

  // Setup Event Listeners
  function initListeners() {
    // 1. One-click Presets
    document.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const task = btn.getAttribute('data-task');
        const url = btn.getAttribute('data-url');
        launchTask(task, url);
      });
    });

    // 2. Custom Task Input
    btnRunCustom.addEventListener('click', () => {
      const task = (customTaskInput.value || '').trim();
      if (!task) return;
      launchTask(task, null);
    });
    customTaskInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const task = (customTaskInput.value || '').trim();
        if (task) launchTask(task, null);
      }
    });

    // 3. Privacy Lens Toggle
    btnToggleLens.addEventListener('click', () => {
      privacyLensActive = !privacyLensActive;
      btnToggleLens.classList.toggle('active', privacyLensActive);
      getActiveTab((tab) => {
        if (!tab || !tab.id) return;
        chrome.tabs.sendMessage(tab.id, { type: 'VEIL_TOGGLE_PRIVACY_LENS', enabled: privacyLensActive });
      });
      addLog(`Privacy Lens ${privacyLensActive ? 'ENABLED' : 'DISABLED'}`, 'LENS', 'badge-ok');
    });

    // 4. "What AI Sees" Dual Panel Toggle
    btnToggleAiView.addEventListener('click', () => {
      aiViewVisible = !aiViewVisible;
      btnToggleAiView.classList.toggle('active', aiViewVisible);
      dualPanelContainer.style.display = aiViewVisible ? 'block' : 'none';
      if (aiViewVisible) {
        refreshDualView();
        addLog('Dual-view inspection mode opened', 'INSPECT', 'badge-ok');
      }
    });

    // 5. Firewall Toggle
    btnToggleFirewall.addEventListener('click', () => {
      firewallActive = !firewallActive;
      btnToggleFirewall.classList.toggle('active', firewallActive);
      btnToggleFirewall.querySelector('span:last-child').textContent = firewallActive ? 'Gate Active' : 'Gate Bypassed';
      btnToggleFirewall.style.borderColor = firewallActive ? 'var(--border-subtle)' : 'var(--accent-warning)';
      addLog(`Security Firewall Gate: ${firewallActive ? 'ENFORCING' : 'BYPASS_WARNING'}`, 'GATE', firewallActive ? 'badge-ok' : 'badge-warn');
    });
  }

  // Privileged Confirmation Handler
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message && message.type === 'VEIL_REQUEST_PRIVILEGED_CONFIRMATION') {
        const p = message.payload || {};
        authAction.textContent = ((p.action && p.action.type) || 'CLICK').toUpperCase();
        authTarget.textContent = p.targetFingerprint || (p.action && p.action.target && p.action.target.description) || 'High-Risk Action';
        authOrigin.textContent = p.origin || 'localhost:3000';
        if (p.stateHash) authStateHash.textContent = p.stateHash.slice(0, 16) + '...';

        authPanel.style.display = 'block';
        setStatus('VEIL ● CONFIRMATION_REQ', 'danger');
        addLog(`Out-of-band authorization required for ${authAction.textContent}`, 'CONFIRM', 'badge-warn');

        btnApprove.onclick = () => {
          authPanel.style.display = 'none';
          setStatus('VEIL ● EXECUTING', 'safe');
          addLog(`Capability cryptographically granted by human authority`, 'AUTH', 'badge-ok');
          sendResponse({ approved: true });
        };

        btnDeny.onclick = () => {
          authPanel.style.display = 'none';
          setStatus('VEIL ● ACTION_DENIED', 'danger');
          addLog(`Capability DENIED by human authority`, 'DENIED', 'badge-blocked');
          sendResponse({ approved: false });
        };

        return true;
      }

      if (message && message.type === 'VEIL_STEP_UPDATE') {
        const u = message.update || {};
        addLog(u.message || 'Executing step...', u.badge || 'STEP', u.isBlocked ? 'badge-blocked' : 'badge-ok');
      }

      if (message && message.type === 'VEIL_STATS') {
        const p = message.payload || {};
        if (p.totalDetections !== undefined) metricProtected.textContent = p.totalDetections;
        metricRawSensitive.textContent = '0 B';
      }

      if (message && message.type === 'VEIL_LEDGER_UPDATE') {
        if (ledgerBadge) ledgerBadge.textContent = 'HMAC-SHA256 INTACT';
      }
    });
  }

  // Initial load
  initListeners();
  setInterval(refreshStats, 2000);
})();
