/**
 * VEIL — background service worker
 *
 * Holds the most recent stats per tab (content scripts push, popup pulls),
 * and performs the one network call this extension makes: POST /act to the
 * local server, with the already-sanitized context the content script built.
 * This runs from the service worker rather than the content script so it's
 * never subject to the page's own CSP.
 */

const SERVER_URL = 'http://127.0.0.1:8000/act';
const statsByTab = new Map();
let currentSessionKey = null;

const ALLOWED_MESSAGE_TYPES = new Set([
  'VEIL_STATS',
  'VEIL_GET_STATS',
  'VEIL_RUN_TASK_SERVER_CALL',
  'VEIL_FETCH_IMAGE_BLOB',
  'VEIL_REQUEST_PRIVILEGED_CONFIRMATION',
  'VEIL_SET_SESSION_KEY'
]);

function validateVEILMessage(message) {
  if (!message || typeof message !== 'object') return false;
  if (!message.type || typeof message.type !== 'string') return false;
  if (!ALLOWED_MESSAGE_TYPES.has(message.type)) return false;
  if (Object.prototype.hasOwnProperty.call(message, '__proto__') ||
     (Object.prototype.hasOwnProperty.call(message, 'constructor') && typeof message.constructor !== 'function')) {
    return false;
  }
  return true;
}

function isSafeImageUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    if (host === '169.254.169.254' || host === 'metadata.google.internal' || host === '100.100.100.200') {
      return false;
    }
    return true;
  } catch (_) {
    return false;
  }
}

async function callServer(task, context) {
  const headers = { 'Content-Type': 'application/json' };
  if (currentSessionKey) {
    headers['X-VEIL-Session-Key'] = currentSessionKey;
  }

  const res = await fetch(SERVER_URL, {
    method: 'POST',
    headers,
    body: JSON.stringify({ task, page: context }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`server responded ${res.status}: ${body.slice(0, 200)}`);
  }
  return res.json();
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!validateVEILMessage(message)) {
    sendResponse({ ok: false, error: 'Invalid or unauthorized VEIL message envelope' });
    return false;
  }

  if (message.type === 'VEIL_SET_SESSION_KEY') {
    currentSessionKey = typeof message.key === 'string' ? message.key : null;
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === 'VEIL_STATS' && sender.tab) {
    statsByTab.set(sender.tab.id, message.payload);
    return false;
  }

  if (message.type === 'VEIL_GET_STATS') {
    const stats = statsByTab.get(message.tabId) || null;
    sendResponse({ stats });
    return true;
  }

  if (message.type === 'VEIL_RUN_TASK_SERVER_CALL') {
    callServer(message.task, message.context)
      .then((action) => sendResponse({ ok: true, action }))
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true; // keep the message channel open for the async response
  }

  if (message.type === 'VEIL_FETCH_IMAGE_BLOB') {
    if (!message.url || !isSafeImageUrl(message.url)) {
      sendResponse({ ok: false, error: 'Invalid or prohibited image URL (SSRF defense)' });
      return false;
    }

    fetch(message.url)
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const buffer = await res.arrayBuffer();
        const mime = res.headers.get('content-type') || 'image/png';
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        sendResponse({ ok: true, dataUrl: `data:${mime};base64,${base64}` });
      })
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true;
  }

  if (message.type === 'VEIL_REQUEST_PRIVILEGED_CONFIRMATION') {
    // Privileged human confirmation requested from content script
    // In production side panel / popup UI, human approves through privileged channel
    // Fails closed if side panel is not active
    sendResponse({ approved: false, reason: 'Out-of-band privileged UI pending user interaction' });
    return false;
  }

  return false;
});

chrome.tabs.onRemoved.addListener((tabId) => statsByTab.delete(tabId));
