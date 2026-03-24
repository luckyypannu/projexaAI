/**
 * api.js — TrustTrace Backend Communication
 *
 * FIXES APPLIED:
 *   [1] BASE_URL now reads from CONFIG.API_BASE (defined in config.js)
 *       instead of being hardcoded. config.js must be loaded first in HTML.
 *
 * Why this file works for all 3 input types (url, phone, email):
 *   Backend receives:  { "input": "whatever the user typed" }
 *   Backend's classify_input() in pattern_detector.py
 *   automatically detects whether it is a URL, phone, or email.
 *
 * BACKEND ENDPOINT REFERENCE:
 *   URL:     CONFIG.API_BASE + /scan
 *   Method:  POST
 *   Headers: Content-Type: application/json
 *   Body:    { "input": "<user value>" }
 *
 * BACKEND RESPONSE FIELDS (exact names from scan_routes.py):
 *   input          → string  — the scanned value
 *   type           → string  — "url" | "phone" | "email"
 *   trust_score    → integer — 0 to 100
 *   risk_level     → string  — "Low" | "Medium" | "High"
 *   pattern_flags  → array   — list of threat flag strings
 *   advice         → array   — list of advice strings
 */

// FIX: was hardcoded 'http://localhost:5000' — now reads from config.js
const BASE_URL = (typeof CONFIG !== 'undefined' && CONFIG.API_BASE)
  ? CONFIG.API_BASE
  : 'http://localhost:5000'; // fallback in case config.js fails to load

/**
 * scanApi(value)
 * Sends user input to backend /scan endpoint.
 * Works for URL, phone, AND email — backend classifies automatically.
 *
 * @param {string} value — raw trimmed input from the text field
 * @returns {object}     — raw backend response
 * @throws  {Error}      — on network failure or HTTP error
 */
async function scanApi(value) {
  const response = await fetch(BASE_URL + '/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ input: value.trim() }),
  });

  if (!response.ok) {
    let msg = `Server error: ${response.status}`;
    try {
      const errData = await response.json();
      if (errData.error) msg = errData.error;
    } catch (_) {}
    throw new Error(msg);
  }

  return response.json();
}

/**
 * reportApi(value)
 * Submits a user report to /report endpoint.
 * Works for all three input types.
 *
 * @param {string} value  — the input being reported
 * @param {string} reason — optional reason string
 */
async function reportApi(value, reason = 'Reported by user') {
  try {
    await fetch(BASE_URL + '/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: value.trim(), reason }),
    });
  } catch (_) {
    // Non-critical — do not block UI if report fails
  }
}
