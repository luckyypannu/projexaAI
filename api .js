/**
 * api.js — TrustTrace Backend Communication (FINAL VERSION)
 */

// Base URL (from config.js)
const BASE_URL = (typeof CONFIG !== 'undefined' && CONFIG.API_BASE)
  ? CONFIG.API_BASE
  : 'http://localhost:5000';


/**
 * Helper: fetch with timeout
 */
async function fetchWithTimeout(url, options = {}, timeout = 8000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(id);
  }
}


/**
 * scanApi(value)
 */
async function scanApi(value) {
  if (!value || !value.trim()) {
    throw new Error("Input cannot be empty");
  }

  let response;

  try {
    response = await fetchWithTimeout(BASE_URL + '/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ input: value.trim() }),
    });
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error("Request timed out. Server is slow.");
    }
    throw new Error("Network error. Check if backend is running.");
  }

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
 * reportApi(value, reason)
 */
async function reportApi(value, reason = 'Reported by user') {
  if (!value || !value.trim()) return;

  try {
    await fetchWithTimeout(BASE_URL + '/report', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        input: value.trim(),
        reason,
      }),
    });
  } catch (_) {
    // Silent fail (non-critical)
  }
}