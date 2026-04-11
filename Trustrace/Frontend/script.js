/**
 * validation.js — TrustTrace Input Validation
 *
 * FIXES APPLIED:
 *   ✅ FIX 1 — Added email validation
 *              Was:  only url and phone validated
 *              Now:  url | phone | email all validated
 *              Without email validation, someone typing
 *              "notanemail" would either pass silently
 *              or get a confusing "invalid URL" error.
 *
 *   ✅ FIX 2 — Email regex matches backend _EMAIL_RE pattern
 *              Backend pattern_detector.py uses:
 *              r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
 *              Frontend regex mirrors this exactly so
 *              any input that passes frontend also passes backend.
 *
 *   ✅ FIX 3 — Error messages are type-specific
 *              Each type gets a clear, relevant error message.
 *
 * validate() returns null = valid, or string = error message.
 * showError() / clearError() update id="emsg" and id="inp".
 */

function validate(value, type) {
  const trimmed = (value || '').trim();

  // Empty check
  if (!trimmed) {
    const labels = { url: 'URL', phone: 'phone number', email: 'email address' };
    return `Please enter a ${labels[type] || 'value'} to check.`;
  }

  // Too long — protect backend from abuse
  if (trimmed.length > 500) return 'Input is too long. Maximum 500 characters.';

  // ── URL validation ───────────────────────────────────────────
  if (type === 'url') {
    const urlRegex = /^(https?:\/\/)?([\w-]+\.)+[\w]{2,}(\/\S*)?$/i;
    if (!urlRegex.test(trimmed))
      return 'Please enter a valid URL or domain (e.g., example.com)';
  }

  // ── Phone validation ─────────────────────────────────────────
  else if (type === 'phone') {
    const digitsOnly = trimmed.replace(/[\s\-\+\(\)]/g, '');
    if (!/^\d+$/.test(digitsOnly))
      return 'Phone number must contain only digits (spaces, +, - are allowed).';
    if (digitsOnly.length < 7 || digitsOnly.length > 15)
      return 'Phone number must be 7–15 digits long.';
  }

  // ── Email validation ─────────────────────────────────────────
  // FIX: mirrors backend _EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
  else if (type === 'email') {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;
    if (!emailRegex.test(trimmed))
      return 'Please enter a valid email address (e.g., user@example.com)';
  }

  return null; // null = valid — proceed with scan
}

function showError(message) {
  const el = document.getElementById('emsg');
  el.textContent   = '⚠ ' + message;
  el.style.display = 'block';
  document.getElementById('inp').classList.add('es');
}

function clearError() {
  document.getElementById('emsg').style.display = 'none';
  document.getElementById('inp').classList.remove('es');
}

document.getElementById('inp').addEventListener('input', clearError);
