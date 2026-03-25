/**
 * main.js — TrustTrace Main Controller
 *
 * FIXES APPLIED:
 *   [1] reportScam() function added — wired to the "Report this" button
 *       in the result panel (added in trusttrace.html).
 *       Calls reportApi() from api.js with the last scanned value.
 *       Shows user feedback after reporting.
 *
 * FUNCTIONS CALLED FROM HTML:
 *   go()         → onclick="go()"         on id="cbtn"
 *   reset()      → onclick="reset()"      on class="rbtn"
 *   reportScam() → onclick="reportScam()" on id="reportbtn"
 */

let _lastScanned = '';

// ── Main scan handler ──────────────────────────────────────────────────────────
async function go() {

  const value = document.getElementById('inp').value.trim();
  const type  = getType(); // from inputToggle.js

  const error = validate(value, type); // from validation.js
  if (error) { showError(error); return; }

  clearError();
  _lastScanned = value;

  setLoading(true);

  try {
    const data = await scanApi(value); // from api.js
    setLoading(false);
    renderResult(data); // from renderer.js

  } catch (ex) {
    setLoading(false);
    showApiError(ex.message || 'Unable to analyze. Please try again later.');
    console.error('[TrustTrace] Scan failed:', ex);
  }
}

// ── Reset / check another ──────────────────────────────────────────────────────
function reset() {
  document.getElementById('rs').style.display             = 'none';
  document.getElementById('inp').value                    = '';
  document.getElementById('ae').style.display             = 'none';
  document.getElementById('sv').textContent               = '--';
  document.getElementById('sv').style.color               = '';
  document.getElementById('bfill').style.width            = '0%';
  document.getElementById('rfill').style.strokeDashoffset = '314';

  // Reset report button state
  const rb = document.getElementById('reportbtn');
  if (rb) {
    rb.disabled     = false;
    rb.textContent  = '🚩 Report this';
  }

  clearError();

  const btn = document.getElementById('cbtn');
  btn.disabled    = false;
  btn.textContent = '⚡ CHECK TRUST SCORE';

  window.scrollTo({
    top: document.getElementById('card').offsetTop - 100,
    behavior: 'smooth',
  });

  document.getElementById('inp').focus();
  _lastScanned = '';
}

// ── Report scam handler ────────────────────────────────────────────────────────
async function reportScam() {
  if (!_lastScanned) return;

  const btn = document.getElementById('reportbtn');
  if (btn) {
    btn.disabled    = true;
    btn.textContent = '✅ Reported — Thank you!';
  }

  await reportApi(_lastScanned, 'Reported by user via UI'); // from api.js
}

// ── Loading state ──────────────────────────────────────────────────────────────
function setLoading(isLoading) {
  const btn = document.getElementById('cbtn');
  const lb  = document.getElementById('lb');
  const ae  = document.getElementById('ae');

  if (isLoading) {
    btn.disabled     = true;
    btn.textContent  = 'ANALYZING...';
    lb.style.display = 'flex';
    ae.style.display = 'none';
  } else {
    btn.disabled     = false;
    btn.textContent  = '⚡ CHECK TRUST SCORE';
    lb.style.display = 'none';
  }
}

// ── API error display ──────────────────────────────────────────────────────────
function showApiError(message) {
  const ae = document.getElementById('ae');
  ae.textContent   = '❌ ' + message;
  ae.style.display = 'block';
}

// ── Enter key triggers scan ────────────────────────────────────────────────────
document.getElementById('inp').addEventListener('keydown', e => {
  if (e.key === 'Enter') go();
});

// ── Contact form handler ───────────────────────────────────────────────────────
function sendContact() {
  const name  = document.getElementById('cname').value.trim();
  const email = document.getElementById('cemail').value.trim();
  const msg   = document.getElementById('cmsg').value.trim();

  if (!name || !email || !msg) {
    alert('Please fill in all fields before sending.');
    return;
  }

  // Show success state (no backend endpoint yet — UI feedback only)
  const btn = document.getElementById('csend');
  btn.disabled    = true;
  btn.textContent = '✅ Sent!';
  document.getElementById('cok').style.display = 'block';
}

// ── Backend health check on page load ─────────────────────────────────────────
(async function checkBackendOnLoad() {
  try {
    const res = await fetch(BASE_URL + '/health');
    if (!res.ok) throw new Error('not ok');
  } catch (_) {
    const ae = document.getElementById('ae');
    ae.textContent   = '⚠️ Backend server is not reachable. Make sure it is running on ' + BASE_URL;
    ae.style.display = 'block';
  }
})();