/**
 * inputToggle.js — TrustTrace Input Type Toggle
 *
 * FIXES APPLIED:
 *   [1] clearError() call is now guarded with typeof check.
 *       inputToggle.js loads BEFORE validation.js in the HTML script order.
 *       If a user clicks a radio button before all scripts have loaded,
 *       calling clearError() directly would throw:
 *       "ReferenceError: clearError is not defined"
 *       The guard makes this safe regardless of load order.
 */

const tu  = document.getElementById('tu');   // URL radio
const tp  = document.getElementById('tp');   // Phone radio
const te  = document.getElementById('te');   // Email radio
const inp = document.getElementById('inp');
const ico = document.getElementById('ico');

// Config for each type — placeholder and icon
const typeConfig = {
  url: {
    placeholder: 'Enter website URL (e.g., example.com)',
    icon: '🌐',
  },
  phone: {
    placeholder: 'Enter phone number (e.g., +919876543210)',
    icon: '📞',
  },
  email: {
    placeholder: 'Enter email address (e.g., support@example.com)',
    icon: '✉️',
  },
};

// Listen for all three radio buttons
[tu, tp, te].forEach(radio => {
  radio.addEventListener('change', () => {
    // FIX: guard against clearError not yet being defined (script load order)
    if (typeof clearError === 'function') clearError();
    inp.value = '';

    const cfg = typeConfig[radio.value] || typeConfig.url;
    inp.placeholder = cfg.placeholder;
    inp.type        = 'text'; // always text — safe cross-browser
    ico.textContent = cfg.icon;
  });
});

/**
 * getType()
 * Returns the currently selected input type.
 * Returns "url" | "phone" | "email"
 * These values match EXACTLY what backend returns in data.type
 */
function getType() {
  const checked = document.querySelector('input[name="ct"]:checked');
  return checked ? checked.value : 'url';
}
