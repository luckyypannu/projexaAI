/**
 * nav.js — TrustTrace Navigation
 * No changes — was already correct.
 */

const ham = document.getElementById('ham');
const nm  = document.getElementById('nmob');

ham.addEventListener('click', () => {
  ham.classList.toggle('open');
  nm.classList.toggle('open');
});

function cn() {
  ham.classList.remove('open');
  nm.classList.remove('open');
}
