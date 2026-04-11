/**
 * renderer.js — TrustTrace Result Rendering
 *
 * FIXES APPLIED FOR EMAIL:
 *   ✅ FIX 1 — result header now shows correct label for email
 *              Was:  just showed type uppercase — "EMAIL: user@gmail.com"
 *              Now: type label maps cleanly for all three types
 *
 *   ✅ FIX 2 — email flags render correctly
 *              Backend pattern_detector.py returns email-specific flags like:
 *              "Email domain may be impersonating a free provider: gmai1.com"
 *              "Email local part contains a suspicious keyword: 'support'"
 *              These are plain strings — renderer already handles them
 *              correctly as a string array. No change needed to flag logic.
 *
 *   ✅ FIX 3 — email advice renders correctly
 *              Backend advice_generator.py returns email-specific advice like:
 *              "Check the sender's full email address — display names can be spoofed."
 *              "Mark this email as spam and delete it immediately."
 *              Already rendered as bullet array. No change needed.
 *
 * ALL BACKEND FIELD NAMES CONFIRMED CORRECT:
 *   data.input          ✅
 *   data.type           ✅  "url" | "phone" | "email"
 *   data.trust_score    ✅
 *   data.risk_level     ✅  "Low" | "Medium" | "High"
 *   data.pattern_flags  ✅  string array
 *   data.advice        ✅  string array
 *
 * HTML ELEMENTS WRITTEN (match trusttrace.html exactly):
 *   id="rsub"   id="rhb"   id="sv"    id="rfill"
 *   id="rpill"  id="stitle" id="bfill" id="scap"
 *   id="ilist"  id="ebox"  id="rs"
 */

// ── Risk level config ──────────────────────────────────────────
// Keys match EXACTLY what backend returns in risk_level:
// "Low" | "Medium" | "High"
const riskConfig = {
  High: {
    color:      'var(--red)',
    pillBg:     'rgba(255,45,85,.15)',
    pillBorder: 'rgba(255,45,85,.4)',
    emoji:      '🚨',
    label:      'HIGH RISK',
    title:      'Dangerous — Avoid!',
    caption:    'Strong indicators of malicious or fraudulent activity.',
  },
  Medium: {
    color:      'var(--yellow)',
    pillBg:     'rgba(255,213,0,.12)',
    pillBorder: 'rgba(255,213,0,.35)',
    emoji:      '⚠️',
    label:      'MEDIUM RISK',
    title:      'Proceed with Caution',
    caption:    'Suspicious characteristics found. Verify before interacting.',
  },
  Low: {
    color:      'var(--green)',
    pillBg:     'rgba(0,255,157,.1)',
    pillBorder: 'rgba(0,255,157,.28)',
    emoji:      '✅',
    label:      'LOW RISK',
    title:      'Trusted & Verified',
    caption:    'No major threats detected. Stay cautious online.',
  },
};

const typeLabels = {
  url:   'WEBSITE URL',
  phone: 'PHONE NUMBER',
  email: 'EMAIL ADDRESS',
};

function renderResult(data) {
  const inputVal  = data.input         || '';
  const inputType = data.type          || 'url';
  const score     = data.trust_score   ?? 0;
  const riskLevel = data.risk_level    || 'High';
  const flags     = data.pattern_flags || [];
  const advice    = data.advice        || [];

  if (data.api_results && data.api_results.urlhaus && data.api_results.urlhaus.threat) {
    const threat = data.api_results.urlhaus.threat.replace(/_/g, ' ');
    if (!flags.some(f => f.toLowerCase().includes('malware'))) {
      flags.push('URLhaus threat detected: ' + threat);
    }
  }

  const cfg       = riskConfig[riskLevel] || riskConfig['High'];
  const typeLabel = typeLabels[inputType] || inputType.toUpperCase();

  document.getElementById('rsub').textContent =
    typeLabel + ': ' +
    (inputVal.length > 55 ? inputVal.substring(0, 52) + '...' : inputVal);

  document.getElementById('rhb').innerHTML =
    `<span style="
       font-size:.8rem;
       color:${cfg.color};
       background:${cfg.pillBg};
       border:1px solid ${cfg.pillBorder};
       padding:5px 15px;
       border-radius:50px;
       font-weight:700;
       letter-spacing:1px;">
       ${cfg.emoji} ${cfg.label}
     </span>`;

  const circumference = 314;
  const ring = document.getElementById('rfill');
  ring.style.stroke           = cfg.color;
  ring.style.filter           = `drop-shadow(0 0 8px ${cfg.color})`;
  ring.style.strokeDashoffset = String(circumference);

  requestAnimationFrame(() => {
    setTimeout(() => {
      ring.style.strokeDashoffset = String(
        circumference - (score / 100) * circumference
      );
    }, 60);
  });

  const scoreEl = document.getElementById('sv');
  scoreEl.style.color = cfg.color;
  animateCount(scoreEl, score, 1200);

  document.getElementById('rpill').innerHTML =
    `<div class="rp" style="
       background:${cfg.pillBg};
       color:${cfg.color};
       border:1px solid ${cfg.pillBorder};">
       ${cfg.emoji} ${cfg.label}
     </div>`;

  const titleEl = document.getElementById('stitle');
  titleEl.textContent = cfg.title;
  titleEl.style.color = cfg.color;
  document.getElementById('scap').textContent = cfg.caption;

  const bar = document.getElementById('bfill');
  bar.style.background = cfg.color;
  bar.style.boxShadow  = `0 0 12px ${cfg.color}`;
  bar.style.width      = '0%';
  requestAnimationFrame(() => {
    setTimeout(() => { bar.style.width = score + '%'; }, 80);
  });

  const list = document.getElementById('ilist');
  list.innerHTML = '';

  if (!flags || flags.length === 0) {
    list.innerHTML =
      `<li class="ii2">
         <div class="id ds">✓</div>
         <span>No suspicious patterns detected</span>
       </li>`;
  } else {
    flags.forEach((flagText, i) => {
      const li = document.createElement('li');
      li.className = 'ii2';
      li.style.animationDelay = `${i * 0.06}s`;
      li.innerHTML =
        `<div class="id dr">!</div>
         <span>${flagText}</span>`;
      list.appendChild(li);
    });
  }

  const ebox = document.getElementById('ebox');

  if (!advice || advice.length === 0) {
    ebox.innerHTML = `<em>${cfg.emoji}</em>No specific advice available.`;
  } else {
    const bullets = advice.map(tip =>
      `<div style="
         margin-bottom:.55rem;
         padding-left:.85rem;
         border-left:2px solid ${cfg.color};
         line-height:1.6;">
         ${tip}
       </div>`
    ).join('');
    ebox.innerHTML = `<em>${cfg.emoji}</em>${bullets}`;
  }

  const rs = document.getElementById('rs');
  rs.style.display = 'block';
  setTimeout(() => {
    rs.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);
}

function animateCount(el, target, duration) {
  const start = performance.now();
  const step  = (timestamp) => {
    const elapsed  = timestamp - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(target * eased);
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
