let currentType = 'url';

  function setType(type) {
    currentType = type;
    const input = document.getElementById('main-input');
    document.getElementById('btn-url').classList.toggle('active', type === 'url');
    document.getElementById('btn-phone').classList.toggle('active', type === 'phone');
    input.placeholder = type === 'url'
      ? 'Enter website URL (e.g., example.com)'
      : 'Enter phone number';
    clearErrors();
  }

  function clearErrors() {
    const err = document.getElementById('error-msg');
    const inp = document.getElementById('main-input');
    err.classList.remove('show');
    inp.classList.remove('error-input');
  }

  function validate(value) {
    if (!value.trim()) return 'This field cannot be empty.';
    if (currentType === 'url') {
      const urlRegex = /^(https?:\/\/)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(\/.*)?$/;
      if (!urlRegex.test(value.trim())) return 'Please enter a valid domain (e.g., example.com).';
    } else {
      const digits = value.replace(/[\s\-\+\(\)]/g, '');
      if (!/^\d+$/.test(digits)) return 'Phone number must contain only digits.';
      if (digits.length < 10 || digits.length > 15) return 'Phone number must be 10–15 digits.';
    }
    return null;
  }

  async function handleCheck() {
    clearErrors();
    document.getElementById('api-error').classList.remove('show');
    document.getElementById('result-section').classList.remove('show');

    const value = document.getElementById('main-input').value;
    const errMsg = validate(value);

    if (errMsg) {
      const errEl = document.getElementById('error-msg');
      errEl.textContent = errMsg;
      errEl.classList.add('show');
      document.getElementById('main-input').classList.add('error-input');
      return;
    }

    const btn = document.getElementById('check-btn');
    const loading = document.getElementById('loading');
    btn.disabled = true;
    loading.classList.add('show');

    try {
      const endpoint = currentType === 'url'
        ? '/api/check-url'
        : '/api/check-phone';

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: value.trim(), type: currentType })
      });

      if (!res.ok) throw new Error('Server error');
      const data = await res.json();
      renderResult(data);

    } catch (e) {
      // Show demo result for preview (remove this block in production)
      const demo = getDemoResult(value);
      renderResult(demo);
      // Uncomment below for real error display:
      // document.getElementById('api-error').classList.add('show');
    } finally {
      btn.disabled = false;
      loading.classList.remove('show');
    }
  }

  // Demo data generator for preview purposes
  function getDemoResult(input) {
    const score = Math.floor(Math.random() * 100);
    const isUrl = currentType === 'url';
    return {
      score,
      indicators: isUrl
        ? [
            { label: 'HTTPS Enabled', safe: score > 50 },
            { label: 'Domain Age: ' + (score > 60 ? '3 Years' : '2 Months'), safe: score > 60 },
            { label: 'Not in Blacklist', safe: score > 40 },
            { label: 'Valid SSL Certificate', safe: score > 55 },
            { label: 'Low Spam Score', safe: score > 45 },
          ]
        : [
            { label: 'Registered carrier number', safe: score > 50 },
            { label: 'No fraud reports found', safe: score > 60 },
            { label: 'Not in scam database', safe: score > 40 },
            { label: 'Valid country code', safe: true },
          ],
      message: score >= 70
        ? 'This ' + (isUrl ? 'website' : 'number') + ' appears safe based on our analysis. It has a good reputation and no significant risk indicators were found.'
        : score >= 40
        ? 'This ' + (isUrl ? 'website' : 'number') + ' is moderately trusted but shows some suspicious signals. Proceed with caution and verify independently.'
        : 'This ' + (isUrl ? 'website' : 'number') + ' shows high-risk indicators and may be associated with scam activity. We strongly advise against engaging with it.',
    };
  }

  function renderResult(data) {
    const score = data.score;
    const isGreen = score >= 70, isYellow = score >= 40;
    const color = isGreen ? 'var(--safe)' : isYellow ? 'var(--warn)' : 'var(--danger)';
    const labelClass = isGreen ? 'label-safe' : isYellow ? 'label-warn' : 'label-danger';
    const labelText = isGreen ? '✓ Safe' : isYellow ? '⚠ Suspicious' : '✕ High Risk';
    const titleText = isGreen ? 'Looks Trustworthy' : isYellow ? 'Use with Caution' : 'Potential Scam';

    // Score ring
    const circumference = 207.3;
    const offset = circumference - (score / 100) * circumference;
    const ring = document.getElementById('ring-fg');
    ring.style.stroke = color;
    ring.style.strokeDashoffset = offset;

    document.getElementById('score-num').textContent = score;
    document.getElementById('score-num').style.color = color;

    // Label & title
    const lbl = document.getElementById('trust-label');
    lbl.textContent = labelText;
    lbl.className = 'trust-label ' + labelClass;

    document.getElementById('result-title').textContent = titleText;
    document.getElementById('result-subtitle').textContent = 'Trust Score: ' + score + ' / 100';

    // Progress bar
    const fill = document.getElementById('progress-fill');
    fill.style.width = score + '%';
    fill.style.background = `linear-gradient(90deg, ${color}aa, ${color})`;

    // Indicators
    const list = document.getElementById('indicators-list');
    list.innerHTML = '';
    (data.indicators || []).forEach(ind => {
      const div = document.createElement('div');
      div.className = 'indicator-item';
      div.innerHTML = `
        <div class="ind-icon ${ind.safe ? 'ind-safe' : 'ind-risk'}">${ind.safe ? '✔' : '✖'}</div>
        <span>${ind.label}</span>
      `;
      list.appendChild(div);
    });

    // Explanation
    document.getElementById('explanation').innerHTML = `<strong>Analysis:</strong> ${data.message}`;

    // Show result
    const resultSection = document.getElementById('result-section');
    resultSection.classList.add('show');
    setTimeout(() => resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);
  }

  function resetForm() {
    document.getElementById('main-input').value = '';
    document.getElementById('result-section').classList.remove('show');
    document.getElementById('api-error').classList.remove('show');
    clearErrors();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // Enter key support
  document.getElementById('main-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') handleCheck();
  });