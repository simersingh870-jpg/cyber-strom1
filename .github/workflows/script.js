/* ============================================================
   LINK ANALYZER — script.js
   Handles: URL validation, API call, rendering results
   ============================================================ */

// ── CONFIGURATION ──────────────────────────────────────────
// Backend server runs on port 3000
const API_BASE = 'http://localhost:3000';

// ── DOM REFERENCES ─────────────────────────────────────────
const urlInput       = document.getElementById('urlInput');
const analyzeBtn     = document.getElementById('analyzeBtn');
const loadingOverlay = document.getElementById('loadingOverlay');
const errorMsg       = document.getElementById('errorMsg');
const errorText      = document.getElementById('errorText');
const homeSection    = document.getElementById('home-section');
const resultsSection = document.getElementById('resultsSection');
const resultsGrid    = document.getElementById('resultsGrid');
const seoSection     = document.getElementById('seoSection');
const analyzedUrl    = document.getElementById('analyzedUrl');

// ── UTILITY: Basic URL Validation ──────────────────────────
/**
 * Returns true if the string looks like a valid http/https URL.
 * We use the built-in URL constructor which throws on bad input.
 */
function isValidURL(str) {
  try {
    const url = new URL(str);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

// ── UTILITY: Show / Hide Error ──────────────────────────────
const errorSolutions = [
  {
    match: /Invalid URL format|doesn't look like a valid URL|Invalid URL format/,
    solution: 'Make sure the address includes http:// or https:// and has no typos. Example: https://example.com',
  },
  {
    match: /Access forbidden|blocked our request|403/,
    solution: 'Try another website or use a URL that is publicly accessible. Some sites block automated analysis.',
  },
  {
    match: /Domain not found|ENOTFOUND/,
    solution: 'Check the URL spelling and verify the domain exists. If the site is new, DNS may not have propagated yet.',
  },
  {
    match: /timed out|ETIMEDOUT/,
    solution: 'The website is responding too slowly. Try again later or check your network connection.',
  },
  {
    match: /Connection refused|ECONNREFUSED/,
    solution: 'The target site is not accepting requests. Verify the website is online and try again later.',
  },
  {
    match: /Failed to reach the server|Failed to analyze the URL/,
    solution: 'Ensure the backend server is running and can connect to the internet.',
  },
];

function findErrorSolution(message) {
  if (!message) return '';
  const errorText = String(message);
  const found = errorSolutions.find(entry => entry.match.test(errorText));
  return found ? found.solution : 'Please check the URL or try again with a different website.';
}

function showError(message) {
  errorText.textContent = message;
  const solutionText = findErrorSolution(message);
  const errorSolution = document.getElementById('errorSolution');
  if (solutionText) {
    errorSolution.textContent = `Help: ${solutionText}`;
    errorSolution.hidden = false;
  } else {
    errorSolution.hidden = true;
  }
  errorMsg.classList.add('visible');
  // Re-initialize icons so the alert-circle shows
  lucide.createIcons();
}
function hideError() {
  const errorSolution = document.getElementById('errorSolution');
  errorSolution.hidden = true;
  errorMsg.classList.remove('visible');
}

// ── UTILITY: Fill an example URL into the input ─────────────
function fillExample(url) {
  urlInput.value = url;
  hideError();
  urlInput.focus();
}

// ── MAIN: Analyze URL ───────────────────────────────────────
/**
 * Called when the user clicks "Analyze" or presses Enter.
 * 1. Validates the URL
 * 2. Shows loading overlay
 * 3. POSTs to backend /analyze
 * 4. Renders result cards
 */
async function analyzeURL() {
  const rawURL = urlInput.value.trim();

  // Step 1 — Validate
  if (!rawURL) {
    showError('Please enter a URL before analyzing.');
    return;
  }

  // Auto-prepend https:// if the user forgot
  const url = rawURL.startsWith('http') ? rawURL : 'https://' + rawURL;

  if (!isValidURL(url)) {
    showError('That doesn\'t look like a valid URL. Try: https://example.com');
    return;
  }

  hideError();

  // Step 2 — Show loading
  setLoading(true);

  try {
    // Step 3 — Call backend API
    const response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    // Check for server-side errors (e.g., site unreachable)
    if (!response.ok || data.error) {
      throw new Error(data.error || 'Server error. Please try again.');
    }

    // Step 4 — Render results
    renderResults(url, data);

  } catch (err) {
    setLoading(false);
    showError(err.message || 'Failed to reach the server. Is the backend running?');
  }
}

// ── TOGGLE LOADING STATE ────────────────────────────────────
function setLoading(active) {
  if (active) {
    analyzeBtn.disabled = true;
    loadingOverlay.classList.add('active');
  } else {
    analyzeBtn.disabled = false;
    loadingOverlay.classList.remove('active');
  }
}

// ── RENDER: Switch to Results View ─────────────────────────
/**
 * Hides the hero section and shows the results section.
 * Builds all the result cards dynamically.
 */
function renderResults(url, data) {
  setLoading(false);

  // Update the "analyzed URL" badge at the top of results
  analyzedUrl.innerHTML = `<span>🔗</span> ${url}`;

  // Hide home, show results
  homeSection.style.display = 'none';
  resultsSection.classList.add('active');

  // Clear previous results
  resultsGrid.innerHTML = '';
  seoSection.innerHTML  = '';

  // ── Build result cards ──────────────────────────────────
  // Each card: { icon, label, value, accent, type }
  const cards = [

    // 1. Website Title
    {
      icon: 'type',
      label: 'Page Title',
      value: data.title || 'Not found',
      accent: 'var(--accent-1)',
      type: 'text',
    },

    // 2. Favicon
    {
      icon: 'image',
      label: 'Favicon',
      value: data.favicon || null,
      accent: 'var(--accent-warn)',
      type: 'favicon',
    },

    // 4. Page Load Time
    {
      icon: 'zap',
      label: 'Load Time',
      value: data.loadTime ? `${data.loadTime} ms` : 'N/A',
      accent: data.loadTime < 1000 ? 'var(--accent-3)' : 'var(--accent-warn)',
      type: 'big',
    },

    // 5. Content Type
    {
      icon: 'file-text',
      label: 'Content Type',
      value: data.contentType || 'Unknown',
      accent: data.contentType?.includes('text/html') ? 'var(--accent-3)' : 'var(--accent-warn)',
      type: 'mono',
    },

    // 6. IP Address
    {
      icon: 'server',
      label: 'Server IP Address',
      value: data.ip || 'Could not resolve',
      accent: 'var(--accent-3)',
      type: 'mono',
    },

    // 7. Server Header
    {
      icon: 'cpu',
      label: 'Server Header',
      value: data.serverHeader || 'Not exposed',
      accent: data.serverHeader ? 'var(--accent-1)' : 'var(--accent-warn)',
      type: 'mono',
    },

    // 8. Final URL
    {
      icon: 'external-link',
      label: 'Final URL',
      value: data.finalUrl || 'N/A',
      accent: 'var(--accent-2)',
      type: 'text',
    },

    // 9. Canonical URL
    {
      icon: 'link-2',
      label: 'Canonical URL',
      value: data.canonical || 'Not specified',
      accent: 'var(--accent-2)',
      type: 'text',
    },

    // 10. Security Header Score
    {
      icon: 'shield-check',
      label: 'Security Header Score',
      value: data.securityHeaders ? `${data.securityHeaders.score}/100` : 'N/A',
      accent: data.securityHeaders?.score >= 70 ? 'var(--accent-3)' : 'var(--accent-warn)',
      type: 'big',
    },

    // 11. SSL Certificate
    {
      icon: 'shield',
      label: 'SSL Certificate',
      value: data.sslInfo
        ? data.sslInfo.valid
          ? `Valid for ${data.sslInfo.daysUntilExpiry} day(s)`
          : `Invalid / Expired: ${data.sslInfo.error || 'Unknown'}`
        : 'HTTPS required',
      accent: data.sslInfo?.valid ? 'var(--accent-3)' : 'var(--accent-err)',
      type: 'text',
    },

    // 12. Security Check
    {
      icon: 'shield',
      label: 'Security',
      value: data.isSecure ? 'Secure (HTTPS)' : 'Not Secure (HTTP)',
      accent: data.isSecure ? 'var(--accent-3)' : 'var(--accent-err)',
      type: 'text',
    },

    // 7. Risk Level
    {
      icon: data.riskAssessment?.riskLevel === 'High' ? 'alert-triangle' : 
            data.riskAssessment?.riskLevel === 'Medium' ? 'alert-circle' : 'check-circle',
      label: 'Risk Assessment',
      value: `${data.riskAssessment?.riskLevel || 'Unknown'} Risk (${data.riskAssessment?.riskScore || 0}/100)`,
      accent: data.riskAssessment?.riskLevel === 'High' ? 'var(--accent-err)' :
              data.riskAssessment?.riskLevel === 'Medium' ? 'var(--accent-warn)' : 'var(--accent-3)',
      type: 'text',
    },

    // 8. Threat Detection
    {
      icon: data.threatAnalysis?.threats?.length > 0 ? 'shield-x' : 'shield-check',
      label: 'Threat Detection',
      value: data.threatAnalysis?.threats?.length > 0 ? 
             `${data.threatAnalysis.threats.length} threat(s) detected` : 'No threats detected',
      accent: data.threatAnalysis?.threats?.length > 0 ? 'var(--accent-err)' : 'var(--accent-3)',
      type: 'text',
    },

    // 9. Analysis Timestamp
    {
      icon: 'clock',
      label: 'Analysis Time',
      value: data.analysisTimestamp ? new Date(data.analysisTimestamp).toLocaleString() : 'N/A',
      accent: 'var(--accent-2)',
      type: 'mono',
    },

    // 10. Page Language
    {
      icon: 'globe',
      label: 'Page Language',
      value: data.language || 'Not specified',
      accent: 'var(--accent-1)',
      type: 'mono',
    },
  ];

  // Render each card into the grid
  cards.forEach(card => {
    resultsGrid.appendChild(buildCard(card));
  });

  // ── SEO Checks Panel ────────────────────────────────────
  renderSEOPanel(data);

  // Re-initialize Lucide icons for the newly created elements
  lucide.createIcons();

  // Smooth scroll to results
  resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// ── BUILD A SINGLE RESULT CARD ──────────────────────────────
/**
 * Creates a .result-card DOM element for the given data.
 */
function buildCard({ icon, label, value, accent, type }) {
  const card = document.createElement('div');
  card.className = 'result-card';
  card.style.setProperty('--card-accent', accent);

  // Card header (icon + label)
  const header = document.createElement('div');
  header.className = 'card-header';
  header.innerHTML = `
    <div class="card-icon" style="background:${accent}18; color:${accent}">
      <i data-lucide="${icon}"></i>
    </div>
    <span class="card-label">${label}</span>
  `;

  // Card body (value display depends on type)
  let body;
  if (type === 'favicon') {
    body = document.createElement('div');
    if (value) {
      body.innerHTML = `<img class="favicon-img" src="${value}" alt="favicon"
        onerror="this.outerHTML='<span class=\\'card-value mono\\'>Could not load favicon</span>'" />`;
    } else {
      body.innerHTML = `<span class="card-value mono">No favicon found</span>`;
    }
  } else if (type === 'big') {
    body = document.createElement('div');
    body.className = `card-value big`;
    body.style.color = accent;
    body.textContent = value;
  } else if (type === 'mono') {
    body = document.createElement('div');
    body.className = 'card-value mono';
    body.textContent = value;
  } else {
    body = document.createElement('div');
    body.className = 'card-value';
    body.textContent = value;
  }

  card.appendChild(header);
  card.appendChild(body);
  return card;
}

// ── RENDER SEO CHECKS PANEL ─────────────────────────────────
/**
 * Builds a list of basic SEO checks with pass / fail / warn icons.
 */
function renderSEOPanel(data) {
  // Define checks: each has a label, status, and short note
  const checks = [
    {
      label: 'Page Title present',
      status: data.title ? 'pass' : 'fail',
      note: data.title ? `${data.title.length} chars` : 'Missing',
    },
    {
      label: 'Title length (50–60 chars ideal)',
      status: data.title
        ? (data.title.length >= 50 && data.title.length <= 70 ? 'pass' : 'warn')
        : 'fail',
      note: data.title ? `${data.title.length} chars` : '—',
    },
    {
      label: 'Favicon present',
      status: data.favicon ? 'pass' : 'warn',
      note: data.favicon ? 'Found' : 'Not detected',
    },
    {
      label: 'Page language declared',
      status: data.language ? 'pass' : 'warn',
      note: data.language || 'Missing',
    },
    {
      label: 'HTTPS security enabled',
      status: data.isSecure ? 'pass' : 'fail',
      note: data.isSecure ? 'Secure connection' : 'HTTP (not secure)',
    },
    {
      label: 'URL validation passed',
      status: data.validation?.isValid ? 'pass' : 'fail',
      note: data.validation?.isValid ? 'Valid URL' : 'Validation failed',
    },
    {
      label: 'Threat detection',
      status: data.threatAnalysis?.threats?.length === 0 ? 'pass' : 'fail',
      note: data.threatAnalysis?.threats?.length === 0 ? 'No threats' : `${data.threatAnalysis.threats.length} threat(s)`,
    },
    {
      label: 'Risk assessment',
      status: data.riskAssessment?.riskLevel === 'Low' ? 'pass' :
              data.riskAssessment?.riskLevel === 'Medium' ? 'warn' : 'fail',
      note: `${data.riskAssessment?.riskLevel || 'Unknown'} (${data.riskAssessment?.riskScore || 0}/100)`,
    },
  ];

  // Icons for each status
  const iconMap = {
    pass: '<i data-lucide="check"></i>',
    fail: '<i data-lucide="x"></i>',
    warn: '<i data-lucide="minus"></i>',
  };

  const checksHTML = checks.map(c => `
    <div class="seo-check">
      <span class="seo-check-icon ${c.status}">${iconMap[c.status]}</span>
      <span class="seo-check-label">${c.label}</span>
      <span class="seo-check-note">${c.note}</span>
    </div>
  `).join('');

  seoSection.innerHTML = `
    <h3><i data-lucide="bar-chart-2"></i> Security Analysis</h3>
    <div class="seo-checks">${checksHTML}</div>
    ${data.riskAssessment?.explanation ? `
    <div class="risk-explanation">
      <h4><i data-lucide="info"></i> Risk Explanation</h4>
      <p>${data.riskAssessment.explanation}</p>
    </div>
    ` : ''}
    ${data.securityHeaders ? `
    <div class="security-headers">
      <h4><i data-lucide="shield"></i> Security Headers</h4>
      <p class="security-header-score">Score: ${data.securityHeaders.score}/100</p>
      ${data.securityHeaders.missing.length > 0 ? `
        <p class="security-header-missing">Missing headers: ${data.securityHeaders.missing.join(', ')}</p>
      ` : '<p class="security-header-ok">All required security headers are present.</p>'}
    </div>
    ` : ''}
    ${data.sslInfo ? `
    <div class="ssl-details">
      <h4><i data-lucide="lock"></i> SSL Certificate</h4>
      <p>${data.sslInfo.valid ? `Valid for ${data.sslInfo.daysUntilExpiry} day(s)` : `Invalid / Expired: ${data.sslInfo.error || 'Unknown'}`}</p>
    </div>
    ` : ''}
    ${data.threatAnalysis?.threats?.length > 0 ? `
    <div class="threat-details">
      <h4><i data-lucide="alert-triangle"></i> Detected Threats</h4>
      <ul>
        ${data.threatAnalysis.threats.map(threat => `<li>${threat}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
  `;
}

// ── GO BACK TO HOME ─────────────────────────────────────────
function goBack() {
  resultsSection.classList.remove('active');
  homeSection.style.display = 'flex';
  urlInput.value = '';
  urlInput.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── KEYBOARD: Press Enter to Analyze ───────────────────────
urlInput.addEventListener('keydown', function (e) {
  if (e.key === 'Enter') analyzeURL();
});
