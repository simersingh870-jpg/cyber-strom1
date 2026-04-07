/*
   LINK ANALYZER — server.js
   Node.js + Express backend
   POST /analyze  →  scrapes URL and returns JSON data
   */

// ── IMPORTS ─────────────────────────────────────────────────
const express = require('express'); // Web framework
const axios   = require('axios');   // HTTP client (fetches web pages)
const cheerio = require('cheerio'); // HTML parser (like jQuery for Node)
const dns     = require('dns');     // Built-in Node module for DNS lookups
const tls     = require('tls');     // TLS for SSL certificate checks
const cors    = require('cors');    // Allows frontend to call this API
const validator = require('validator'); // URL validation
const { promisify } = require('util'); // Turns callbacks into promises

// ── APP SETUP ────────────────────────────────────────────────
const app  = express();
const DEFAULT_PORT = 3000;
const PORT = process.env.PORT ? Number(process.env.PORT) : DEFAULT_PORT;

// Middleware: parse JSON bodies sent by the frontend
app.use(express.json());

// Middleware: allow requests from any origin (frontend running on file:// or localhost)
app.use(cors());

// Promisify dns.lookup so we can use async/await
const dnsLookup = promisify(dns.lookup);

/* ============================================================
   SECURITY HEADER ANALYSIS
   ============================================================ */
function analyzeSecurityHeaders(headers) {
  const normalized = Object.keys(headers || {}).reduce((acc, name) => {
    acc[name.toLowerCase()] = headers[name];
    return acc;
  }, {});

  const checks = [
    { name: 'strict-transport-security', label: 'HSTS' },
    { name: 'content-security-policy', label: 'Content-Security-Policy' },
    { name: 'x-content-type-options', label: 'X-Content-Type-Options' },
    { name: 'x-frame-options', label: 'X-Frame-Options' },
    { name: 'referrer-policy', label: 'Referrer-Policy' },
    { name: 'permissions-policy', label: 'Permissions-Policy' },
    { name: 'x-xss-protection', label: 'X-XSS-Protection' },
  ];

  const present = {};
  const missing = [];
  let score = 0;

  checks.forEach(check => {
    if (normalized[check.name]) {
      present[check.label] = normalized[check.name];
      score += 100 / checks.length;
    } else {
      missing.push(check.label);
    }
  });

  return {
    present,
    missing,
    score: Math.round(score),
  };
}

const DEFAULT_REQUEST_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1',
  'DNT': '1',
};

function buildRequestHeaders(useReferer = false) {
  const headers = { ...DEFAULT_REQUEST_HEADERS };
  if (useReferer) {
    headers.Referer = 'https://www.google.com/';
    headers['Sec-Fetch-Site'] = 'none';
    headers['Sec-Fetch-Mode'] = 'navigate';
    headers['Sec-Fetch-User'] = '?1';
    headers['Sec-Fetch-Dest'] = 'document';
  }
  return headers;
}

async function fetchPageWithFallback(url) {
  const commonOptions = {
    timeout: 12000,
    maxRedirects: 5,
    validateStatus: (status) => status >= 200 && status < 600,
  };

  const firstAttempt = await axios.get(url, {
    ...commonOptions,
    headers: buildRequestHeaders(false),
  });

  if (firstAttempt.status !== 403) {
    return firstAttempt;
  }

  const secondAttempt = await axios.get(url, {
    ...commonOptions,
    headers: buildRequestHeaders(true),
  });

  return secondAttempt;
}

async function getSSLCertificateInfo(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const port = parsed.port || 443;

    return await new Promise((resolve) => {
      const socket = tls.connect({
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 5000,
      }, () => {
        const cert = socket.getPeerCertificate();
        socket.end();

        if (!cert || !cert.valid_to) {
          return resolve({ valid: false, error: 'No certificate details available' });
        }

        const validTo = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const now = new Date();
        const daysUntilExpiry = Math.max(0, Math.ceil((validTo - now) / 86400000));

        resolve({
          valid: now < validTo,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysUntilExpiry,
          issuer: cert.issuer,
          subject: cert.subject,
        });
      });

      socket.on('error', (err) => {
        socket.destroy();
        resolve({ valid: false, error: err.message });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ valid: false, error: 'TLS handshake timed out' });
      });
    });
  } catch (err) {
    return { valid: false, error: err.message || 'Certificate check failed' };
  }
};

/* ============================================================
   THREAT DETECTION DATABASE (Basic implementation)
   In production, use a real threat intelligence service
   ============================================================ */
const KNOWN_MALICIOUS_DOMAINS = [
  'malicious-site.com',
  'phishing-example.net',
  'fake-bank-login.ru',
  // Add more known malicious domains
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'account', 'verify', 'confirm', 'secure', 'update',
  'password', 'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
  'support', 'help', 'service', 'billing', 'payment', 'credit', 'card', 'wallet',
  'crypto', 'bitcoin', 'ethereum', 'nft', 'investment', 'trading', 'broker',
  'irs', 'tax', 'refund', 'prize', 'winner', 'lottery', 'free', 'gift', 'offer'
];

const PHISHING_PATTERNS = [
  /login.*password/i,
  /bank.*account/i,
  /paypal.*verify/i,
  /amazon.*refund/i,
  /microsoft.*support.*verify/i,
  /apple.*id.*recovery/i,
  /google.*account.*suspended/i,
  /facebook.*security.*alert/i,
  /irs.*tax.*refund/i,
  /netflix.*payment.*failed/i,
  /spotify.*account.*suspended/i,
  /instagram.*verification/i,
  /twitter.*account.*locked/i,
  /linkedin.*profile.*update/i,
  /ebay.*account.*verification/i,
  /craigslist.*posting.*verification/i,
];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'adf.ly',
  'is.gd', 'v.gd', 's.co', 'qr.ae', 'bc.vc', 'j.mp', 'tr.im', 'u.to',
  'cli.gs', 'po.st', 'su.pr', 'dlvr.it', 'fb.me', 'wp.me', 'youtu.be'
];

const HOMoglyph_CHARS = {
  'a': ['а', 'а', 'а'], // Cyrillic a
  'c': ['с', 'с'], // Cyrillic c
  'e': ['е', 'е'], // Cyrillic e
  'i': ['і', 'і'], // Cyrillic i
  'o': ['о', 'о', 'ο'], // Cyrillic o, Greek omicron
  'p': ['р', 'р'], // Cyrillic p
  's': ['ѕ'], // Cyrillic s
  'x': ['х', 'х'], // Cyrillic x
  'y': ['у'], // Cyrillic y
  '0': ['о'], // Zero looks like o
  '1': ['і', 'l'], // One looks like i or l
  '3': ['е'], // Three looks like e
  '5': ['ѕ'], // Five looks like s
  '8': ['о'], // Eight looks like o
};

/* ============================================================
   HELPER: Enhanced URL Validation
   ============================================================ */
function validateURL(url) {
  const errors = [];
  
  // Basic URL validation
  if (!validator.isURL(url, { 
    protocols: ['http', 'https'], 
    require_protocol: true 
  })) {
    errors.push('Invalid URL format');
    return { isValid: false, errors };
  }

  // Check for suspicious characters
  if (/[<>'"]/.test(url)) {
    errors.push('URL contains suspicious characters');
  }

  // Check URL length (very long URLs can be malicious)
  if (url.length > 2048) {
    errors.push('URL is unusually long');
  }

  // Check for IP addresses in URL (often used in malicious links)
  const hostname = getHostname(url);
  if (hostname && /^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    errors.push('URL uses IP address instead of domain name');
  }

  return { 
    isValid: errors.length === 0, 
    errors,
    warnings: [] // Could add warnings for non-critical issues
  };
}

/* ============================================================
   HELPER: Threat Detection
   ============================================================ */
function detectThreats(url, hostname) {
  const threats = [];
  let riskScore = 0;

  // Check against known malicious domains
  if (KNOWN_MALICIOUS_DOMAINS.includes(hostname)) {
    threats.push('Known malicious domain');
    riskScore += 100;
  }

  // Check for phishing patterns in URL
  PHISHING_PATTERNS.forEach(pattern => {
    if (pattern.test(url)) {
      threats.push(`Phishing pattern detected: ${pattern.source}`);
      riskScore += 25;
    }
  });

  // Check for suspicious keywords in URL
  const urlLower = url.toLowerCase();
  const suspiciousKeywordsFound = SUSPICIOUS_KEYWORDS.filter(keyword =>
    urlLower.includes(keyword.toLowerCase())
  );
  if (suspiciousKeywordsFound.length > 0) {
    threats.push(`Suspicious keywords detected: ${suspiciousKeywordsFound.slice(0, 3).join(', ')}`);
    riskScore += Math.min(suspiciousKeywordsFound.length * 5, 30);
  }

  // Check for URL shorteners (can hide malicious links)
  if (URL_SHORTENERS.some(shortener => hostname.includes(shortener))) {
    threats.push('URL shortener detected - cannot verify destination');
    riskScore += 40;
  }

  // Check for homoglyph attacks (similar looking characters)
  const homoglyphFound = checkHomoglyphs(url);
  if (homoglyphFound) {
    threats.push('Homoglyph characters detected (similar-looking characters)');
    riskScore += 35;
  }

  // Check for excessive subdomains
  const subdomainCount = hostname.split('.').length - 2; // Subtract TLD and main domain
  if (subdomainCount > 3) {
    threats.push('Excessive subdomains detected');
    riskScore += 15;
  }

  // Check for non-standard ports
  try {
    const urlObj = new URL(url);
    if (urlObj.port && ![80, 443].includes(parseInt(urlObj.port))) {
      threats.push('Non-standard port detected');
      riskScore += 15;
    }
  } catch (e) {
    // URL parsing failed, already handled in validation
  }

  // Check for IP addresses in URL (often used in malicious links)
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    threats.push('IP address in URL (bypasses domain reputation)');
    riskScore += 25;
  }

  // Check for unusual TLDs that might be typosquatting
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club'];
  const tld = hostname.split('.').pop();
  if (suspiciousTlds.includes('.' + tld)) {
    threats.push(`Suspicious TLD detected: .${tld}`);
    riskScore += 20;
  }

  return { threats, riskScore: Math.min(riskScore, 100) };
}

/* ============================================================
   HELPER: Check for Homoglyph Attacks
   ============================================================ */
function checkHomoglyphs(url) {
  const urlChars = url.split('');
  for (const char of urlChars) {
    const lowerChar = char.toLowerCase();
    if (HOMoglyph_CHARS[lowerChar]) {
      // Check if this character is a homoglyph
      if (HOMoglyph_CHARS[lowerChar].includes(char)) {
        return true;
      }
    }
  }
  return false;
}

/* ============================================================
   HELPER: Risk Assessment
   ============================================================ */
function assessRisk(threats, riskScore, isSecure, loadTime, securityHeaderScore) {
  let riskLevel = 'Low';
  let explanation = [];

  if (riskScore >= 80) {
    riskLevel = 'High';
    explanation.push('Multiple high-risk indicators detected');
  } else if (riskScore >= 50) {
    riskLevel = 'Medium';
    explanation.push('Some risk indicators detected');
  } else if (riskScore >= 20) {
    riskLevel = 'Low-Medium';
    explanation.push('Minor risk indicators detected');
  } else {
    explanation.push('No significant risk indicators detected');
  }

  // Additional risk factors
  if (!isSecure) {
    riskScore += 20;
    explanation.push('HTTP connection (not secure)');
  }

  if (loadTime > 5000) {
    riskScore += 10;
    explanation.push('Slow loading time may indicate issues');
  }

  if (typeof securityHeaderScore === 'number') {
    if (securityHeaderScore < 50) {
      riskScore += 20;
      explanation.push('Critical security headers are missing');
    } else if (securityHeaderScore < 70) {
      riskScore += 10;
      explanation.push('Some security headers are missing or incomplete');
    }
  }

  // Cap risk score
  riskScore = Math.min(riskScore, 100);

  // Adjust risk level based on final score
  if (riskScore >= 70) riskLevel = 'High';
  else if (riskScore >= 40) riskLevel = 'Medium';
  else riskLevel = 'Low';

  return {
    riskLevel,
    riskScore,
    explanation: explanation.join('. ')
  };
}

/* ============================================================
   HELPER: Extract hostname from URL string
   e.g. 'https://github.com/explore' → 'github.com'
   ============================================================ */
function getHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/* ============================================================
   HELPER: Resolve a relative URL to an absolute one
   e.g. '/favicon.ico' + 'https://github.com' → 'https://github.com/favicon.ico'
   ============================================================ */
function resolveURL(href, base) {
  if (!href) return null;
  try {
    return new URL(href, base).href;
  } catch {
    return href; // return as-is if it can't be resolved
  }
}

/* ============================================================
   API ENDPOINT: POST /analyze
   Body: { url: "https://example.com" }
   Returns: JSON with metadata, threat analysis, risk assessment, etc.
   ============================================================ */
app.post('/analyze', async (req, res) => {

  // 1. Get the URL from the request body
  const { url } = req.body;

  // Basic validation — make sure url was provided
  if (!url) {
    return res.status(400).json({ error: 'No URL provided in request body.' });
  }

  // Enhanced URL validation
  const validation = validateURL(url);
  if (!validation.isValid) {
    return res.status(400).json({ 
      error: 'URL validation failed: ' + validation.errors.join(', '),
      validation: validation
    });
  }

  // Parse URL for threat detection
  let parsedURL;
  try {
    parsedURL = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  const hostname = getHostname(url);
  const isSecure = parsedURL.protocol === 'https:';

  // Perform threat detection
  const threatAnalysis = detectThreats(url, hostname);

  try {

    // ── STEP 1: Record start time for load time measurement ──
    const startTime = Date.now();
    const analysisTimestamp = new Date().toISOString();

    // ── STEP 2: Fetch the webpage using axios with fallback headers ────────────────
    const response = await fetchPageWithFallback(url);

    // ── STEP 3: Calculate how long the fetch took ────────────
    const loadTime = Date.now() - startTime;

    if (response.status === 403) {
      return res.status(403).json({
        error: 'Access forbidden. The website blocked our request.',
        detail: 'The site returned HTTP 403 even after trying more browser-like request headers.',
      });
    }

    const finalUrl = response.request?.res?.responseUrl || url;
    const contentType = response.headers['content-type'] || null;
    const serverHeader = response.headers['server'] || null;
    const securityHeaders = analyzeSecurityHeaders(response.headers);
    const sslInfo = isSecure ? await getSSLCertificateInfo(url) : null;

    // ── STEP 4: Load HTML into cheerio (like jQuery) ─────────
    const $ = cheerio.load(response.data);
    const canonical = $('link[rel="canonical"]').attr('href')
      ? resolveURL($('link[rel="canonical"]').attr('href'), url)
      : null;

    // ── STEP 5: Extract metadata using cheerio selectors ─────

    // Page title: <title>...</title>
    const title = $('title').first().text().trim() || null;

    // Favicon — try multiple common locations in order
    let favicon =
      $('link[rel="icon"]').attr('href') ||
      $('link[rel="shortcut icon"]').attr('href') ||
      $('link[rel="apple-touch-icon"]').attr('href') ||
      null;

    // If found, resolve it to an absolute URL
    if (favicon) {
      favicon = resolveURL(favicon, url);
    } else {
      // Fallback: most sites have /favicon.ico at the root
      favicon = `${parsedURL.origin}/favicon.ico`;
    }

    // Page language from <html lang="en">
    const language = $('html').attr('lang') || null;

    // ── STEP 6: Resolve IP address using DNS ─────────────────
    let ip = null;
    try {
      const hostname = getHostname(url);
      if (hostname) {
        const result = await dnsLookup(hostname); // { address: '...', family: 4 }
        ip = result.address;
      }
    } catch (dnsErr) {
      // DNS lookup failed — not a fatal error, just set ip to null
      ip = null;
    }

    // ── STEP 7: Perform risk assessment ─────────────────────
    const riskAssessment = assessRisk(
      threatAnalysis.threats,
      threatAnalysis.riskScore,
      isSecure,
      loadTime,
      securityHeaders.score
    );

    // ── STEP 8: Send back all the collected data as JSON ─────
    return res.json({
      // Original metadata
      title,
      favicon,
      loadTime,   // in milliseconds
      ip,
      language,
      isSecure,   // true if HTTPS, false if HTTP
      contentType,
      serverHeader,
      finalUrl,
      canonical,
      securityHeaders,
      sslInfo,

      // New security and analysis features
      validation: validation,
      threatAnalysis: threatAnalysis,
      riskAssessment: riskAssessment,
      analysisTimestamp: analysisTimestamp,

      // Real-time analysis status
      status: 'completed',
      freshness: 'real-time'
    });

  } catch (err) {
    // Handle common errors nicely
    if (err.code === 'ECONNREFUSED') {
      return res.status(502).json({ error: 'Connection refused. The website may be down.' });
    }
    if (err.code === 'ENOTFOUND') {
      return res.status(502).json({ error: 'Domain not found. Check the URL and try again.' });
    }
    if (err.code === 'ETIMEDOUT' || err.message?.includes('timeout')) {
      return res.status(504).json({ error: 'Request timed out. The website took too long to respond.' });
    }
    if (err.response?.status === 403) {
      return res.status(403).json({ error: 'Access forbidden. The website blocked our request.' });
    }

    // Generic fallback error
    console.error('[/analyze error]', err.message);
    return res.status(500).json({ error: 'Failed to analyze the URL. ' + err.message });
  }

});

/* ============================================================
   HEALTH CHECK ENDPOINT: GET /
   Visit http://localhost:3000 to confirm server is running
   ============================================================ */
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Link Analyzer API is running 🚀' });
});

/* ============================================================
   START SERVER
   ============================================================ */
const server = app.listen(PORT, () => {
  console.log(`\n✅ Link Analyzer backend running at http://localhost:${PORT}`);
  console.log(`   POST http://localhost:${PORT}/analyze  →  Analyze a URL\n`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n🚨 Port ${PORT} is already in use. Use a different port by setting PORT or stop the process using this port.`);
    process.exit(1);
  }
  throw err;
});
