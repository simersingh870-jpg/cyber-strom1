# 🔍 CyberLink Analyzer

A comprehensive URL analysis tool with security features, threat detection, and risk assessment. Built with vanilla HTML/CSS/JS (frontend) and Node.js + Express (backend).

---

## ✨ Features

- **URL Validation**: Advanced validation with security checks
- **Threat Detection**: Identifies suspicious patterns and known malicious domains
- **Phishing Protection**: Advanced detection of phishing attempts, homoglyph attacks, and suspicious URLs
- **Security Header Analysis**: Checks HSTS, CSP, X-Frame-Options, Referrer-Policy, and more
- **SSL Certificate Inspection**: Shows certificate validity and expiry days remaining
- **Risk Assessment**: Comprehensive risk scoring with detailed explanations
- **Real-time Analysis**: Live analysis with timestamps and freshness indicators
- **SEO Analysis**: Title optimization and basic SEO checks
- **User-friendly Interface**: Modern dark theme with glassmorphism effects

---

## 📁 Project Structure

```
cyber-link/
├── index.html          ← Main UI (single page)
├── style.css           ← All styling (dark theme, glassmorphism)
├── script.js           ← Frontend logic (API calls, rendering)
├── server.js           ← Express API server
├── package.json        ← Node.js dependencies
└── README.md           ← This file
```

---

## 🚀 How to Run (Step by Step)

### Prerequisites
Make sure you have **Node.js** installed. Check with:
```bash
node --version
```
If not installed, download from: https://nodejs.org

---

### Step 1 — Install Dependencies

Open your terminal, navigate to the project folder and install packages:

```bash
cd cyber-link
npm install
```

This installs: `express`, `axios`, `cheerio`, `cors`, `validator`.

---

### Step 2 — Start the Backend Server

```bash
npm start
```

You should see:
```
✅ Link Analyzer backend running at http://localhost:3000
```

> **Tip for development:** Use `npm run dev` instead to auto-restart on file changes (uses nodemon).

---

### Step 3 — Open the Frontend

Open a **new terminal window** (keep the backend running).

Navigate to the project folder and serve the frontend:

**Option A — Use Python's HTTP server:**
```bash
cd cyber-link
python -m http.server 8080
# Then visit: http://localhost:8080
```

**Option B — Just double-click** `index.html` in your file explorer.

**Option C — Use VS Code Live Server** (recommended):
1. Install the "Live Server" extension in VS Code
2. Right-click `index.html` → "Open with Live Server"

---

### Step 4 — Use the App

1. Enter any URL (e.g., `https://github.com`)
2. Click **Analyze**
3. See comprehensive results including:
   - **Security Analysis**: Threat detection and risk assessment
   - **SEO Data**: Title optimization and SEO checks
   - **Technical Info**: Load time, IP address, HTTPS status
   - **Risk Explanation**: Detailed breakdown of detected risks
   - **Real-time Analysis**: Timestamp and analysis freshness

---

## 🌐 API Reference

### `POST /analyze`

**Request body:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "title": "Example Domain",
  "favicon": "https://example.com/favicon.ico",
  "loadTime": 312,
  "ip": "93.184.216.34",
  "language": "en",
  "isSecure": true,
  "validation": {
    "isValid": true,
    "errors": [],
    "warnings": []
  },
  "threatAnalysis": {
    "threats": [],
    "riskScore": 0
  },
  "riskAssessment": {
    "riskLevel": "Low",
    "riskScore": 0,
    "explanation": "No significant risk indicators detected"
  },
  "analysisTimestamp": "2024-01-15T10:30:00.000Z",
  "status": "completed",
  "freshness": "real-time"
}
```

**New Security Features:**
- `validation`: URL validation results with errors and warnings
- `threatAnalysis`: Detected threats and risk score
- `riskAssessment`: Overall risk level and detailed explanation
- `analysisTimestamp`: When the analysis was performed
- `status` & `freshness`: Analysis status indicators
- `phishingDetection`: Specific phishing threat indicators

---

## 🛠 Tech Stack

| Layer    | Technology                      |
|----------|---------------------------------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend  | Node.js, Express.js             |
| Scraping | Axios (HTTP), Cheerio (HTML)    |
| Validation| Validator.js                    |
| DNS      | Node.js built-in `dns` module   |
| Fonts    | Google Fonts (Syne + DM Mono)   |
| Icons    | Lucide Icons (CDN)              |

---

## ❓ Troubleshooting

| Problem | Solution |
|---------|----------|
| `npm install` fails | Make sure Node.js ≥ 16 is installed |
| "Failed to reach the server" | Confirm backend is running on port 3000 |
| CORS error in browser | Backend includes CORS middleware — check it's running |
| Site returns 403 | Some sites block bots; try another URL |
| Favicon not showing | Some sites use non-standard paths; the fallback `/favicon.ico` is tried |
