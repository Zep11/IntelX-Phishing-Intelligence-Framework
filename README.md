![Python](https://img.shields.io/badge/Python-3.10-blue) ![License](https://img.shields.io/badge/License-MIT-green)![Status](https://img.shields.io/badge/Status-Active-success)![Security](https://img.shields.io/badge/Threat%20Intelligence-Multi--Source-red)

# 🛡️ IntelX Phishing Intelligence Framework

> **An Automated Multi-Source Phishing URL Investigation Platform**

A comprehensive Python-based phishing URL investigation framework that combines **static URL analysis**, **multi-source threat intelligence**, and a **custom risk correlation engine** to determine the likelihood of a URL being malicious.

The tool performs automated investigations using industry-recognized threat intelligence providers and generates detailed investigation reports suitable for cybersecurity analysis.

---

# Features

## Static URL Analysis

The analyzer performs multiple heuristic checks before contacting external services.

✔ URL Parsing & Validation

✔ Heuristic URL Inspection

✔ Punycode Detection

✔ URL Shortener Detection

✔ Suspicious Keyword Analysis

✔ '@' Symbol Detection

✔ IP Hostname Detection

✔ HTTP/HTTPS Validation

✔ Subdomain Enumeration

✔ Non-standard Port Detection

---

## Threat Intelligence Integrations

The platform correlates intelligence from multiple providers.

| Provider | Purpose |
|----------|---------|
| VirusTotal | Multi-engine URL reputation |
| URLScan.io | Dynamic website analysis |
| AbuseIPDB | IP reputation lookup |
| WHOIS | Domain registration intelligence |
| Google Safe Browsing | Google phishing & malware detection |

---

## Risk Correlation Engine

Rather than relying on a single provider, the Risk Engine combines evidence from multiple intelligence sources to produce a final assessment.

The engine provides:

- Risk Score (0–100)
- Investigation Verdict
- Confidence Score
- Evidence Correlation
- Analyst Recommendation
- Provider Score Breakdown

---

## Reporting

The analyzer automatically generates:

### Raw Reports

Stores complete JSON responses from each threat intelligence provider.

```
reports/
└── raw_rprt/
```

### Clean Reports

Readable reports generated from each provider.

```
reports/
└── clean_rprt/
```

### Final Incident Report

A consolidated investigation report containing:

- Static URL Analysis
- VirusTotal Intelligence
- URLScan.io Analysis
- AbuseIPDB Investigation
- WHOIS Intelligence
- Google Safe Browsing Results
- Risk Correlation
- Final Analyst Conclusion

```
reports/
└── final_report/
```

---

# Project Architecture

```
Phishing_URL_Analyzer
│
├── main.py
├── validator.py
├── parser.py
├── signals.py
├── config.py
├── uiux.py
├── utils.py
│
├── Threat_Intel/
│   ├── virus_total.py
│   ├── urlscan_io.py
│   ├── abuseipdb.py
│   ├── whois.py
│   └── google_safe.py
│
├── Risk_Engine/
│   └── risk_engine.py
│
├── Report_Generator/
│   └── incident_report.py
│
├── reports/
│   ├── raw_rprt/
│   ├── clean_rprt/
│   └── final_report/
│
└── .env
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/Zep11/PHISHING_URL_ANALYZER.git
```

Navigate into the project

```bash
cd Phishing_URL_Analyzer
```

Create a virtual environment

```bash
python -m venv venv
```

Activate the environment

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# API Keys

The tool supports the following APIs.

| Provider | Required |
|----------|----------|
| VirusTotal | Optional |
| URLScan.io | Optional |
| AbuseIPDB | Optional |
| Google Safe Browsing | Optional |
| WHOIS | No API Required |

If API keys are not configured, the tool continues the investigation using the available providers.

---

# Running the Tool

```bash
python main.py
```

The tool will:

1. Load configuration
2. Validate the URL
3. Perform Static Analysis
4. Query Threat Intelligence Providers
5. Correlate Evidence
6. Calculate Risk
7. Generate Investigation Reports

---

# Example Investigation Flow

```
Target URL
        │
        ▼
Static URL Analysis
        │
        ▼
VirusTotal
        │
        ▼
URLScan.io
        │
        ▼
AbuseIPDB
        │
        ▼
WHOIS
        │
        ▼
Google Safe Browsing
        │
        ▼
Risk Correlation Engine
        │
        ▼
Final Incident Report
```

---

# Output

After every investigation the following reports are generated.

```
reports/

├── raw_rprt/
│
├── clean_rprt/
│
└── final_report/
    └── incident_report.txt
```

---

# Technologies Used

- Python 3.x
- Requests
- Rich
- JSON
- REST APIs

Threat Intelligence

- VirusTotal API
- URLScan.io API
- AbuseIPDB API
- Google Safe Browsing API
- WHOIS Lookup

---

# Future Improvements

- PDF Incident Reports
- HTML Dashboard
- Batch URL Analysis
- OpenPhish Integration
- AlienVault OTX Integration
- MalwareBazaar Support
- IOC Export
- Email Reputation Analysis
- QR Code Investigation
- Web Interface

---

# Disclaimer

This project is intended for:

- Cybersecurity Education
- Threat Hunting
- Security Research
- SOC Workflows
- Malware Investigation

Always ensure that investigations comply with applicable laws, regulations, and organizational policies.

---

# Author

*@Shubrajit Dey*

SOC Enthusiast

---

# License

This project is released under the MIT License.

# IMPORTANT 
This result does not guarantee that the URL is safe. Newly deployed or recently reported phishing URLs may not yet appear in VirusTotal, Google Safe Browsing, URLScan, or AbuseIPDB.
