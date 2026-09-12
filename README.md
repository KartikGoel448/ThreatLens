# ThreatLens

> **AI-assisted email forensic analysis platform for phishing detection, security intelligence, threat correlation, and tamper-evident reporting.**

ThreatLens is a full-stack cybersecurity web application designed to analyze suspicious emails and turn raw email data into structured forensic intelligence.

It combines **deterministic email security analysis**, **domain and network intelligence**, **AI-assisted content analysis**, **cross-case infrastructure correlation**, and **cryptographic report integrity** into a single investigation workflow.

---

## Overview

Email threats rarely depend on a single indicator.

A suspicious message may involve:

* Failed SPF, DKIM, or DMARC authentication
* Sender and Return-Path mismatches
* Newly registered domains
* Suspicious relay infrastructure
* Potentially risky URLs
* Social-engineering or credential-harvesting language
* Infrastructure shared with previously analyzed cases

ThreatLens brings these signals together and presents them as an interactive forensic investigation rather than relying on a single AI-generated verdict.

### Core analysis pipeline

```text
                    ┌──────────────────┐
                    │   Raw Email /    │
                    │      .eml        │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Email / MIME     │
                    │ Parser           │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        Authentication   Domain / IP      URL
        SPF/DKIM/DMARC   Intelligence   Extraction
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌──────────────────┐
                    │ Deterministic    │
                    │ Risk Analysis    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Gemini AI        │
                    │ Content Analysis │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Firestore        │
                    │ Case Storage     │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        Relay Trace    Correlation      Investigation
                         Engine             Graph
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌──────────────────┐
                    │ Forensic Report  │
                    │ + SHA-256 Hash   │
                    └──────────────────┘
```

---

## Features

### Email Forensic Analysis

* Parse raw RFC-style email headers and `.eml` files
* Extract `From`, `Return-Path`, `Received`, and other relevant headers
* Handle folded headers and MIME content
* Extract plain-text and HTML email content
* Extract URLs and surrounding HTML anchor context

### Authentication Analysis

ThreatLens evaluates available:

* **SPF**
* **DKIM**
* **DMARC**
* Authentication alignment
* Policy diagnostics

Technical authentication findings are kept separate from AI-generated interpretation.

### Domain Intelligence

ThreatLens uses live RDAP-based domain intelligence to determine:

* Registration date
* Domain age
* Registrar
* Recently registered status

Recently registered domains can contribute to the deterministic risk score.

When registration information is unavailable, ThreatLens reports it as unavailable instead of fabricating a value.

### Relay Trace

ThreatLens reconstructs the email's observed delivery path from `Received` headers.

The relay investigation includes:

* Hop number
* Hostname
* Sending hostname
* IP address
* IP classification
* Timestamp
* Timezone
* Transit delay
* Approximate geolocation
* ISP / ASN information when available

Private, reserved, loopback, and other non-public addresses are handled separately from public IPs.

> **Note:** IP geolocation represents approximate network information. It does not establish the exact physical location or identity of a sender.

### URL Intelligence

ThreatLens extracts URLs from email content and provides:

* URL
* Hostname/domain
* Path information
* HTML anchor context when available
* Available security classification

ThreatLens does not fabricate reputation information when external intelligence is unavailable.

### AI-Assisted Content Analysis

Gemini is used to analyze the actual email content for social-engineering indicators such as:

* Urgency and pressure
* Credential harvesting
* Financial coercion
* Authority or brand impersonation
* Suspicious requests

The AI analysis provides structured:

* Threat category
* Severity
* Confidence
* Evidence-based explanation

### Important AI Safety Boundary

Gemini does **not** determine or invent deterministic technical evidence.

The application keeps AI interpretation separate from:

* SPF
* DKIM
* DMARC
* Received headers
* IP geolocation
* RDAP/domain registration data
* URL intelligence

This separation helps prevent AI-generated claims from being presented as technical facts.

---

## Risk Scoring

ThreatLens combines multiple evidence sources into a bounded **0–100 risk score**.

The scoring system considers available signals such as:

* Authentication failures
* Domain intelligence
* URL indicators
* AI-assisted content findings
* Other deterministic security evidence

The score is constrained to the application's configured range of:

```text
0 ─────────────────────────────── 100
LOW                              HIGH
```

The final classification is presented alongside the evidence that contributed to the assessment.

---

## Investigation Graph & Campaign Correlation

ThreatLens can compare an analyzed case with previously stored cases.

Observable infrastructure can include:

* Sender domains
* Return-Path domains
* Public relay IPs
* URL domains
* Flagged URLs

When multiple cases share meaningful infrastructure, ThreatLens can identify a **campaign candidate** and visualize the relationships in an investigation graph.

The correlation system deliberately avoids claiming attacker attribution.

> **Correlation disclaimer:**
> This correlation indicates shared observable infrastructure across analyzed cases. It does not prove common ownership or attacker attribution.

Unrelated cases remain isolated rather than receiving artificially generated relationships.

---

## Forensic Reporting

ThreatLens generates a structured forensic dossier containing:

### A. Case Overview

* Case ID
* Analysis timestamp
* Classification
* Risk score
* Risk level
* Available analysis confidence

### B. Sender & Domain Intelligence

* From address
* Return-Path
* Sender domain
* Return-Path domain
* Alignment information
* Registration date
* Domain age
* Registrar
* Recently registered status

### C. Authentication Analysis

* SPF
* DKIM
* DMARC
* Alignment diagnostics

### D. Relay Trace

* Observed hops
* Hostnames
* IP addresses
* IP classification
* Timestamps
* Transit delays
* Approximate geolocation
* Network information

### E. URL Intelligence

* Extracted URLs
* Host domains
* Indicator classifications
* Available security findings

### F. AI-Assisted Content Analysis

* Model
* Overall assessment
* Threat categories
* Severity
* Confidence
* Evidence explanations

### G. Investigation & Correlation

* Related cases
* Shared domains
* Shared IPs
* Shared URLs
* Campaign candidate information
* Correlation explanation

### H. Key Evidence

A consolidated evidence summary mapped to the relevant analysis layer.

Missing information is explicitly represented as:

```text
Unavailable
```

rather than fabricated.

---

## Report Integrity

ThreatLens provides a **SHA-256 Report Integrity Hash** for the canonical forensic report payload.

The report data is deterministically serialized before hashing so that the same underlying data produces the same digest.

### Integrity workflow

```text
Stored Analysis
      │
      ▼
Canonical Report Payload
      │
      ▼
Deterministic Serialization
      │
      ▼
SHA-256
      │
      ▼
Integrity Hash
```

ThreatLens also supports integrity verification by recalculating the hash and comparing it with the stored/generated value.

Possible results include:

```text
Integrity verified — hash matches
```

or

```text
Integrity verification failed — hash mismatch
```

### What the hash does NOT prove

The integrity hash does not prove:

* That an email is malicious
* That a report is truthful
* That evidence is authentic
* The identity of an attacker
* Attacker attribution

It is an integrity mechanism for detecting changes to the canonical report data.

---

## Export Formats

ThreatLens supports:

| Format                | Purpose                             |
| --------------------- | ----------------------------------- |
| **PDF / Print**       | Printable forensic dossier          |
| **JSON**              | Structured case data                |
| **Markdown**          | Human-readable forensic report      |
| **Clipboard Summary** | Incident-response/ticketing summary |

---

## Technology Stack

### Frontend

* React
* TypeScript
* Vite
* Tailwind CSS
* Lucide React
* Motion

### Backend

* Node.js
* Express
* TypeScript
* `tsx`
* esbuild

### AI

* Google Gemini API
* `@google/genai`

### Data Storage

* Google Cloud Firestore
* `@google-cloud/firestore`

### Intelligence

* ICANN/IANA-compatible RDAP infrastructure for domain registration data
* Public IP geolocation providers for approximate network geolocation

### Build & Development

* Vite
* TypeScript
* esbuild
* Bun lockfile

The repository's current package configuration uses React, Vite, Express, Firestore, Gemini, Tailwind, Motion, and related TypeScript tooling.

---

## Project Structure

```text
ThreatLens/
│
├── server/
│   ├── emailContentExtractor.ts
│   ├── geminiContentThreatAnalyzer.ts
│   ├── firestore.ts
│   ├── correlationEngine.ts
│   └── ...
│
├── src/
│   ├── components/
│   │   ├── AnalyzerView.tsx
│   │   ├── ResultsView.tsx
│   │   ├── TraceView.tsx
│   │   ├── GraphView.tsx
│   │   ├── ReportView.tsx
│   │   └── ...
│   ├── App.tsx
│   ├── types.ts
│   └── ...
│
├── server.ts
├── index.html
├── package.json
├── bun.lock
├── tsconfig.json
├── vite.config.ts
├── metadata.json
├── .env.example
├── .gitignore
└── README.md
```

The repository currently contains the `server/` and `src/` application directories alongside the main TypeScript server entry point and Vite/TypeScript configuration.

---

## Environment Variables

Create a local `.env` file using `.env.example` as a reference.

```env
GEMINI_API_KEY="your_gemini_api_key_here"
APP_URL="your_app_url_here"
WHOIS_API_KEY=""
```

### Variables

| Variable         | Required             | Description                                        |
| ---------------- | -------------------- | -------------------------------------------------- |
| `GEMINI_API_KEY` | Yes                  | Gemini API access for AI-assisted content analysis |
| `APP_URL`        | Deployment-dependent | Application base URL                               |
| `WHOIS_API_KEY`  | No                   | Optional third-party WHOIS/RDAP provider key       |

ThreatLens can use public RDAP infrastructure for domain registration information, so a third-party WHOIS API key is optional.

> **Never commit `.env` or real API keys to GitHub.**

The repository includes `.env.example`, while `.env*` files are excluded through `.gitignore`.

---

## Local Development

### Prerequisites

* Node.js
* npm/Bun-compatible environment
* Google Gemini API access
* Google Cloud/Firestore configuration when persistence is enabled

### Install dependencies

```bash
npm install
```

### Start the development server

```bash
npm run dev
```

The development configuration runs the full-stack application through the TypeScript server entry point.

### Type-check

```bash
npm run lint
```

### Production build

```bash
npm run build
```

### Start the production server

```bash
npm start
```

The repository's current scripts define development, production build, production start, preview, clean, and TypeScript-check commands.

---

## Application Health

ThreatLens exposes a backend health endpoint:

```text
GET /api/health
```

A healthy deployment returns a service status indicating that the ThreatLens forensic analysis engine is operational.

---

## Security Design

ThreatLens follows several security-oriented design principles:

### Server-side secrets

API keys and credentials are kept on the server rather than embedded in client-side code.

### Evidence separation

Deterministic technical evidence is kept separate from probabilistic AI interpretation.

### No fabricated telemetry

When information is unavailable, ThreatLens displays:

```text
Unavailable
```

instead of inventing values.

### Safe correlation

Infrastructure correlation is presented as observable overlap rather than definitive attacker attribution.

### Report integrity

Forensic reports can be verified using a deterministic SHA-256 integrity hash.

### Public repository safety

The repository uses `.gitignore` rules for environment files, build output, dependencies, logs, and other generated content.

---

## Validation

ThreatLens has been validated across the complete analysis pipeline.

### QA Results

```text
Build & Application Health       PASS
Clean Email Analysis             PASS
Phishing-Style Analysis          PASS
Incomplete Email Handling        PASS
Domain Intelligence              PASS
Relay Trace                      PASS
URL Intelligence                 PASS
Gemini Content Analysis          PASS
Risk Scoring                     PASS
Investigation Correlation        PASS
Forensic Report                  PASS
PDF / Print Export               PASS
JSON Export                      PASS
Markdown Export                  PASS
Clipboard Export                 PASS
SHA-256 Integrity                PASS
Firestore Persistence            PASS
Secret / Security Review        PASS
Regression Test                  PASS
```

The validation confirmed that missing telemetry is represented as unavailable rather than fabricated, AI analysis remains separated from deterministic authentication evidence, cross-case correlation uses real stored indicators, and the report integrity mechanism detects modified payloads.

---

## Limitations

ThreatLens is an **AI-assisted forensic analysis tool**, not a replacement for a professional SOC, mail gateway, EDR, SIEM, or incident-response team.

Important limitations include:

* IP geolocation is approximate.
* Correlation does not prove attacker attribution.
* AI analysis is probabilistic.
* External intelligence providers may be unavailable or rate-limited.
* Authentication analysis depends on the information available in the analyzed email.
* A risk score should be interpreted together with its underlying evidence.
* A clean authentication result does not independently prove that an email is trustworthy.

---

## Responsible Use

ThreatLens is intended for:

* Security education
* Email security research
* Defensive cybersecurity analysis
* Incident-response workflows
* Threat-intelligence investigation
* Security demonstrations and experimentation

Only analyze email data that you are authorized to inspect.

Do not use the platform to access, expose, or distribute private information without appropriate authorization.

---

## Project Status

**Status: v1 — Core forensic analysis pipeline complete**

Current capabilities include:

* Email parsing
* Authentication analysis
* Domain intelligence
* Relay tracing
* IP intelligence
* URL extraction
* AI-assisted content analysis
* Risk scoring
* Firestore persistence
* Cross-case correlation
* Investigation graph
* Forensic reporting
* Multi-format export
* SHA-256 report integrity verification

---

## Future Improvements

Potential future development areas include:

* Additional threat-intelligence providers
* More advanced URL reputation enrichment
* Authentication result verification against live DNS/mail infrastructure
* Improved campaign clustering
* Authentication/user accounts
* Advanced case management
* Automated regression testing
* More deployment and observability tooling

These are intentionally outside the current v1 core feature set.

---

## Disclaimer

ThreatLens provides security analysis and intelligence to assist investigation. Its results should be treated as decision-support information rather than definitive attribution or proof of malicious activity.

AI-generated findings may be probabilistic and should be evaluated alongside the underlying technical evidence.

---

## Author

**Kartik Goel**

GitHub: [@KartikGoel448](https://github.com/KartikGoel448)

---

## License

No license has currently been specified for this repository.

If you intend to distribute the source code as open source, consider adding an appropriate license.
