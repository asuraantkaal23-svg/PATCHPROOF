
# PATCHPROOF
### Discover Real Flaws. Test Solutions. Prove Zero Regressions.

An intelligent application security platform that detects vulnerabilities, recommends and applies defensive patches, and verifies that security fixes actually work.

**Live Demo:** https://patchproof-indol.vercel.app/

---

## Overview

PatchProof is a defensive application security platform designed to make vulnerability detection and remediation more transparent, actionable, and verifiable.

Traditional vulnerability scanners identify security weaknesses but often leave developers with the difficult task of understanding, fixing, and validating them.

PatchProof goes beyond detection through an end-to-end security workflow:

1. **Scan** – Inspect public websites or upload application source code.
2. **Analyze** – Identify vulnerabilities, classify their severity, and provide supporting evidence.
3. **Patch** – Apply safe defensive changes in an isolated project copy.
4. **Prove** – Run exploit tests, regression checks, and before-and-after comparisons.

The goal is simple: not just to claim that a vulnerability has been fixed, but to provide evidence that the fix works.

## Key Features

### 1. Website Security Scanner

- Inspect publicly accessible websites.
- Analyze HTTP security headers and HTTPS transport.
- Review Content Security Policy (CSP).
- Check HSTS, MIME sniffing protection, Referrer Policy, and Permissions Policy.
- Identify browser runtime console errors.
- Generate actionable security recommendations.

### 2. Source Code Vulnerability Detection

Upload Python, JavaScript, TypeScript, or ZIP source files for security analysis.

The platform focuses on vulnerabilities such as:

- SQL Injection
- Broken Access Control
- Path Traversal
- Insecure application and server configurations

Findings include severity classification, CWE-related information, evidence, and relevant source locations.

### 3. Automated Security Patching

- Generate defensive remediation plans.
- Apply supported safe patches.
- Review individual fixes or use the Fix All Safe Patches workflow.
- Preserve original project files through isolated patching.
- Display before-and-after code differences.
- Download the patched project as a ZIP archive.

### 4. Security Verification and Regression Testing

PatchProof doesn't stop after applying a patch.

It provides verification workflows to:

- Test whether the original exploit is blocked.
- Check whether legitimate application behavior remains functional.
- Display regression test output.
- Compare earlier and patched versions.
- Track fixed and remaining vulnerabilities.

### 5. PS-02: Repeatable Security Practice Challenge

A built-in vulnerable application fixture demonstrates three important security weaknesses:

| Vulnerability | Security validation |
|---|---|
| SQL Injection | Malicious queries cannot retrieve unintended records. |
| Broken Access Control | Unauthorized users cannot perform privileged deletions. |
| Path Traversal | Files outside the permitted directory cannot be accessed. |

The fixture includes both attack tests and benign regression tests, making it possible to demonstrate security improvements without uploading an external project.

### 6. Security Center and Analytics

A centralized security dashboard provides:

- Overall application resilience score.
- Severity distribution.
- Vulnerability statistics.
- Fix readiness indicators.
- Active protection layers.
- Defensive improvement recommendations.

### 7. Before-and-After Comparison

Visualize the difference between the original and secured application.

Features include:

- Original versus patched source code.
- Security score comparison.
- Remaining vulnerability tracking.
- Sandbox policy previews.
- Exploit verification results.

### 8. Hackathon Evaluation Readiness

A dedicated evaluation module maps project capabilities against eight judging criteria:

- A – Security Problem and Threat Relevance
- B – Verified Cybersecurity Effectiveness
- C – Technical Implementation
- D – Innovation and Originality
- E – UI/UX Design and Experience
- F – Safety and Responsible Engineering
- G – Feasibility and Real-World Impact
- H – Live Demo and Communication

This helps connect working features with demonstrable technical evidence.

---

## Technology Stack

### Frontend

- React
- Vite
- Tailwind CSS v4
- Framer Motion
- Lucide React
- Aceternity UI components

### Backend

- Python
- Flask
- REST API architecture
- Static analysis and security detection
- Automated patching and verification workflows

### Deployment

- Vercel – Frontend deployment
- Flask backend – API and security analysis services

---

## Project Architecture

Example high-level structure:

```text
PATCHPROOF/
|
|-- backend/
|   |-- app.py
|
|-- frontend/
|   |-- src/
|   |-- public/
|   |-- package.json
|   |-- vite.config.js
|
|-- requirements.txt
|-- .env.example
|-- README.md
|-- .gitignore
```

The frontend communicates with the Flask backend through REST API endpoints under `/api/*`.

The architecture separates the user interface from the security analysis and remediation logic, making the platform easier to maintain and extend.

---

## Installation and Setup

### Prerequisites

- Python 3.10+
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd PatchProof
```

### 2. Set up the backend

Create and activate a virtual environment.

**Windows:**

```bash
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the Flask backend:

```bash
python backend/app.py
```

### 3. Set up the frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

### 4. Open the application

Visit the local Vite development URL displayed in your terminal, usually:

```text
http://localhost:5173
```

**Note:** Configure the frontend API connection and required environment variables using the supplied project configuration and `.env.example` file. The backend must be running for live scanning, patching, and verification features.

---

## Security and Responsible Engineering

PatchProof is designed as a defensive security tool.

Important design considerations include:

- Source modifications are performed in an isolated copy rather than directly overwriting the original project.
- Security checks are restricted to supported analysis patterns.
- Unsupported or ambiguous code patterns should be flagged for manual review rather than automatically modified.
- Practice-fixture tests use controlled, deliberately vulnerable application scenarios.
- Website scanning is intended for authorized security assessment.
- The platform does not deploy changes to third-party websites.

**Important limitation:** Website scanning identifies security configuration gaps and provides remediation recommendations. Applying a sandbox policy does not modify the original website. Actual security improvements must be deployed at the website's origin server or CDN and confirmed through a subsequent scan.

The static analysis engine does not detect every possible vulnerability. Manual security review remains important.

---

## Problem Statement

Many developers lack accessible tools that connect vulnerability discovery with reliable remediation and verification.

Existing approaches often create a gap between identifying a security issue and proving that the issue has been resolved without introducing new problems.

PatchProof addresses this gap through a unified workflow that combines:

- Vulnerability discovery.
- Evidence-based security analysis.
- Automated defensive remediation.
- Exploit validation.
- Regression testing.
- Transparent before-and-after comparisons.

## Innovation

The central innovation behind PatchProof is its **proof-gated remediation approach**.

Instead of treating a successful patch operation as proof of security, PatchProof emphasizes testing the original attack scenario and checking that legitimate functionality continues to work.

A vulnerability is not simply marked fixed because code changed. It must be tested, verified, and evaluated against regression behavior.

---

## Future Scope

Potential future improvements include:

- Expanded vulnerability detection across more programming languages.
- Deeper integration with CI/CD pipelines.
- More advanced contextual and AI-assisted remediation.
- Additional security testing frameworks.
- Automated post-deployment security monitoring.
- Broader CWE and OWASP vulnerability coverage.
- More comprehensive regression and false-positive analysis.

---

## Hackathon Project

**PATCHPROOF — Security Analysis and Verified Remediation**

Built to demonstrate how application security can become more accessible, transparent, and measurable.

Rather than stopping at identifying vulnerabilities, PatchProof aims to demonstrate the complete journey from detection to verified remediation.

**Live Website:** https://patchproof-indol.vercel.app/

---

## Disclaimer

PatchProof is intended for educational, defensive, and authorized security testing purposes only.

Users are responsible for obtaining appropriate authorization before scanning websites or analyzing application source code. Never use the platform to access, exploit, or modify systems without permission.

---

<p align="center">
  <strong>PATCHPROOF</strong><br>
  Detect. Defend. Verify.<br>
  Made for a more secure digital world.
</p>
