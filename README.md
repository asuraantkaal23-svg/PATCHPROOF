# PatchProof 

**A local-first security inspection and automated remediation workspace built with Flask, React, and Vite.**

PatchProof helps developers inspect websites and source-code projects, review security findings, apply supported fixes, compare original and patched code, and download a patched project archive.

> **Source and scope:** This repository was migrated from the uploaded `V9_fixed.py` source. It is not a verification of a separate `PatchProof_4_0_Final(2).py` release. The implementation notes below describe the code that is actually included here.

## Features

- **Website inspection** — inspect public website response headers, page facts, and available browser/runtime signals.
- **Source scanning** — upload a ZIP project or supported individual source files for inspection.
- **Finding review** — view severity, evidence, and remediation guidance returned by the backend.
- **Automated remediation** — review and apply supported source patches individually or in a batch.
- **Patch verification** — run the backend's available checks against the patched result.
- **Code comparison** — inspect before/after source and patch output.
- **Project download** — download a ZIP containing the patched project.
- **Website preview sandbox** — preview selected security-header policy overlays without changing the live origin.
- **Practice challenge** — use the included fixture to explore the scan-and-fix workflow.
- **Diagnostics and readiness** — inspect runtime capabilities and the backend's diagnostic results.
- **Activity timeline** — see a session-local trace of frontend operations.

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | React 19, Vite |
| Styling | Tailwind CSS v4 |
| Motion | Motion for React (`motion/react` import) |
| Icons | Lucide React |
| UI components | Seven selected Aceternity UI components |
| Python security analysis | Bandit, with the source's compatibility fallback |
| Optional browser checks | Playwright + Chromium |

The seven selected Aceternity components are Aurora Background, Bento Grid, Glowing Effect, Code Block, Sidebar, File Upload, and Card Spotlight. Card Spotlight uses an internal Canvas Reveal Effect dependency; this is an implementation helper, not an additional selected component.

## Project structure

```text
PatchProof/
├── backend/
│   └── app.py
├── backup/
│   └── V9_fixed.py          # unchanged source backup
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── components/
│       ├── hooks/
│       ├── lib/
│       ├── pages/
│       ├── services/
│       ├── utils/
│       ├── App.jsx
│       ├── index.css
│       └── main.jsx
├── tests/
├── .env.example
├── requirements.txt
├── requirements-browser.txt
├── TEST_REPORT.md
└── README.md
```

## Requirements

- Python **3.10 or newer**
- Node.js **22.12 or newer** and npm
- Windows, macOS, or Linux
- Internet access for installing dependencies and for inspecting public websites

No external AI API key is required. The included security advisor uses the backend's offline/contextual logic.

## Quick start — Windows PowerShell

### 1. Clone the repository

Replace the URL with your GitHub repository URL:

```powershell
git clone https://github.com/YOUR-USERNAME/PatchProof.git
cd PatchProof
```

### 2. Set up the Flask backend

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, allow it for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Start Flask

From the repository root, with the virtual environment active:

```powershell
python .\backend\app.py
```

The backend listens at **http://127.0.0.1:5000** by default. Keep this terminal open.

### 4. Set up and start React

Open a second PowerShell terminal:

```powershell
cd .\PatchProof\frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173** in your browser. Vite proxies `/api/*` and `/health` requests to Flask on port `5000`.

### 5. Stop the application

Press `Ctrl+C` in both terminal windows.

## macOS / Linux quick start

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python backend/app.py
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Then open **http://127.0.0.1:5173**.

## Optional browser engine

The website inspection workflow can use Playwright and Chromium when installed. Install the optional dependencies:

```powershell
# Windows PowerShell, from the repository root
pip install -r requirements-browser.txt
python -m playwright install chromium
```

Without Playwright/Chromium, the backend uses its available static-analysis fallback and should not be interpreted as having completed Chromium-based browser checks.

## Production frontend build

To build the React frontend and serve it through Flask:

```powershell
cd .\frontend
npm install
npm run build
cd ..
python .\backend\app.py
```

When `frontend/dist/index.html` exists, Flask serves the built frontend at **http://127.0.0.1:5000**. During development, use the separate Vite server at port `5173`.

## Configuration

### Backend

Copy `.env.example` to `.env` and adjust the local bind settings only when needed:

```dotenv
PATCHPROOF_HOST=127.0.0.1
PATCHPROOF_PORT=5000
```

The defaults bind to localhost. Keep this for local development unless you have deliberately configured an appropriate trusted deployment boundary.

### Frontend development proxy

The frontend uses Vite's development proxy. To target a different local backend, copy `frontend/.env.example` to `frontend/.env.local` and set:

```dotenv
VITE_API_TARGET=http://127.0.0.1:5000
```

Restart Vite after changing the environment file.

## Supported remediation scope

The supplied backend's direct AST-based source remediation candidates include:

| Finding / pattern | Patch behavior |
|---|---|
| SQL injection | SQLite parameterized query transformation (`sqlite_parameter`) |
| Broken access control | Access-control guard transformation (`access_control`) |
| Path traversal | Safe-path handling (`safe_path`) |

The backend also integrates Bandit when available and includes a Python compatibility fallback. It can produce a bundled Bandit-hardening candidate for a reviewed subset of fixture findings.

**Important:** The ten patch-pattern list in the original migration brief is not fully implemented by the uploaded source. This repository does not contain registered handlers for `url_scheme`, `literal_eval`, `shell_argv`, `env_secret`, `stronger_digest`, `json_deserialize`, or `flask_debug`. These have not been fabricated or represented as supported fixes.

## Backend API

The React frontend calls the existing Flask routes directly.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Serves production React build when present; otherwise the embedded UI fallback |
| `GET` | `/health` | Backend health check |
| `POST` | `/api/audit` | Upload and scan ZIP projects or individual source files |
| `POST` | `/api/apply-patch` | Apply one registered source patch and verify it |
| `POST` | `/api/apply-all` | Apply selected/all patches; empty `patch_ids` resets the patched copy to the original input |
| `GET` | `/api/download/<project_id>` | Download the patched project ZIP |
| `POST` | `/api/inspect` | Inspect a public website |
| `POST` | `/api/challenge-demo` | Run the built-in practice challenge |
| `POST` | `/api/analytics/stats` | Return security analytics aggregates |
| `POST` | `/api/website-sandbox-fix` | Apply supported security-header overlays to a local preview sandbox |
| `GET` | `/api/preview` | Browser screenshot endpoint; requires Playwright + Chromium |
| `GET` | `/api/website-preview-original` | Preview the original website |
| `GET` | `/api/website-preview-patched` | Preview the patched-policy website sandbox |
| `GET` | `/api/sample-project` | Download the built-in practice fixture ZIP |
| `GET` | `/api/evaluation/readiness` | Return evidence-readiness and diagnostic information |
| `GET` | `/api/diagnostics/ultra` | Run the built-in backend diagnostic suite |
| `GET` | `/api/diagnostics` | Report runtime and dependency capabilities |

Project IDs and upload workspaces are held in process memory. Keep the Flask process running during a workflow. Restarting Flask clears active project sessions; upload and scan the project again if a session has expired.

## Testing and validation

See [`TEST_REPORT.md`](./TEST_REPORT.md) for the detailed report. The available validation includes:

- Python compilation
- 12 source-contract tests
- 22 built-in backend diagnostics
- JavaScript/JSX parsing and relative-import resolution
- Vite configuration and package JSON validation
- ZIP integrity and original-backup hash verification

**Build limitation:** In the environment where this migration was assembled, npm registry access timed out. Therefore `npm install`, `npm run build`, live browser rendering, and live React-to-Flask HTTP workflows were not verified there. The diagnostic suite was executed with a Flask import shim because Flask was not installed in that environment; it was not a live HTTP server test. Install dependencies locally and run the commands above before relying on a deployment.

## Security notes

- This is a local development and security-assistance tool, not a substitute for manual security review, CI isolation, production authentication, or deployment approval.
- Keep Flask bound to `127.0.0.1` for local use. Do not expose the development server directly to the public internet.
- Uploaded ZIP files are processed by the backend's safe extraction routine. Do not remove or weaken its archive path checks.
- Uploaded untrusted test suites are not automatically executed by the web process; the backend contains an explicit execution guard.
- Website URL and redirect validation are part of the backend's security boundary. Preserve these checks when modifying the application.
- Website sandbox header overlays change the local preview response, not the real website's server, CDN, or production configuration.
- The backend does not expose a separate persistent patch-history or historical rollback API. `POST /api/apply-all` with an empty `patch_ids` list resets the patched copy to its original uploaded content; this is a reset to baseline, not a version-history rollback.
- The source does not include a finding-feedback persistence endpoint. The frontend activity timeline is client-side and session-local, not server-persisted audit history.

## Contributing

Issues and pull requests are welcome. Before submitting a change:

1. Preserve existing Flask route contracts unless a change is documented.
2. Add or update tests for backend behavior.
3. Run the Python tests and compile checks.
4. Run `npm run build` for frontend changes.
5. Document any capability that requires an optional dependency or external service.

## License

No license file was supplied with this source. Add a `LICENSE` file before distributing this repository under an open-source license.
