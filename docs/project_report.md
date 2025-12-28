# VulneraAI Project Report

## Abstract
VulneraAI is a vulnerability intelligence platform that combines automated scanning with AI-assisted risk assessment to help users identify, prioritize, and track security issues across targets. The system provides clear reports, dashboards, and historical insights to support remediation.

## Table of Contents
- Introduction
- Objectives
- System Overview
- Architecture
- Data Model (ERD)
- Key Features
- Implementation Details
  - Backend (Flask)
  - Services Layer
  - Data & Models
  - External Integrations
- API Overview
- Frontend Overview
- Security Practices
- Testing Strategy & Coverage
- Results & Screens
- How to Run
- Limitations & Future Work
- Conclusion


## System Overview
VulneraAI follows a layered architecture: Frontend (HTML/CSS/JS), Backend (Flask API), Services (Scanner, Risk, Reports, Auth, Integrations), and Data (SQLite models + configs). Communication occurs via REST endpoints secured by tokens.

## Architecture
See the architecture diagram for components and flows:
- Image: [docs/architecture.png](architecture.png)
- Source: [docs/architecture.mmd](architecture.mmd)

## Data Model (ERD)
Core entities are `USER`, `SCAN`, and `VULNERABILITY` with relationships for ownership and containment.
- Poster: [docs/erd_poster.png](erd_poster.png)
- Standard: [docs/erd.png](erd.png)

## Key Features
- Vulnerability scanning with progress view and results
- AI-assisted risk assessment and severity grouping
- Report generation and export
- Authentication and user profiles
- Historical tracking of scans and vulnerabilities

## Implementation Details
### Backend (Flask)
- Entry: [backend/app.py](../backend/app.py)
- Routes: Auth, Scans, Reports
- CORS enabled for frontend integrations

### Services Layer
- Scanner: [backend/services/scanner.py](../backend/services/scanner.py)
- Risk Assessor: [backend/services/risk_assessor.py](../backend/services/risk_assessor.py)
- Report Generator: [backend/services/report_generator.py](../backend/services/report_generator.py)
- Auth Service: [backend/services/auth_service.py](../backend/services/auth_service.py)
- API Integrations: [backend/services/api_integrations.py](../backend/services/api_integrations.py)

### Data & Models
- Config: [backend/config.py](../backend/config.py)
- Models: [backend/models](../backend/models)
  - `user_model.py`, `scan_model.py`
- Storage: SQLite (file-based for simplicity)

### External Integrations
Designed for integrations like NVD, Censys, and VirusTotal for enrichment (see `api_integrations.py`).

## API Overview
Common endpoints (examples):
- `POST /api/auth/register` — Create account
- `POST /api/auth/login` — Obtain token
- `POST /api/auth/verify` — Validate token
- `GET /api/scans` — List scans
- `POST /api/scans` — Start a new scan
- `GET /api/scans/{id}` — Scan details
- `GET /api/reports/{id}` — Report output

## Frontend Overview
Pages and assets located in [frontend](../frontend):
- Pages: `home.html`, `index-scanner.html`, `dashboard.html`, `auth.html`, `report.html`, `privacy.html`, `terms.html`, `security.html`, `contact.html`
- Styles: `css/styles.css` + page-specific CSS
- Scripts: `js/api.js`, `js/dashboard.js`, `js/auth.js`, `js/report.js`

## Security Practices
- Token-based authentication with storage scoped to UI
- Transport security assumptions via TLS (when hosted)
- Least privilege across services
- Frontend hardening via reduced inline styles and consistent classes

## Testing Strategy & Coverage
Artifacts:
- Coverage poster: [docs/testing_poster.png](testing_poster.png)
- Test matrix (HTML): [docs/test_cases.html](test_cases.html)
- Backend tests: [backend/test_api_response.py](../backend/test_api_response.py), [backend/test_scan_details.py](../backend/test_scan_details.py), [backend/test_scan_db.py](../backend/test_scan_db.py)

Approach:
- Unit tests for services and models
- API tests for routes and auth
- Integration tests combining scanner and risk assessor
- Planned E2E via browser automation

## Results & Screens
- Tools & technology poster: [docs/tools_technology_poster.png](tools_technology_poster.png)
- Architecture and ERD posters for presentation
- Dashboard and report page visuals in `/frontend`

## How to Run
### Windows (Python installed)
1) Install deps
```
python -m pip install -r backend/requirements.txt
```
2) Start backend
```
python backend/app.py
```
3) Open frontend
- Open `frontend/home.html` or `frontend/index-scanner.html` in your browser

### macOS/Linux
Use [start.sh](../start.sh) for end-to-end startup.

## Limitations & Future Work
- Real integrations may require API keys and rate limiting
- Enhance risk scoring with exploit likelihood and asset criticality
- Add role-based access control and audit trails
- Implement PDF export for reports and dashboards

## Conclusion
VulneraAI provides a cohesive workflow for scanning, assessing, and reporting vulnerabilities. Its modular design allows easy extension for new scanners, risk models, and output formats while keeping the frontend simple and readable.
