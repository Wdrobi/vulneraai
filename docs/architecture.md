# Architecture Diagram

The diagram below visualizes the main components and data flows in the VulnerAai project.

```mermaid
flowchart TD
    %% Users and Frontend
    U[User] --> BROWSER[Browser: HTML/CSS/JS]

    subgraph Frontend
        BROWSER --> V[Validation (frontend/js/utils.js)]
        BROWSER --> SJS[Scanner UI (frontend/js/script.js)]
        BROWSER --> RJS[Report UI (frontend/js/report.js)]
    end

    %% Backend API (Flask)
    subgraph Backend[Flask API]
        APP[backend/app.py] --> ROUTES[routes (backend/routes/*)]
        ROUTES --> AUTH[/api/auth/*]
        ROUTES --> SCAN_API[/api/scans/*]
        ROUTES --> REPORT_API[/api/reports/generate]
        ROUTES --> RISK_API[/api/risk/*]
    end

    %% Domain Services
    subgraph Services
        SCN[VulnerabilityScanner (backend/services/scanner.py)]
        INTEG[API Integrations (backend/services/api_integrations.py)]
        RISK[Risk Assessor (backend/services/risk_assessor.py)]
        REPORT[Report Generator (ReportLab + svglib + Pillow) (backend/services/report_generator.py)]
    end

    %% Data Layer
    subgraph Data_Layer[Data Layer]
        MODELS[Scan & Vulnerability Models (backend/models/*)]
        DB[(SQLite Database)]
        CFG[Configuration (backend/config.py)]
    end

    %% Frontend → Backend: Start Scan
    SJS -->|POST target| SCAN_API
    SCAN_API --> SCN
    SCN --> MODELS
    MODELS --> DB

    %% Risk Aggregation
    RISK_API --> RISK
    RISK --> MODELS

    %% Frontend → Backend: Fetch Results
    RJS -->|GET results| SCAN_API
    SCAN_API -->|JSON results| RJS

    %% Report Generation Flow
    RJS -->|GET PDF| REPORT_API
    REPORT_API --> REPORT
    REPORT -->|reads logo.svg| FRONTASSETS[frontend/assets/logo.svg]
    REPORT -->|PDF stream| BROWSER

    %% Auth Flow
    BROWSER -->|login/logout| AUTH
    AUTH --> DB

    %% Configuration
    CFG --> APP
    CFG --> MODELS

    %% External Integrations
    INTEG --> SCN

    %% File Naming
    REPORT -->|sanitized target filename| BROWSER
```
