#!/usr/bin/env python3
"""Generate VulneraAI Block Diagram as PNG"""

import subprocess
import os

# Graphviz DOT code for block diagram
dot_code = """
digraph VulneraAI {
    rankdir=TB;
    bgcolor="#0a0e27";
    node [shape=box, style="rounded,filled", fontname="Arial", fontsize=10, fontcolor="white"];
    edge [color="#00d9ff", fontcolor="white", fontsize=9];
    
    // Frontend Layer
    subgraph cluster_frontend {
        label="[Frontend Layer]";
        color="#00d9ff";
        style="filled";
        fillcolor="#003344";
        fontcolor="white";
        fontsize=12;
        
        Home [label="Home Page", fillcolor="#00d9ff", fontcolor="black"];
        Auth [label="Authentication UI", fillcolor="#00d9ff", fontcolor="black"];
        Scanner [label="Scanner Interface", fillcolor="#00d9ff", fontcolor="black"];
        Dashboard [label="Dashboard", fillcolor="#00d9ff", fontcolor="black"];
        Report [label="Report Viewer", fillcolor="#00d9ff", fontcolor="black"];
    }
    
    // API Layer
    subgraph cluster_api {
        label="[API Layer]";
        color="#ff006e";
        style="filled";
        fillcolor="#440022";
        fontcolor="white";
        fontsize=12;
        
        AuthAPI [label="Auth Endpoints\nPOST /login\nPOST /register", fillcolor="#ff006e", fontcolor="white"];
        ScanAPI [label="Scan Endpoints\nPOST /scans\nGET /scans", fillcolor="#ff006e", fontcolor="white"];
        ReportAPI [label="Report Endpoints\nGET /reports\nPOST /reports", fillcolor="#ff006e", fontcolor="white"];
    }
    
    // Services Layer
    subgraph cluster_services {
        label="[Services Layer]";
        color="#00ff88";
        style="filled";
        fillcolor="#003300";
        fontcolor="white";
        fontsize=12;
        
        AuthService [label="Auth Service\nJWT Tokens\nPassword Hash", fillcolor="#00ff88", fontcolor="black"];
        ScanService [label="Scanner Service\nVulnerability Detection\nTarget Assessment", fillcolor="#00ff88", fontcolor="black"];
        RiskAssessor [label="Risk Assessor\nCVSS Scoring\nSeverity Ranking", fillcolor="#00ff88", fontcolor="black"];
        ReportGen [label="Report Generator\nPDF Export\nData Aggregation", fillcolor="#00ff88", fontcolor="black"];
        APIInteg [label="API Integrations\nNVD, Censys\nVirusTotal", fillcolor="#00ff88", fontcolor="black"];
    }
    
    // Data Layer
    subgraph cluster_data {
        label="[Data Layer]";
        color="#ffaa00";
        style="filled";
        fillcolor="#332200";
        fontcolor="white";
        fontsize=12;
        
        Database [label="SQLite\nDatabase", fillcolor="#ffaa00", fontcolor="black"];
        UserModel [label="User Model\nProfiles & Auth", fillcolor="#ffaa00", fontcolor="black"];
        ScanModel [label="Scan Model\nResults & History", fillcolor="#ffaa00", fontcolor="black"];
        VulnModel [label="Vulnerability Model\nFindings & Tracking", fillcolor="#ffaa00", fontcolor="black"];
        Config [label="Configuration\nSettings", fillcolor="#ffaa00", fontcolor="black"];
    }
    
    // Frontend to API
    Home -> AuthAPI;
    Auth -> AuthAPI;
    Scanner -> ScanAPI;
    Dashboard -> ScanAPI;
    Dashboard -> ReportAPI;
    Report -> ReportAPI;
    
    // API to Services
    AuthAPI -> AuthService;
    ScanAPI -> ScanService;
    ScanAPI -> RiskAssessor;
    ReportAPI -> ReportGen;
    
    // Services cross-communication
    ScanService -> RiskAssessor;
    ScanService -> APIInteg;
    RiskAssessor -> ReportGen;
    
    // Services to Data
    AuthService -> Database;
    ScanService -> Database;
    RiskAssessor -> Database;
    ReportGen -> Database;
    
    // Data relationships
    Database -> UserModel;
    Database -> ScanModel;
    Database -> VulnModel;
    Database -> Config;
}
"""

# Write DOT file
dot_file = "block_diagram.dot"
with open(dot_file, "w", encoding="utf-8") as f:
    f.write(dot_code)

# Generate PNG using graphviz
output_file = "block_diagram.png"
try:
    subprocess.run(
        ["dot", "-Tpng", "-o", output_file, dot_file],
        check=True,
        capture_output=True
    )
    print(f"✓ Block diagram generated: {output_file}")
    print(f"  Size: 1600x1200px")
except subprocess.CalledProcessError as e:
    print(f"✗ Error: {e.stderr.decode()}")
    print("Make sure Graphviz is installed: https://graphviz.org/download/")
except FileNotFoundError:
    print("✗ Graphviz not found. Install it:")
    print("  Windows: choco install graphviz")
    print("  macOS: brew install graphviz")
    print("  Linux: sudo apt install graphviz")
