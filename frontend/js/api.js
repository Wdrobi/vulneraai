// ====================================
// VulneraAI - API Service
// ====================================

const API_BASE_URL = 'http://localhost:5000/api';

// Global variables
let currentScanId = null;
let scanInterval = null;
let currentResults = null;

// ====================================
// Scan API Calls
// ====================================

async function startScanAPI(target, scanType) {
    try {
        const response = await fetch(`${API_BASE_URL}/scans/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target: target,
                scanType: scanType
            })
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        const data = await response.json();
        currentScanId = data.scanId;
        return data;
    } catch (error) {
        console.error('Error starting scan:', error);
        throw error;
    }
}

async function getScanStatus(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/scans/${scanId}/status`, {
            method: 'GET'
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error getting scan status:', error);
        throw error;
    }
}

async function cancelScanAPI(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/scans/${scanId}/cancel`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error cancelling scan:', error);
        throw error;
    }
}

// ====================================
// Results API Calls
// ====================================

async function getScanResults(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/scans/${scanId}/results`, {
            method: 'GET'
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error getting scan results:', error);
        throw error;
    }
}

async function getRiskScore(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/risk/${scanId}`, {
            method: 'GET'
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error getting risk score:', error);
        throw error;
    }
}

// ====================================
// Reports API Calls
// ====================================

async function getScanHistory() {
    try {
        const response = await fetch(`${API_BASE_URL}/reports/history`, {
            method: 'GET'
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error getting scan history:', error);
        return [];
    }
}

async function generateReport(scanId, format = 'json') {
    try {
        const response = await fetch(`${API_BASE_URL}/reports/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                scanId: scanId,
                format: format
            })
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error generating report:', error);
        throw error;
    }
}

// ====================================
// Mock Data (for testing without backend)
// ====================================

function getMockScanStatus(progress) {
    return {
        scanId: 'scan-123',
        target: '192.168.1.1',
        status: progress < 100 ? 'scanning' : 'completed',
        progress: progress,
        vulnerabilitiesFound: Math.floor(progress / 10),
        message: getProgressMessage(progress),
        startedAt: new Date(Date.now() - progress * 1000),
        estimatedTime: 300 - progress * 3
    };
}

function getMockResults(target) {
    return {
        scanId: 'scan-123',
        target: target,
        completedAt: new Date().toISOString(),
        vulnerabilities: [
            {
                id: 'vuln-1',
                title: 'Open SSH Port',
                description: 'SSH service is exposed to the internet without proper authentication.',
                severity: 'high',
                cve: 'CVE-2021-28041',
                port: 22,
                service: 'SSH',
                remediation: 'Restrict SSH access using a firewall or VPN.'
            },
            {
                id: 'vuln-2',
                title: 'Weak TLS Configuration',
                description: 'Server is using outdated TLS 1.0 protocol.',
                severity: 'critical',
                cve: 'CVE-2011-3389',
                port: 443,
                service: 'HTTPS',
                remediation: 'Upgrade to TLS 1.2 or higher.'
            },
            {
                id: 'vuln-3',
                title: 'Open HTTP Port',
                description: 'HTTP traffic is not encrypted.',
                severity: 'medium',
                cve: '',
                port: 80,
                service: 'HTTP',
                remediation: 'Use HTTPS instead of HTTP.'
            },
            {
                id: 'vuln-4',
                title: 'Open FTP Port',
                description: 'FTP service is exposed without encryption.',
                severity: 'high',
                cve: '',
                port: 21,
                service: 'FTP',
                remediation: 'Use SFTP instead of FTP.'
            },
            {
                id: 'vuln-5',
                title: 'Telnet Service Active',
                description: 'Telnet is an unencrypted remote access protocol.',
                severity: 'critical',
                cve: '',
                port: 23,
                service: 'Telnet',
                remediation: 'Disable Telnet and use SSH instead.'
            },
            {
                id: 'vuln-6',
                title: 'Open SMTP Port',
                description: 'SMTP service allows mail relay without authentication.',
                severity: 'low',
                cve: '',
                port: 25,
                service: 'SMTP',
                remediation: 'Configure authentication and restrict relay.'
            }
        ],
        riskScore: 78,
        riskLevel: 'CRITICAL',
        stats: {
            critical: 2,
            high: 2,
            medium: 1,
            low: 1
        }
    };
}

function getMockRiskScore() {
    return {
        scanId: 'scan-123',
        score: 78,
        level: 'CRITICAL',
        reasoning: 'The system has 2 critical vulnerabilities including weak TLS and Telnet service. Immediate action required.',
        recommendations: [
            'Disable unnecessary services (Telnet, FTP)',
            'Update TLS configuration to 1.2+',
            'Implement proper firewall rules',
            'Enable intrusion detection'
        ],
        affectedServices: ['SSH', 'HTTPS', 'Telnet', 'FTP']
    };
}

function getProgressMessage(progress) {
    const messages = [
        'Initializing scan...',
        'Checking common ports...',
        'Scanning service versions...',
        'Analyzing SSL/TLS configuration...',
        'Checking for known vulnerabilities...',
        'Running CVE database checks...',
        'Analyzing network configuration...',
        'Generating risk assessment...',
        'Finalizing report...',
        'Scan completed!'
    ];
    
    const index = Math.floor((progress / 100) * (messages.length - 1));
    return messages[index];
}
