/**
 * Report Viewer Logic
 */

const API_BASE = 'http://localhost:5000/api';
let currentToken = null;
let currentScanId = null;
let currentScanData = null;
let currentUser = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    checkAuthentication();
    setupEventListeners();
    loadReportData();
});

// Check if user is authenticated
function checkAuthentication() {
    currentToken = localStorage.getItem('token');
    const userData = localStorage.getItem('user');

    if (!currentToken || !userData) {
        window.location.href = 'auth.html';
        return;
    }

    currentUser = JSON.parse(userData);
    document.getElementById('usernameDisplay').textContent = currentUser.username;
}

// Get scanId from URL query parameter
function getScanIdFromUrl() {
    const params = new URLSearchParams(window.location.search);
    return params.get('scanId');
}

// Setup event listeners
function setupEventListeners() {
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('printBtn').addEventListener('click', printReport);
    document.getElementById('downloadPdfBtn').addEventListener('click', downloadReportPdf);
}

// Load report data
async function loadReportData() {
    currentScanId = getScanIdFromUrl();

    if (!currentScanId) {
        showError('No scan ID provided');
        return;
    }

    try {
        showLoading(true);
        console.log(`Loading scan report for: ${currentScanId}`);

        const response = await fetch(`${API_BASE}/scans/${currentScanId}/results`, {
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });

        console.log(`Response status: ${response.status}`);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            console.error('API Error:', errorData);
            
            if (response.status === 404) {
                throw new Error('Scan not found. It may have been deleted or the ID is incorrect.');
            } else if (response.status === 403) {
                throw new Error('You do not have permission to view this scan.');
            } else {
                throw new Error(errorData.error || `Failed to load scan results (Status: ${response.status})`);
            }
        }

        const data = await response.json();
        console.log('Scan data loaded:', data);

        // Try to enrich with risk assessment
        const riskData = await fetchRiskData(currentScanId);
        if (riskData) {
            data.risk_score = riskData.score;
            data.risk_level = riskData.level;
            data.risk_reasoning = riskData.reasoning;
            data.risk_recommendations = riskData.recommendations;
        }

        currentScanData = data;
        renderReport(data);

    } catch (error) {
        console.error('Error loading report:', error);
        showError('Failed to load report: ' + error.message);
    } finally {
        showLoading(false);
    }
}

// Render the report HTML
function renderReport(data) {
    try {
        const content = document.getElementById('reportContent');
        const loadingMessage = document.getElementById('loadingMessage');
        if (loadingMessage) {
            loadingMessage.remove();
        }

        console.log('Rendering report with data:', data);

        const riskScoreRaw = data.risk_score || data.riskScore || 0;
        const riskScore = isNaN(parseFloat(riskScoreRaw)) ? 0 : Math.max(0, Math.min(100, parseFloat(riskScoreRaw)));
        const riskLevel = normalizeRiskLevel(data.risk_level) || getRiskLevel(riskScore);
        const riskClass = getRiskClass(riskScore);
        const vulns = data.vulnerabilities || [];
        
        console.log(`Risk Score: ${riskScore}, Level: ${riskLevel}, Vulnerabilities: ${vulns.length}`);
        
        const sevCounts = {
            critical: vulns.filter(v => (v.severity || '').toLowerCase() === 'critical').length,
            high: vulns.filter(v => (v.severity || '').toLowerCase() === 'high').length,
            medium: vulns.filter(v => (v.severity || '').toLowerCase() === 'medium').length,
            low: vulns.filter(v => (v.severity || '').toLowerCase() === 'low').length,
            info: vulns.filter(v => (v.severity || '').toLowerCase() === 'info').length
        };

        const recommendations = vulns
            .map(v => v.remediation)
            .filter(Boolean)
            .slice(0, 4);

        const riskPercent = Math.max(0, Math.min(100, Math.round(riskScore)));

        let html = `
            <div class="report-hero">
                <div class="hero-left">
                    <div class="brand-mark">
                        <img src="assets/logo.svg" alt="VulneraAI" />
                        <div class="brand-text">
                            <span class="brand-name">VulneraAI</span>
                            <span class="brand-tag">Security Assessment</span>
                        </div>
                    </div>
                    <h1 class="report-title">Vulnerability Scan Report</h1>
                    <p class="report-subtitle">Prepared by VulneraAI Security Team</p>
                </div>
                <div class="hero-right">
                    <div class="hero-chip risk-${riskClass}">${riskLevel} Risk</div>
                    <div class="hero-meta">Scan ID: ${escapeHtml(currentScanId)}</div>
                    <div class="hero-meta">Prepared for: ${escapeHtml(currentUser?.username || 'Authenticated User')}</div>
                </div>
            </div>

            <div class="report-meta-grid">
                <div class="meta-card">
                    <span class="meta-label">Target</span>
                    <span class="meta-value">${escapeHtml(data.target)}</span>
                </div>
                <div class="meta-card">
                    <span class="meta-label">Scan Date</span>
                    <span class="meta-value">${formatDate(data.completedAt || new Date().toISOString())}</span>
                </div>
                <div class="meta-card">
                    <span class="meta-label">Total Findings</span>
                    <span class="meta-value">${vulns.length}</span>
                </div>
                <div class="meta-card">
                    <span class="meta-label">Assessor</span>
                    <span class="meta-value">VulneraAI Automated Scanner</span>
                </div>
            </div>

            <div class="risk-summary">
                <div class="risk-score">
                    <div class="risk-gauge ${riskClass}" style="--score:${riskPercent};">${riskPercent}</div>
                    <div>
                        <div class="risk-label">Overall Risk</div>
                        <div class="risk-level-text">${riskLevel}</div>
                        <p class="risk-copy">${data.risk_reasoning || getRiskDescription(riskScore)}</p>
                    </div>
                </div>
                <div class="severity-grid">
                    <div class="sev-card critical">
                        <div class="sev-label">Critical</div>
                        <div class="sev-value">${sevCounts.critical}</div>
                    </div>
                    <div class="sev-card high">
                        <div class="sev-label">High</div>
                        <div class="sev-value">${sevCounts.high}</div>
                    </div>
                    <div class="sev-card medium">
                        <div class="sev-label">Medium</div>
                        <div class="sev-value">${sevCounts.medium}</div>
                    </div>
                    <div class="sev-card low">
                        <div class="sev-label">Low</div>
                        <div class="sev-value">${sevCounts.low}</div>
                    </div>
                <div class="sev-card info">
                    <div class="sev-label">Info</div>
                    <div class="sev-value">${sevCounts.info}</div>
                </div>
            </div>
        </div>

        <div class="recommendations">
            <div class="report-section-title">Top Recommendations</div>
            <ul class="rec-list">
                ${recommendations.length ? recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('') : '<li>Implement secure configuration baselines and retest.</li><li>Ensure timely patching of exposed services.</li><li>Harden network access with least privilege rules.</li>'}
            </ul>
        </div>
    `;

    // Vulnerabilities section
    html += '<div class="report-section">';
    html += '<h2 class="report-section-title">Detailed Findings</h2>';

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        html += `
            <div class="no-vulnerabilities">
                <div class="no-vulnerabilities-icon">✓</div>
                <h3>No Vulnerabilities Found</h3>
                <p>This scan did not identify any security vulnerabilities.</p>
            </div>
        `;
    } else {
        html += '<div class="vulnerabilities-list">';
        data.vulnerabilities.forEach((vuln, index) => {
            const sevClass = (vuln.severity || '').toLowerCase();
            html += `
                <div class="vuln-card ${sevClass}">
                    <div class="vuln-header">
                        <h3 class="vuln-title">${index + 1}. ${escapeHtml(vuln.title || 'Unknown Vulnerability')}</h3>
                        <span class="severity-badge ${sevClass}">${vuln.severity || 'Unknown'}</span>
                    </div>
                    <p class="vuln-description">${escapeHtml(vuln.description || 'No description provided')}</p>
                    
                    <div class="vuln-details">
                        <div class="detail-item">
                            <span class="detail-label">Port</span>
                            <span class="detail-value">${vuln.port || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Service</span>
                            <span class="detail-value">${escapeHtml(vuln.service || 'Unknown')}</span>
                        </div>
                        ${vuln.cve ? `
                        <div class="detail-item">
                            <span class="detail-label">CVE ID</span>
                            <span class="detail-value">${escapeHtml(vuln.cve)}</span>
                        </div>
                        ` : ''}
                    </div>

                    ${vuln.remediation ? `
                    <div class="remediation-section">
                        <div class="remediation-label">Remediation Steps</div>
                        <div class="remediation-text">${escapeHtml(vuln.remediation)}</div>
                    </div>
                    ` : ''}
                </div>
            `;
        });
        html += '</div>';
    }

    html += '</div>';

    // Footer
    html += `
        <div class="report-footer">
            <div class="footer-brand">
                <img src="assets/logo.svg" alt="VulneraAI" />
                <div>
                    <div class="footer-title">VulneraAI Security Assessment</div>
                    <div class="footer-meta">Prepared on ${new Date().toLocaleString()} | Confidential</div>
                </div>
            </div>
            <p>This report contains sensitive security information. Handle with care.</p>
        </div>
    `;

    content.innerHTML = html;
    } catch (error) {
        console.error('Error rendering report:', error);
        showError('Failed to render report. Please check browser console for details.');
    }
}

// Download report as PDF
async function downloadReportPdf() {
    try {
        showLoading(true);

        const response = await fetch(`${API_BASE}/reports/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({ scanId: currentScanId, format: 'pdf' })
        });

        if (!response.ok) {
            throw new Error('Failed to generate PDF');
        }

        const blob = await response.blob();
        const disposition = response.headers.get('Content-Disposition') || '';
        let filename = `scan-report-${currentScanId}.pdf`;
        const match = disposition.match(/filename="?([^";]+)"?/i);
        if (match && match[1]) filename = match[1];

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);

        showNotification('PDF downloaded successfully', 'success');

    } catch (error) {
        console.error('Error downloading PDF:', error);
        showNotification('Failed to download PDF', 'error');
    } finally {
        showLoading(false);
    }
}

// Print report
function printReport() {
    window.print();
}

// Utility functions
function getRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Info';
}

// Normalize backend risk_level strings to display labels
function normalizeRiskLevel(level) {
    if (!level) return null;
    const normalized = level.toString().toUpperCase();
    const map = {
        'CRITICAL': 'Critical',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low',
        'MINIMAL': 'Info',
        'INFO': 'Info'
    };
    return map[normalized] || null;
}

function getRiskClass(score) {
    const level = getRiskLevel(score);
    return level.toLowerCase();
}

function getRiskDescription(score) {
    const level = getRiskLevel(score);
    const descriptions = {
        'critical': 'Immediate action required. Critical vulnerabilities pose severe security risks and should be remediated immediately.',
        'high': 'High priority. These vulnerabilities could allow attackers to compromise system security. Address within days.',
        'medium': 'Should be addressed. These issues may lead to unauthorized access or data exposure under certain conditions.',
        'low': 'Lower priority. These vulnerabilities have limited impact but should still be remediated to improve security posture.',
        'info': 'Informational findings that do not pose direct security risks but may be useful for security awareness.'
    };
    return descriptions[level.toLowerCase()] || 'Unknown risk level';
}

function getSeverityClass(value) {
    return value > 0 ? 'critical' : 'low';
}

function formatDate(dateString) {
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return dateString;
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showLoading(show) {
    const spinner = document.getElementById('loadingSpinner');
    if (show) {
        spinner.classList.add('show');
    } else {
        spinner.classList.remove('show');
    }
}

function showError(message) {
    const content = document.getElementById('reportContent');
    content.innerHTML = `
        <div style="text-align: center; padding: 60px 20px; color: #d32f2f;">
            <h2>Error Loading Report</h2>
            <p>${escapeHtml(message)}</p>
            <a href="dashboard.html" class="btn btn-primary" style="margin-top: 20px;">← Back to Dashboard</a>
        </div>
    `;
}

// Fetch risk data from backend
async function fetchRiskData(scanId) {
    try {
        const res = await fetch(`${API_BASE}/risk/${scanId}`, {
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });

        if (!res.ok) return null;
        return await res.json();
    } catch (e) {
        console.error('Risk fetch failed', e);
        return null;
    }
}

function showNotification(message, type) {
    // Create a simple toast notification
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'success' ? '#4caf50' : '#d32f2f'};
        color: white;
        border-radius: 4px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'auth.html';
}

// Add slide animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(400px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(400px); opacity: 0; }
    }
`;
document.head.appendChild(style);
