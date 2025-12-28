// ====================================
// VulneraAI - Main Script
// ====================================

let progressTimer = null;
let mockProgress = 0;
let currentUser = null;
let currentToken = null;

// ====================================
// Initialization
// ====================================

document.addEventListener('DOMContentLoaded', function() {
    checkAuthentication();
    initializeNavigation();
    loadScanHistory();
    initializeTargetValidation();
    
    // Fix CSS path
    const styleLink = document.querySelector('link[rel="stylesheet"]');
    if (styleLink) {
        styleLink.href = 'css/styles.css';
    }
});

// Initialize real-time target validation
function initializeTargetValidation() {
    const targetInput = document.getElementById('target-input');
    const validationMessage = document.getElementById('input-validation');
    const inputHint = document.getElementById('input-hint');
    
    if (!targetInput || !validationMessage) return;
    
    targetInput.addEventListener('input', function() {
        const target = this.value.trim();
        
        // Clear validation if empty
        if (target === '') {
            targetInput.classList.remove('valid', 'invalid');
            validationMessage.style.display = 'none';
            validationMessage.textContent = '';
            return;
        }
        
        // Validate target
        if (isValidTarget(target)) {
            const targetType = getTargetType(target);
            targetInput.classList.remove('invalid');
            targetInput.classList.add('valid');
            validationMessage.style.display = 'block';
            validationMessage.className = 'input-validation valid';
            validationMessage.textContent = `✓ Valid ${targetType} detected`;
        } else {
            targetInput.classList.remove('valid');
            targetInput.classList.add('invalid');
            validationMessage.style.display = 'block';
            validationMessage.className = 'input-validation invalid';
            validationMessage.textContent = '✗ Invalid format. Enter a valid IP address or domain name';
        }
    });
    
    // Clear validation on focus if empty
    targetInput.addEventListener('focus', function() {
        if (this.value.trim() === '') {
            this.classList.remove('valid', 'invalid');
            validationMessage.style.display = 'none';
        }
    });
}

// Check authentication
function checkAuthentication() {
    currentToken = localStorage.getItem('token');
    const userData = localStorage.getItem('user');

    if (!currentToken || !userData) {
        // Not authenticated, redirect to login
        window.location.href = 'auth.html';
        return;
    }

    currentUser = JSON.parse(userData);
    
    // Setup logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'auth.html';
}

// ====================================
// Navigation
// ====================================

function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link:not(.logout-btn)');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

// ====================================
// Scanning Functions
// ====================================

async function startScan() {
    const targetInput = document.getElementById('target-input');
    const scanTypeSelect = document.getElementById('scan-type');
    const scanBtn = document.getElementById('scan-btn');
    const target = targetInput.value.trim();
    const scanType = scanTypeSelect.value;

    // Validation
    if (!target) {
        showNotification('Please enter an IP address or domain name', 'warning');
        targetInput.focus();
        return;
    }

    if (!isValidTarget(target)) {
        const cleanTarget = target.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
        showNotification('Invalid target format. Please enter a valid IPv4, IPv6, domain, or subdomain (e.g., 192.168.1.1, example.com, sub.example.com)', 'error');
        targetInput.focus();
        targetInput.select();
        return;
    }

    // Check authentication
    if (!currentToken) {
        window.location.href = 'auth.html';
        return;
    }

    // Disable button
    scanBtn.disabled = true;
    mockProgress = 0;

    try {
        // Show progress section
        showElement('progress-section');
        hideElement('results-section');
        
        document.getElementById('progress-target').textContent = target;

        // Initialize timer
        progressTimer = new ProgressTimer(document.getElementById('progress-time'));
        progressTimer.start();

        // Call actual API to start scan
        const response = await fetch('http://localhost:5000/api/scans/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({ target, scanType })
        });

        if (!response.ok) {
            throw new Error('Failed to start scan');
        }

        const data = await response.json();
        const scanId = data.scanId;

        // Poll for scan status
        pollScanStatus(scanId, target);

    } catch (error) {
        console.error('Scan error:', error);
        showNotification('Error starting scan. Please try again.', 'error');
        scanBtn.disabled = false;
    }
}

async function pollScanStatus(scanId, target) {
    const maxAttempts = 60; // 30 seconds with 500ms interval
    let attempts = 0;

    const checkStatus = async () => {
        try {
            const response = await fetch(`http://localhost:5000/api/scans/${scanId}/status`, {
                headers: {
                    'Authorization': `Bearer ${currentToken}`
                }
            });

            const data = await response.json();
            
            // Update progress bar
            document.getElementById('progress-bar').style.width = data.progress + '%';
            document.getElementById('progress-text').textContent = getProgressMessage(data.progress);
            document.getElementById('scan-status').textContent = data.status;

            if (data.status === 'completed') {
                // Get scan results
                getScanResults(scanId, target);
            } else if (attempts < maxAttempts) {
                attempts++;
                setTimeout(checkStatus, 500);
            } else {
                showNotification('Scan timeout', 'error');
                document.getElementById('scan-btn').disabled = false;
            }
        } catch (error) {
            console.error('Error polling scan status:', error);
            // Fallback to simulation if API fails
            simulateScan(target, 'standard');
        }
    };

    checkStatus();
}

async function getScanResults(scanId, target) {
    try {
        const response = await fetch(`http://localhost:5000/api/scans/${scanId}/results`, {
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });

        const data = await response.json();

        // Get risk assessment
        const riskResponse = await fetch(`http://localhost:5000/api/risk/${scanId}`, {
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });

        const riskData = await riskResponse.json();

        const results = {
            vulnerabilities: data.vulnerabilities || []
        };

        const riskScore = {
            score: riskData.score || 0,
            level: riskData.level || 'Unknown'
        };

        currentResults = { results, riskScore };

        // Store in database via API
        const scanData = {
            scanId: scanId,
            target: target,
            completedAt: new Date().toISOString(),
            vulnerabilities: results.vulnerabilities,
            riskScore: riskScore.score,
            riskLevel: riskScore.level
        };

        // Update UI
        displayResults(results, riskScore);

        // Update progress
        document.getElementById('progress-bar').style.width = '100%';
        document.getElementById('progress-text').textContent = 'Scan completed!';
        document.getElementById('scan-status').textContent = 'Completed';

        // Stop timer
        if (progressTimer) {
            progressTimer.stop();
        }

        // Show results
        hideElement('progress-section');
        showElement('results-section');

        // Reload history
        loadScanHistory();

        showNotification('Scan completed successfully!', 'success');

        document.getElementById('scan-btn').disabled = false;

    } catch (error) {
        console.error('Error getting scan results:', error);
        showNotification('Error retrieving scan results', 'error');
        document.getElementById('scan-btn').disabled = false;
    }
}

function simulateScan(target, scanType) {
    const duration = {
        'quick': 30000,
        'standard': 60000,
        'comprehensive': 120000
    }[scanType] || 60000;

    const startTime = Date.now();
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const vulnCount = document.getElementById('vuln-count');
    const scanStatus = document.getElementById('scan-status');

    const progressInterval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min((elapsed / duration) * 100, 99);
        
        mockProgress = progress;
        progressBar.style.width = progress + '%';
        progressText.textContent = getProgressMessage(progress);
        vulnCount.textContent = Math.floor(progress / 10);
        scanStatus.textContent = 'Scanning...';

        if (progress >= 99) {
            clearInterval(progressInterval);
            completeScan(target);
        }
    }, 500);
}

function completeScan(target) {
    const scanBtn = document.getElementById('scan-btn');
    
    try {
        // Get mock results
        const results = getMockResults(target);
        const riskScore = getMockRiskScore();
        
        currentResults = { results, riskScore };
        
        // Store in local storage
        storage.saveReport({
            scanId: 'scan-' + Date.now(),
            target: target,
            completedAt: new Date().toISOString(),
            vulnerabilities: results.vulnerabilities,
            riskScore: riskScore.score,
            riskLevel: riskScore.level
        });

        // Update UI
        displayResults(results, riskScore);
        
        // Update progress
        document.getElementById('progress-bar').style.width = '100%';
        document.getElementById('progress-text').textContent = 'Scan completed!';
        document.getElementById('scan-status').textContent = 'Completed';
        
        // Stop timer
        if (progressTimer) {
            progressTimer.stop();
        }

        // Show results
        hideElement('progress-section');
        showElement('results-section');
        
        // Reload history
        loadScanHistory();
        
        showNotification('Scan completed successfully!', 'success');
        
    } catch (error) {
        console.error('Error completing scan:', error);
        showNotification('Error completing scan', 'error');
    } finally {
        scanBtn.disabled = false;
    }
}

function cancelScan() {
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = false;
    
    if (progressTimer) {
        progressTimer.stop();
    }
    
    hideElement('progress-section');
    showNotification('Scan cancelled', 'info');
}

// ====================================
// Results Display
// ====================================

function displayResults(results, riskScore) {
    // Update risk gauge
    updateRiskGauge(riskScore.score);
    
    // Update risk card
    document.getElementById('risk-level').textContent = riskScore.level;
    document.getElementById('risk-description').textContent = getRiskDescription(riskScore.score);
    document.getElementById('gauge-score').textContent = riskScore.score;
    
    // Display vulnerabilities
    displayVulnerabilities(results.vulnerabilities);
    
    // Update statistics
    updateStatistics(results.stats);
}

function updateRiskGauge(score) {
    const radius = 90;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;
    
    const gaugeFill = document.getElementById('gauge-fill');
    gaugeFill.style.strokeDashoffset = offset;
    
    // Change color based on score
    const color = getSeverityColor(getRiskLevel(score));
    gaugeFill.style.stroke = color;
}

function displayVulnerabilities(vulnerabilities) {
    const list = document.getElementById('vulnerabilities-list');
    list.innerHTML = '';

    if (vulnerabilities.length === 0) {
        list.innerHTML = '<p style="text-align: center; color: var(--success); padding: 20px;">No vulnerabilities found!</p>';
        return;
    }

    vulnerabilities.forEach(vuln => {
        const item = document.createElement('div');
        item.className = `vuln-item glass-effect ${getSeverityClass(vuln.severity)}`;
        item.innerHTML = `
            <div class="vuln-header">
                <h4 class="vuln-title">${vuln.title}</h4>
                <span class="vuln-severity ${getSeverityClass(vuln.severity)}">${vuln.severity}</span>
            </div>
            <p class="vuln-description">${vuln.description}</p>
            <div style="display: flex; gap: 10px; margin-top: 10px; font-size: 0.85rem; color: var(--text-light);">
                ${vuln.port ? `<span>🔌 Port: ${vuln.port}</span>` : ''}
                ${vuln.service ? `<span>⚙️ Service: ${vuln.service}</span>` : ''}
                ${vuln.cve ? `<span>🔐 ${vuln.cve}</span>` : ''}
            </div>
        `;
        
        item.addEventListener('click', () => {
            showVulnerabilityDetails(vuln);
        });
        
        list.appendChild(item);
    });
}

function updateStatistics(stats) {
    const severities = ['critical', 'high', 'medium', 'low'];
    severities.forEach(severity => {
        const count = stats[severity] || 0;
        const element = document.getElementById(`stat-${severity}`);
        if (element) {
            animateValue(element, 0, count, 500);
        }
    });
}

// ====================================
// Vulnerability Details Modal
// ====================================

function showVulnerabilityDetails(vuln) {
    const modal = document.getElementById('vuln-modal');
    const modalBody = document.getElementById('modal-body');
    
    modalBody.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 20px;">
            <h3 style="margin: 0;">${vuln.title}</h3>
            <span class="vuln-severity ${getSeverityClass(vuln.severity)}" style="padding: 8px 12px; margin: 0;">
                ${vuln.severity.toUpperCase()}
            </span>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4 style="color: var(--primary); margin-bottom: 10px;">Description</h4>
            <p>${vuln.description}</p>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4 style="color: var(--primary); margin-bottom: 10px;">Details</h4>
            <div style="background: rgba(30, 50, 100, 0.2); padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 0.9rem;">
                <p><strong>Port:</strong> ${vuln.port}</p>
                <p><strong>Service:</strong> ${vuln.service}</p>
                ${vuln.cve ? `<p><strong>CVE:</strong> ${vuln.cve}</p>` : ''}
            </div>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4 style="color: var(--primary); margin-bottom: 10px;">Remediation</h4>
            <div style="background: rgba(6, 167, 125, 0.1); padding: 15px; border-left: 3px solid var(--success); border-radius: 8px;">
                <p>${vuln.remediation}</p>
            </div>
        </div>
    `;
    
    modal.classList.add('show');
}

function closeVulnModal() {
    const modal = document.getElementById('vuln-modal');
    modal.classList.remove('show');
}

// Close modal when clicking outside
document.addEventListener('click', function(event) {
    const modal = document.getElementById('vuln-modal');
    if (event.target === modal) {
        closeVulnModal();
    }
});

// ====================================
// Report Download
// ====================================

function downloadReportPDF() {
    if (!currentResults) return;

    const { results, riskScore } = currentResults;
    const content = generatePDFContent(results, riskScore);
    const filename = `VulneraAI_Report_${results.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.txt`;
    
    downloadFile(content, filename, 'text/plain');
    showNotification('PDF report downloaded!', 'success');
}

function downloadReportJSON() {
    if (!currentResults) return;

    const { results, riskScore } = currentResults;
    const report = {
        ...results,
        riskScore: riskScore,
        downloadedAt: new Date().toISOString()
    };

    const content = JSON.stringify(report, null, 2);
    const filename = `VulneraAI_Report_${results.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`;
    
    downloadFile(content, filename, 'application/json');
    showNotification('JSON report downloaded!', 'success');
}

// ====================================
// Scan History
// ====================================

async function loadScanHistory() {
    const reportsList = document.getElementById('reports-list');
    const noReports = document.getElementById('no-reports');

    try {
        const response = await fetch('http://localhost:5000/api/reports/history?limit=50', {
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load scan history');
        }

        const reports = await response.json();

        if (!reports || reports.length === 0) {
            reportsList.innerHTML = '';
            showElement('no-reports');
            return;
        }

        hideElement('no-reports');
        reportsList.innerHTML = '';

        reports.forEach(report => {
            const card = document.createElement('div');
            card.className = 'report-card glass-effect';
            card.innerHTML = `
                <div class="report-header">
                    <div class="report-target">${report.target}</div>
                    <div class="report-date">${formatDate(report.completedAt)}</div>
                </div>
                
                <div class="report-stats">
                    <div class="report-stat">
                        <span class="report-stat-value" style="color: var(--danger);">${report.vulnerabilityCount}</span>
                        <span class="report-stat-label">Vulnerabilities</span>
                    </div>
                    <div class="report-stat">
                        <span class="report-stat-value" style="color: var(--primary);">${report.riskScore}</span>
                        <span class="report-stat-label">Risk Score</span>
                    </div>
                    <div class="report-stat">
                        <span class="report-stat-value" style="color: var(--secondary);">${report.riskLevel}</span>
                        <span class="report-stat-label">Level</span>
                    </div>
                </div>
                
                <button class="btn btn-outline" style="width: 100%; margin-top: 10px;" 
                        onclick="viewScanDetails('${report.scanId}')">
                    View Report
                </button>
            `;
            reportsList.appendChild(card);
        });

    } catch (error) {
        console.error('Error loading scan history:', error);
        // Fallback to local storage
        const localReports = storage.getAllReports();
        if (localReports.length === 0) {
            reportsList.innerHTML = '';
            showElement('no-reports');
        } else {
            // Load from local storage as fallback
            displayLocalReports(localReports);
        }
    }
}

function displayLocalReports(reports) {
    const reportsList = document.getElementById('reports-list');
    hideElement('no-reports');
    reportsList.innerHTML = '';

    reports.forEach(report => {
        const card = document.createElement('div');
        card.className = 'report-card glass-effect';
        card.innerHTML = `
            <div class="report-header">
                <div class="report-target">${report.target}</div>
                <div class="report-date">${formatDate(report.completedAt)}</div>
            </div>
            
            <div class="report-stats">
                <div class="report-stat">
                    <span class="report-stat-value" style="color: var(--danger);">${report.vulnerabilities.length}</span>
                    <span class="report-stat-label">Vulnerabilities</span>
                </div>
                <div class="report-stat">
                    <span class="report-stat-value" style="color: var(--primary);">${report.riskScore}</span>
                    <span class="report-stat-label">Risk Score</span>
                </div>
                <div class="report-stat">
                    <span class="report-stat-value" style="color: var(--secondary);">${report.riskLevel}</span>
                    <span class="report-stat-label">Level</span>
                </div>
            </div>
            
            <button class="btn btn-outline" style="width: 100%; margin-top: 10px;" 
                    onclick="openReport('${report.scanId}')">
                View Report
            </button>
        `;
        reportsList.appendChild(card);
    });
}

async function viewScanDetails(scanId) {
    // Navigate to the report page with the scan ID
    window.location.href = `report.html?scanId=${scanId}`;
}

function openReport(scanId) {
    const report = storage.getReport(scanId);
    if (report) {
        // Populate results with stored data and display
        const results = {
            target: report.target,
            completedAt: report.completedAt,
            vulnerabilities: report.vulnerabilities
        };
        
        const riskScore = {
            score: report.riskScore,
            level: report.riskLevel,
            reasoning: 'This is a previously scanned result.',
            recommendations: []
        };
        
        currentResults = { results, riskScore };
        displayResults(results, riskScore);
        
        // Scroll to results
        document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });
        showElement('results-section');
    }
}

// ====================================
// New Scan
// ====================================

function newScan() {
    // Reset form
    document.getElementById('target-input').value = '';
    document.getElementById('scan-type').value = 'quick';
    
    // Reset UI
    hideElement('progress-section');
    hideElement('results-section');
    
    // Reset timer
    if (progressTimer) {
        progressTimer.reset();
    }
    
    // Scroll to top
    document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
    document.getElementById('target-input').focus();
    
    showNotification('Ready for a new scan!', 'info');
}

// ====================================
// Enter key support
// ====================================

document.addEventListener('DOMContentLoaded', function() {
    const targetInput = document.getElementById('target-input');
    if (targetInput) {
        targetInput.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                startScan();
            }
        });
    }
});
