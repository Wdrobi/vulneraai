/**
 * Dashboard Logic
 */

const API_BASE = 'http://localhost:5000/api';
let currentUser = null;
let currentToken = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    checkAuthentication();
    setupEventListeners();
    loadDashboardData();
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
    updateUserDisplay();
}

// Update user display
function updateUserDisplay() {
    document.getElementById('usernameDisplay').textContent = currentUser.username;
    document.getElementById('profileUsername').textContent = currentUser.username;
    document.getElementById('profileEmail').textContent = currentUser.email;

    const createdDate = new Date(currentUser.created_at).toLocaleDateString();
    document.getElementById('profileCreated').textContent = `Joined ${createdDate}`;
}

// Setup event listeners
function setupEventListeners() {
    // Tab navigation - only for internal sections
    document.querySelectorAll('.nav-link[data-section]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = e.target.dataset.section;
            switchSection(section);
        });
    });

    // Logout
    document.getElementById('logoutBtn').addEventListener('click', logout);

    // Profile actions
    document.getElementById('changePasswordBtn').addEventListener('click', () => {
        alert('Password change feature coming soon');
    });

    document.getElementById('deleteAccountBtn').addEventListener('click', () => {
        if (confirm('Are you sure you want to delete your account? This cannot be undone.')) {
            alert('Account deletion feature coming soon');
        }
    });
}

// Switch section
function switchSection(sectionName) {
    // Update nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-section="${sectionName}"]`).classList.add('active');

    // Update sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(`${sectionName}-section`).classList.add('active');

    // Load profile data when switching to profile
    if (sectionName === 'profile') {
        loadProfileData();
    }
}

// Load dashboard data
async function loadDashboardData() {
    await loadScanHistory();
}

// Load scan history
async function loadScanHistory() {
    const tbody = document.getElementById('scanTableBody');
    const emptyState = document.getElementById('emptyScanState');

    try {
        const response = await fetch(`${API_BASE}/reports/history?limit=50`, {
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });

        if (!response.ok) throw new Error('Failed to load scan history');

        const scans = await response.json();

        if (!scans || scans.length === 0) {
            tbody.innerHTML = '';
            emptyState.style.display = 'block';
            document.getElementById('scanTable').style.display = 'none';
            return;
        }

        emptyState.style.display = 'none';
        document.getElementById('scanTable').style.display = 'table';
        tbody.innerHTML = '';

        scans.forEach(scan => {
            const row = document.createElement('tr');
            const statusClass = scan.status === 'Completed' ? 'status-completed' : (scan.status === 'Running' ? 'status-running' : 'status-pending');
            const riskClass = getRiskClass(scan.riskScore);

            row.innerHTML = `
                <td><strong>${escapeHtml(scan.target)}</strong></td>
                <td><span class="status-badge ${statusClass}">${scan.status}</span></td>
                <td><span class="risk-badge ${riskClass}">${scan.riskScore}</span></td>
                <td>${scan.vulnerabilityCount}</td>
                <td>${formatDate(scan.completedAt)}</td>
                <td>
                    <div class="action-buttons">
                        <button class="action-btn" onclick="viewScanDetails('${scan.scanId}')">View</button>
                        <button class="action-btn" onclick="downloadReport('${scan.scanId}')">Download</button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        updateStats(scans);
    } catch (err) {
        console.error('Error loading scan history:', err);
        tbody.innerHTML = '<tr><td colspan="6">Failed to load scans</td></tr>';
    }
}

// Update stats
function updateStats(scans) {
    document.getElementById('totalScans').textContent = scans.length;
    document.getElementById('profileTotalScans').textContent = scans.length;

    if (scans.length > 0) {
        const avgRisk = Math.round(
            scans.reduce((sum, s) => sum + s.riskScore, 0) / scans.length
        );
        document.getElementById('avgRiskScore').textContent = avgRisk;

        const highCount = scans.filter(s => s.riskScore >= 70).length;
        document.getElementById('highVulns').textContent = highCount;

        // Account age
        const createdDate = new Date(currentUser.created_at);
        const now = new Date();
        const daysOld = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
        document.getElementById('profileAccountAge').textContent = `${daysOld}d`;
    }
}

// Load profile data
function loadProfileData() {
    document.getElementById('profileUsername').textContent = currentUser.username;
    document.getElementById('profileEmail').textContent = currentUser.email;

    const createdDate = new Date(currentUser.created_at);
    const createdFormatted = createdDate.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
    document.getElementById('profileCreated').textContent = `Joined ${createdFormatted}`;
}

// View scan details
function viewScanDetails(scanId) {
    // Navigate to the report page with the scan ID
    window.location.href = `report.html?scanId=${scanId}`;
}

// Download report (PDF)
async function downloadReport(scanId) {
    try {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('Not authenticated');

        const res = await fetch('http://127.0.0.1:5000/api/reports/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ scanId, format: 'pdf' })
        });

        if (!res.ok) throw new Error('Failed to generate report');

        const blob = await res.blob();
        const disposition = res.headers.get('Content-Disposition') || '';
        let filename = `scan-report-${scanId}.pdf`;
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
    } catch (error) {
        console.error('Error downloading report:', error);
        alert('Failed to download report');
    }
}

// Modal functions (no longer used, keeping for backward compatibility)
function openModal() {
    // Redirects to report page now
}

function closeModal() {
    // Redirects to report page now
}

// Logout
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'auth.html';
}

// Utility functions
function showLoading(show) {
    if (show) {
        document.getElementById('loadingSpinner').classList.add('show');
    } else {
        document.getElementById('loadingSpinner').classList.remove('show');
    }
}

function getRiskClass(score) {
    if (score >= 80) return 'risk-critical';
    if (score >= 60) return 'risk-high';
    if (score >= 40) return 'risk-medium';
    return 'risk-low';
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
