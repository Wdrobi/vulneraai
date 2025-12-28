// ====================================
// VulneraAI - Utility Functions
// ====================================

// ====================================
// Validation Functions
// ====================================

function isValidIP(ip) {
    // IPv4 validation
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    if (ipv4Regex.test(ip)) {
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }

    // IPv6 validation (comprehensive pattern)
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    return ipv6Regex.test(ip);
}

function isValidDomain(domain) {
    // Remove protocol if present
    domain = domain.replace(/^(https?:\/\/)?(www\.)?/, '');
    
    // Remove trailing slash
    domain = domain.replace(/\/$/, '');
    
    // Domain regex that supports subdomains
    // Allows: example.com, sub.example.com, sub.sub.example.com
    // Must end with valid TLD (2-6 characters)
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}$/i;
    
    // Check basic format
    if (!domainRegex.test(domain)) {
        return false;
    }
    
    // Check total length
    if (domain.length > 253) {
        return false;
    }
    
    // Check each label length (max 63 characters per label)
    const labels = domain.split('.');
    return labels.every(label => label.length <= 63 && label.length > 0);
}

function isValidTarget(target) {
    target = target.trim();
    
    // Empty check
    if (!target || target.length === 0) {
        return false;
    }
    
    // Remove http/https protocol if present
    const cleanTarget = target.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
    
    return isValidIP(cleanTarget) || isValidDomain(cleanTarget);
}

function getTargetType(target) {
    target = target.trim();
    const cleanTarget = target.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
    
    if (isValidIP(cleanTarget)) {
        return cleanTarget.includes(':') ? 'IPv6' : 'IPv4';
    } else if (isValidDomain(cleanTarget)) {
        const labels = cleanTarget.split('.');
        return labels.length > 2 ? 'Subdomain' : 'Domain';
    }
    return 'Invalid';
}

// ====================================
// Severity Color Functions
// ====================================

function getSeverityColor(severity) {
    const colors = {
        critical: '#ff3838',
        high: '#ff006e',
        medium: '#ff9500',
        low: '#06a77d'
    };
    return colors[severity.toLowerCase()] || '#808099';
}

function getSeverityClass(severity) {
    return severity.toLowerCase();
}

// ====================================
// Format Functions
// ====================================

function formatDate(date) {
    if (typeof date === 'string') {
        date = new Date(date);
    }
    
    const options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    };
    
    return date.toLocaleDateString('en-US', options);
}

function formatTime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function formatDuration(startTime, endTime) {
    if (typeof startTime === 'string') {
        startTime = new Date(startTime);
    }
    if (typeof endTime === 'string') {
        endTime = new Date(endTime);
    }
    
    const seconds = Math.floor((endTime - startTime) / 1000);
    return formatTime(seconds);
}

// ====================================
// Risk Score Functions
// ====================================

function getRiskLevel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'MINIMAL';
}

function getRiskDescription(score) {
    const level = getRiskLevel(score);
    const descriptions = {
        'CRITICAL': 'Immediate action required. Critical vulnerabilities pose severe security risks.',
        'HIGH': 'Urgent remediation needed. High-risk vulnerabilities should be addressed quickly.',
        'MEDIUM': 'Plan remediation. Medium-risk issues should be addressed in the near term.',
        'LOW': 'Monitor and document. Low-risk issues may be addressed in regular maintenance.',
        'MINIMAL': 'No significant vulnerabilities detected. Continue monitoring.'
    };
    return descriptions[level];
}

// ====================================
// Progress Timer
// ====================================

class ProgressTimer {
    constructor(displayElement) {
        this.displayElement = displayElement;
        this.startTime = Date.now();
        this.timerInterval = null;
    }

    start() {
        this.startTime = Date.now();
        this.timerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            this.displayElement.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }, 1000);
    }

    stop() {
        if (this.timerInterval) {
            clearInterval(this.timerInterval);
        }
    }

    reset() {
        this.stop();
        this.displayElement.textContent = '00:00';
    }
}

// ====================================
// Local Storage Management
// ====================================

const storage = {
    saveReport: function(report) {
        const reports = this.getAllReports();
        reports.unshift(report);
        localStorage.setItem('vulneraai_reports', JSON.stringify(reports.slice(0, 50))); // Keep last 50
    },

    getAllReports: function() {
        const data = localStorage.getItem('vulneraai_reports');
        return data ? JSON.parse(data) : [];
    },

    getReport: function(scanId) {
        const reports = this.getAllReports();
        return reports.find(r => r.scanId === scanId);
    },

    deleteReport: function(scanId) {
        const reports = this.getAllReports();
        const filtered = reports.filter(r => r.scanId !== scanId);
        localStorage.setItem('vulneraai_reports', JSON.stringify(filtered));
    },

    clearAll: function() {
        localStorage.removeItem('vulneraai_reports');
    }
};

// ====================================
// DOM Utilities
// ====================================

function showElement(element) {
    if (typeof element === 'string') {
        element = document.getElementById(element);
    }
    if (element) {
        element.style.display = 'block';
    }
}

function hideElement(element) {
    if (typeof element === 'string') {
        element = document.getElementById(element);
    }
    if (element) {
        element.style.display = 'none';
    }
}

function toggleElement(element) {
    if (typeof element === 'string') {
        element = document.getElementById(element);
    }
    if (element) {
        element.style.display = element.style.display === 'none' ? 'block' : 'none';
    }
}

// ====================================
// PDF Generation Helper
// ====================================

function generatePDFContent(results, riskScore) {
    let content = '';
    content += `VulneraAI - Vulnerability Scan Report\n`;
    content += `${'='.repeat(50)}\n\n`;
    
    content += `Target: ${results.target}\n`;
    content += `Scan Date: ${formatDate(results.completedAt)}\n`;
    content += `Risk Score: ${riskScore.score}/100 (${riskScore.level})\n\n`;
    
    content += `VULNERABILITIES FOUND: ${results.vulnerabilities.length}\n`;
    content += `${'─'.repeat(50)}\n`;
    
    results.vulnerabilities.forEach((vuln, index) => {
        content += `\n${index + 1}. ${vuln.title}\n`;
        content += `   Severity: ${vuln.severity.toUpperCase()}\n`;
        content += `   Port: ${vuln.port} (${vuln.service})\n`;
        content += `   Description: ${vuln.description}\n`;
        if (vuln.cve) {
            content += `   CVE: ${vuln.cve}\n`;
        }
        content += `   Remediation: ${vuln.remediation}\n`;
    });
    
    content += `\n\nRISK ASSESSMENT\n`;
    content += `${'─'.repeat(50)}\n`;
    content += `Overall Score: ${riskScore.score}/100\n`;
    content += `Risk Level: ${riskScore.level}\n`;
    content += `Reasoning: ${riskScore.reasoning}\n\n`;
    
    content += `RECOMMENDATIONS:\n`;
    riskScore.recommendations.forEach((rec, index) => {
        content += `${index + 1}. ${rec}\n`;
    });
    
    return content;
}

// ====================================
// CSV Generation Helper
// ====================================

function generateCSVContent(results) {
    let csv = 'Title,Severity,Port,Service,CVE,Description,Remediation\n';
    
    results.vulnerabilities.forEach(vuln => {
        const escaped = (str) => `"${(str || '').replace(/"/g, '""')}"`;
        csv += `${escaped(vuln.title)},${escaped(vuln.severity)},${escaped(vuln.port)},${escaped(vuln.service)},${escaped(vuln.cve)},${escaped(vuln.description)},${escaped(vuln.remediation)}\n`;
    });
    
    return csv;
}

// ====================================
// File Download Helper
// ====================================

function downloadFile(content, filename, contentType = 'text/plain') {
    const element = document.createElement('a');
    element.setAttribute('href', `data:${contentType};charset=utf-8,${encodeURIComponent(content)}`);
    element.setAttribute('download', filename);
    element.style.display = 'none';
    
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

// ====================================
// Animation Utilities
// ====================================

function animateValue(element, start, end, duration = 1000) {
    const range = end - start;
    const increment = range / (duration / 16); // 60fps
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            current = end;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current);
    }, 16);
}

// ====================================
// Status Messages
// ====================================

function showNotification(message, type = 'info', duration = 3000) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Add notification CSS if not already present
    if (!document.getElementById('notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .notification {
                position: fixed;
                bottom: 20px;
                right: 20px;
                padding: 15px 20px;
                border-radius: 8px;
                background: rgba(20, 30, 60, 0.9);
                border-left: 4px solid;
                color: #e0e0ff;
                z-index: 10000;
                animation: slideIn 0.3s ease;
                max-width: 300px;
            }
            
            .notification-info {
                border-left-color: #00d9ff;
            }
            
            .notification-success {
                border-left-color: #06a77d;
            }
            
            .notification-warning {
                border-left-color: #ff9500;
            }
            
            .notification-error {
                border-left-color: #ff3838;
            }
            
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, duration);
}
