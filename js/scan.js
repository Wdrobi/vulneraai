// js/scan.js

// Adjust this if your API is hosted elsewhere
const API_BASE = 'http://localhost:4000/api';

export function initScan({
  state,
  $,
  showToast,
  validateTarget,
  updateFreeScanCounter,
}) {
  const targetInput = $('targetInput');
  const targetStatus = $('targetStatus');

  function updateTargetStatus() {
    const value = targetInput.value.trim();
    if (!value) {
      targetStatus.textContent = '';
      targetStatus.className = 'scan-status';
      return;
    }
    if (validateTarget(value)) {
      targetStatus.textContent = 'Valid target';
      targetStatus.className = 'scan-status ok';
    } else {
      targetStatus.textContent = 'Invalid format';
      targetStatus.className = 'scan-status error';
    }
  }

  targetInput.addEventListener('input', updateTargetStatus);

  // --- Helpers for risk & UI (same as before) ---
  function summarizeBySeverity(vulns) {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    for (const v of vulns) {
      if (counts[v.severity] != null) counts[v.severity]++;
    }
    return counts;
  }

  function computeRiskScore(vulns) {
    if (!vulns.length) return 0;
    let weighted = 0;
    let maxScore = 0;
    for (const v of vulns) {
      const weight =
        v.severity === 'Critical'
          ? 1.0
          : v.severity === 'High'
          ? 0.8
          : v.severity === 'Medium'
          ? 0.5
          : v.severity === 'Low'
          ? 0.3
          : 0.2;
      weighted += v.score * weight;
      if (v.score > maxScore) maxScore = v.score;
    }
    const normalized = Math.min(
      100,
      Math.round((weighted / (vulns.length * 10)) * 100 + maxScore * 3)
    );
    return normalized;
  }

  function riskBucket(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    if (score > 0) return 'Info';
    return 'No data';
  }

  function riskDescriptionFor(score) {
    const level = riskBucket(score);
    switch (level) {
      case 'Critical':
        return 'The target shows a concentration of exploitable, high-impact weaknesses. Immediate triage and containment are recommended.';
      case 'High':
        return 'The target presents elevated exposure with multiple high-severity findings. Prioritize remediation in the next sprint.';
      case 'Medium':
        return 'Risk is moderate. Address identified misconfigurations and patch gaps to prevent incremental exposure over time.';
      case 'Low':
        return 'Risk is relatively low. Continue routine hardening and monitoring to preserve your current posture.';
      case 'Info':
        return 'Only informational or low-impact findings were observed. Consider additional authenticated coverage for deeper insight.';
      default:
        return 'Once a scan completes, VulneraAI will provide a prioritized view of risk across your attack surface.';
    }
  }

  function updateRiskUI(vulns, riskScoreOverride) {
    const counts = summarizeBySeverity(vulns);
    const score =
      typeof riskScoreOverride === 'number'
        ? riskScoreOverride
        : computeRiskScore(vulns);
    const level = riskBucket(score);

    $('riskScore').textContent = score || '--';
    $('riskLevelLabel').textContent = level;
    $('riskBarIndicator').style.left = Math.min(96, Math.max(0, score)) + '%';
    $('riskDescription').textContent = riskDescriptionFor(score);

    $('riskTotal').textContent = vulns.length;
    $('riskCriticalHigh').textContent =
      (counts.Critical || 0) + (counts.High || 0);

    const baseMttr =
      counts.Critical > 0 || counts.High > 2
        ? 14
        : counts.High > 0 || counts.Medium > 2
        ? 10
        : 5;
    $('riskMttr').textContent = baseMttr + ' days (est.)';

    let color;
    switch (level) {
      case 'Critical':
        color = 'var(--accent-critical)';
        break;
      case 'High':
        color = 'var(--accent-high)';
        break;
      case 'Medium':
        color = 'var(--accent-medium)';
        break;
      case 'Low':
        color = 'var(--accent-low)';
        break;
      case 'Info':
        color = 'var(--accent-info)';
        break;
      default:
        color = 'var(--text-muted)';
    }
    $('riskLevelPill').querySelector('.severity-dot').style.background = color;
    $('riskLevelLabel').style.color = color;
  }

  function renderSeveritySummary(counts) {
    const container = $('severitySummary');
    container.innerHTML = '';
    Object.entries(counts).forEach(([level, count]) => {
      if (!count) return;
      const chip = document.createElement('div');
      chip.className = 'severity-chip';
      chip.dataset.level = level;
      chip.innerHTML =
        '<span class="severity-dot"></span>' +
        `<span>${level}</span>` +
        `<span style="opacity:0.7;">${count}</span>`;
      container.appendChild(chip);
    });
  }

  function renderVulnList(vulns) {
    const list = $('vulnList');
    list.innerHTML = '';
    vulns.forEach((v) => {
      const item = document.createElement('div');
      item.className = 'vuln-item';
      item.innerHTML =
        `<div class="vuln-item-header">` +
        `<div class="vuln-title">${v.title}</div>` +
        `<div class="vuln-severity" data-level="${v.severity}">${v.severity} &middot; ${v.score.toFixed(
          1
        )}</div>` +
        `</div>` +
        `<div class="vuln-desc">${v.description}</div>` +
        `<div class="vuln-rem"><span>REMEDIATION</span>${v.remediation}</div>`;
      list.appendChild(item);
    });
  }

  function updateReportMeta(target, type, vulns, atIso) {
    const reportStatus = $('reportStatus');
    const lastRunMeta = $('lastRunMeta');

    reportStatus.classList.remove('empty');
    const ts = atIso
      ? new Date(atIso).toLocaleString(undefined, {
          hour12: false,
          year: 'numeric',
          month: 'short',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
        })
      : new Date().toLocaleString(undefined, {
          hour12: false,
          year: 'numeric',
          month: 'short',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
        });

    reportStatus.innerHTML =
      '<span style="width:7px;height:7px;border-radius:999px;background:var(--accent-primary);display:inline-block;"></span>' +
      `<span>${type === 'deep' ? 'Deep scan complete' : 'Light scan complete'}</span>`;
    lastRunMeta.textContent = `${ts} • ${type} scan on "${target}" • ${vulns.length} findings`;
  }

  function updateQuickSummary(target, type, vulns, riskScore, severitySummary) {
    const el = $('quickSummary');
    const counts = severitySummary || summarizeBySeverity(vulns);
    const score =
      typeof riskScore === 'number' ? riskScore : computeRiskScore(vulns);
    const level = riskBucket(score);
    const criticalHigh = (counts.Critical || 0) + (counts.High || 0);

    el.innerHTML =
      `<div style="margin-bottom:6px;">` +
      `<strong>${type === 'deep' ? 'Deep scan' : 'Light scan'}</strong> for ` +
      `<span class="mono">${target}</span> completed.` +
      `</div>` +
      `<div>Overall risk is <strong>${level}</strong> with a score of <strong>${score}/100</strong> and ` +
      `<strong>${vulns.length}</strong> total findings (${criticalHigh} critical/high).</div>` +
      `<div style="margin-top:6px;">` +
      `We recommend tackling critical and high-severity items first, then addressing configuration hardening and patch hygiene within the next sprint.` +
      `</div>`;
  }

  function setReportDownload(report) {
    const downloadBtn = $('downloadJsonBtn');
    const prettyBtn = $('viewPrettyBtn');

    if (!report) {
      downloadBtn.disabled = true;
      prettyBtn.disabled = true;
      return;
    }
    downloadBtn.disabled = false;
    prettyBtn.disabled = false;

    downloadBtn.onclick = () => {
      const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulneraai-report-${report.target.replace(/[^a-z0-9]/gi, '_')}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    };

    prettyBtn.onclick = () => {
      window.print();
    };
  }

  // --- Scan trigger (calls backend) ---
  async function runScan(type) {
    const target = targetInput.value.trim();
    if (!validateTarget(target)) {
      showToast('Enter a valid IP, domain, or subdomain before scanning.', 'error');
      targetInput.focus();
      targetInput.classList.add('scan-input-error');
      setTimeout(() => targetInput.classList.remove('scan-input-error'), 900);
      return;
    }

    // Free light scans guard (front-end view)
    if (type === 'light' && state.freeScansRemaining <= 0) {
      showToast(
        'You have exhausted your free light scans. Please upgrade to Pro to continue.',
        'error'
      );
      return;
    }

    // Deep scan requires auth token
    if (type === 'deep') {
      const token = localStorage.getItem('vulneraai_token');
      if (!token) {
        showToast('Sign in (or create an account) to unlock deep scanning.', 'error');
        const openAuthBtn = $('openAuthBtn');
        if (openAuthBtn) openAuthBtn.click();
        return;
      }
    }

    const lightBtn = $('lightScanBtn');
    const deepBtn = $('deepScanBtn');
    const originalTextLight = lightBtn.textContent;
    const originalTextDeep = deepBtn.textContent;

    lightBtn.disabled = true;
    deepBtn.disabled = true;
    lightBtn.classList.add('disabled');
    deepBtn.classList.add('disabled');

    if (type === 'light') {
      lightBtn.textContent = 'Scanning…';
    } else {
      deepBtn.textContent = 'Deep scanning…';
    }

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (type === 'deep') {
        const token = localStorage.getItem('vulneraai_token');
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }
      }

      const res = await fetch(
        `${API_BASE}/scan/${type === 'deep' ? 'deep' : 'light'}`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({ target }),
        }
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        // Light scan: if 429, sync local remaining count to 0
        if (type === 'light' && res.status === 429) {
          state.freeScansRemaining = 0;
          updateFreeScanCounter();
        }
        showToast(data.message || 'Scan failed.', 'error');
        return;
      }

      // Sync free scan counter from backend meta (for light scans)
      if (type === 'light' && data.meta && typeof data.meta.freeScansRemaining === 'number') {
        state.freeScansRemaining = data.meta.freeScansRemaining;
        updateFreeScanCounter();
      }

      const vulns = data.vulnerabilities || [];
      const severitySummary =
        data.severitySummary || summarizeBySeverity(vulns);
      const riskScore =
        typeof data.riskScore === 'number'
          ? data.riskScore
          : computeRiskScore(vulns);

      state.lastReport = {
        target: data.target || target,
        type: data.type || type,
        at: data.at || new Date().toISOString(),
        vulnerabilities: vulns,
        severitySummary,
        riskScore,
        meta: data.meta || {},
      };

      renderSeveritySummary(severitySummary);
      renderVulnList(vulns);
      updateRiskUI(vulns, riskScore);
      updateReportMeta(state.lastReport.target, state.lastReport.type, vulns, state.lastReport.at);
      updateQuickSummary(
        state.lastReport.target,
        state.lastReport.type,
        vulns,
        riskScore,
        severitySummary
      );
      setReportDownload(state.lastReport);

      showToast(
        `${type === 'deep' ? 'Deep' : 'Light'} scan completed. A vulnerability report is now available.`
      );

      // Optional: on mobile, scroll to report
      const reportCard = document.querySelector('.card-compact');
      if (reportCard) {
        reportCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    } catch (err) {
      showToast('Network error while running scan.', 'error');
    } finally {
      // Restore button states
      lightBtn.disabled = state.freeScansRemaining <= 0;
      deepBtn.disabled = false;
      if (state.freeScansRemaining <= 0) {
        lightBtn.classList.add('disabled');
      } else {
        lightBtn.classList.remove('disabled');
      }
      deepBtn.classList.remove('disabled');
      lightBtn.textContent = originalTextLight;
      deepBtn.textContent = originalTextDeep;
    }
  }

  $('lightScanBtn').addEventListener('click', () => runScan('light'));
  $('deepScanBtn').addEventListener('click', () => runScan('deep'));

  // Pricing / plan button handlers (unchanged behavior)
  $('pricingBtn').addEventListener('click', () => {
    showToast('Scroll to explore Free, Pro, and Enterprise packages.');
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
  });

  $('selectFreeBtn').addEventListener('click', () => {
    showToast('Free tier selected. You can run up to two light scans without signing in.');
  });

  $('buyProBtn').addEventListener('click', () => {
    showToast('Simulated purchase flow. Integrate your billing provider here.');
  });

  $('contactSalesBtn').addEventListener('click', () => {
    showToast('Opening contact channel. Replace this with your sales workflow.');
  });
}
