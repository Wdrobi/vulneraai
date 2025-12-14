// js/app.js
import { initAuth } from './auth.js';
import { initScan } from './scan.js';

// ----- Global state -----
export const state = {
  freeScansRemaining: 2,
  user: null,
  lastReport: null,
};

// ----- DOM helper -----
export const $ = (id) => document.getElementById(id);

// ----- Toast helper -----
export function showToast(message, kind = 'info') {
  const toast = $('toast');
  if (!toast) return;
  $('toastMessage').textContent = message;
  toast.classList.add('visible');

  const pill = toast.querySelector('.toast-pill');
  if (kind === 'error') {
    toast.style.borderColor = 'rgba(255,110,110,0.7)';
    pill.style.background = 'rgba(255,110,110,0.18)';
    pill.style.color = '#ffb3b3';
  } else {
    toast.style.borderColor = 'rgba(29,233,182,0.7)';
    pill.style.background = 'rgba(29,233,182,0.18)';
    pill.style.color = 'var(--accent-primary)';
  }

  setTimeout(() => toast.classList.remove('visible'), 3600);
}

// ----- User persistence -----
export function setUser(user) {
  state.user = user;
  try {
    if (user) {
      localStorage.setItem('vulneraai_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('vulneraai_user');
    }
  } catch (e) {}

  const label = $('authBtnLabel');
  if (!label) return;
  label.textContent = user
    ? `${user.name || user.email} (Sign out)`
    : 'Sign In';
}

function loadUser() {
  try {
    const stored = localStorage.getItem('vulneraai_user');
    if (!stored) return;
    const parsed = JSON.parse(stored);
    if (parsed && parsed.email) {
      state.user = parsed;
      const label = $('authBtnLabel');
      if (label) {
        label.textContent = `${parsed.name || parsed.email} (Sign out)`;
      }
    }
  } catch (e) {}
}

// ----- Target validation shared with scan.js -----
function isValidIP(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^[0-9]{1,3}$/.test(p)) return false;
    const v = parseInt(p, 10);
    return v >= 0 && v <= 255;
  });
}

function isValidHostname(host) {
  const re =
    /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/;
  return re.test(host);
}

export function validateTarget(value) {
  const v = (value || '').trim();
  if (!v) return false;
  return isValidIP(v) || isValidHostname(v);
}

// Update free scan counter in UI
export function updateFreeScanCounter() {
  const el = $('freeScanCounter');
  if (!el) return;
  el.textContent = state.freeScansRemaining;
  const btn = $('lightScanBtn');
  if (!btn) return;
  if (state.freeScansRemaining <= 0) {
    btn.classList.add('disabled');
    btn.setAttribute('disabled', 'true');
  } else {
    btn.classList.remove('disabled');
    btn.removeAttribute('disabled');
  }
}

// ----- App bootstrap -----
document.addEventListener('DOMContentLoaded', () => {
  loadUser();
  updateFreeScanCounter();

  // Init modules
  initAuth({ state, $, setUser, showToast });
  initScan({ state, $, showToast, validateTarget, updateFreeScanCounter });
});
