/**
 * Authentication Logic
 */

const API_BASE = 'http://localhost:5000/api';

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        const tabName = e.target.dataset.tab;
        switchTab(tabName);
    });
});

function switchTab(tabName) {
    // If Home tab, navigate to home page
    if (tabName === 'home') {
        window.location.href = 'home.html';
        return;
    }

    // Update active tab button
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Update active form
    document.querySelectorAll('.auth-form').forEach(form => {
        form.classList.remove('active');
    });
    document.getElementById(`${tabName}Form`).classList.add('active');

    // Clear error messages
    document.getElementById(`${tabName}Error`).textContent = '';
}

// Login Form Handler
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showError('login', 'Username and password are required');
        return;
    }

    await submitLogin(username, password);
});

// Register Form Handler
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirm = document.getElementById('registerConfirm').value;

    // Validation
    if (!username || !email || !password || !confirm) {
        showError('register', 'All fields are required');
        return;
    }

    if (username.length < 3) {
        showError('register', 'Username must be at least 3 characters');
        return;
    }

    if (!isValidEmail(email)) {
        showError('register', 'Invalid email address');
        return;
    }

    if (password.length < 6) {
        showError('register', 'Password must be at least 6 characters');
        return;
    }

    if (password !== confirm) {
        showError('register', 'Passwords do not match');
        return;
    }

    await submitRegister(username, email, password);
});

// Demo Login Button (removed in UI; guard for safety)
const demoBtn = document.getElementById('demoLoginBtn');
if (demoBtn) {
    demoBtn.addEventListener('click', () => {
        document.getElementById('loginUsername').value = 'demo';
        document.getElementById('loginPassword').value = 'demo123';
        submitLogin('demo', 'demo123');
    });
}

// Submit Login
async function submitLogin(username, password) {
    showLoading(true);

    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            // Store token and user info
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));

            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 500);
        } else {
            showError('login', data.error || 'Login failed');
        }
    } catch (error) {
        showError('login', 'Connection error. Please try again.');
        console.error('Login error:', error);
    } finally {
        showLoading(false);
    }
}

// Submit Register
async function submitRegister(username, email, password) {
    showLoading(true);

    try {
        const response = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });

        const data = await response.json();

        if (data.success) {
            // Show success message
            showSuccess('register', 'Account created successfully! Logging in...');

            // Auto-login after registration
            setTimeout(() => {
                submitLogin(username, password);
            }, 1000);
        } else {
            showError('register', data.error || 'Registration failed');
        }
    } catch (error) {
        showError('register', 'Connection error. Please try again.');
        console.error('Register error:', error);
    } finally {
        showLoading(false);
    }
}

// Utility Functions
function showError(formType, message) {
    const errorEl = document.getElementById(`${formType}Error`);
    errorEl.textContent = message;
    errorEl.classList.add('show');
}

function showSuccess(formType, message) {
    const errorEl = document.getElementById(`${formType}Error`);
    errorEl.textContent = message;
    errorEl.style.background = 'rgba(6, 167, 125, 0.1)';
    errorEl.style.borderColor = '#06a77d';
    errorEl.style.color = '#06a77d';
    errorEl.classList.add('show');
}

function showLoading(show) {
    const spinner = document.getElementById('loadingSpinner');
    if (show) {
        spinner.classList.add('show');
    } else {
        spinner.classList.remove('show');
    }
}

function isValidEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

// Check if already authenticated
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (token) {
        // Verify token
        verifyToken(token).then(valid => {
            if (valid) {
                window.location.href = 'dashboard.html';
            }
        });
    }
});

async function verifyToken(token) {
    try {
        const response = await fetch(`${API_BASE}/auth/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });

        const data = await response.json();
        return data.success;
    } catch (error) {
        return false;
    }
}
