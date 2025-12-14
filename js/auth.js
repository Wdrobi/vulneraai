// js/auth.js

// Adjust this if your API is hosted elsewhere
const API_BASE = 'http://localhost:4000/api';

export function initAuth({ state, $, setUser, showToast }) {
  const authBackdrop = $('authModalBackdrop');
  const authTabLogin = $('authTabLogin');
  const authTabSignup = $('authTabSignup');
  const authLoginSection = $('authLoginSection');
  const authSignupSection = $('authSignupSection');
  const authModalTitle = $('authModalTitle');
  const authModalSubtitle = $('authModalSubtitle');
  const openAuthBtn = $('openAuthBtn');

  const loginError = $('loginError');
  const signupError = $('signupError');

  // ---- UI helpers ----
  function setAuthMode(mode) {
    const isLogin = mode === 'login';
    authTabLogin.classList.toggle('active', isLogin);
    authTabSignup.classList.toggle('active', !isLogin);
    authLoginSection.classList.toggle('active', isLogin);
    authSignupSection.classList.toggle('active', !isLogin);
    authModalTitle.textContent = isLogin
      ? 'Sign in to VulneraAI'
      : 'Create a VulneraAI account';
    authModalSubtitle.textContent = isLogin
      ? 'Authenticate to unlock deep scans, saved reports, and workspace settings.'
      : 'Create a demo account to explore authenticated features.';
    loginError.textContent = '';
    signupError.textContent = '';
  }

  function openAuthModal(initialMode = 'login') {
    setAuthMode(initialMode);
    authBackdrop.classList.add('visible');
    if (initialMode === 'login') {
      $('loginEmail').focus();
    } else {
      $('signupName').focus();
    }
  }

  function closeAuthModal() {
    authBackdrop.classList.remove('visible');
    loginError.textContent = '';
    signupError.textContent = '';
  }

  // ---- Sign out / open modal button ----
  openAuthBtn.addEventListener('click', () => {
    if (state.user) {
      // Sign out: clear user and token
      setUser(null);
      try {
        localStorage.removeItem('vulneraai_token');
      } catch (e) {}
      showToast('Signed out. Deep scans now require authentication again.');
    } else {
      openAuthModal('login');
    }
  });

  $('authCloseBtn').addEventListener('click', closeAuthModal);

  // Esc key closes modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && authBackdrop.classList.contains('visible')) {
      closeAuthModal();
    }
  });

  authTabLogin.addEventListener('click', () => setAuthMode('login'));
  authTabSignup.addEventListener('click', () => setAuthMode('signup'));
  $('switchToSignupLink').addEventListener('click', () => setAuthMode('signup'));
  $('switchToLoginLink').addEventListener('click', () => setAuthMode('login'));

  $('forgotPasswordLink').addEventListener('click', () => {
    showToast(
      'Password reset is not wired to a backend yet. Integrate your reset flow here.'
    );
  });

  // ---- Validation helpers ----
  function validatePasswordQuality(pw) {
    if (pw.length < 8) {
      return 'Password must be at least 8 characters long.';
    }
    if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) {
      return 'Password must contain both letters and numbers.';
    }
    return '';
  }

  // ---- Signup submit (calls /api/auth/signup) ----
  $('signupSubmitBtn').addEventListener('click', async () => {
    const name = $('signupName').value.trim();
    const email = $('signupEmail').value.trim();
    const password = $('signupPassword').value;
    const confirm = $('signupPasswordConfirm').value;
    const accept = $('signupAccept').checked;

    signupError.textContent = '';

    if (!name) {
      signupError.textContent = 'Please enter your full name.';
      return;
    }
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      signupError.textContent = 'Enter a valid email address.';
      return;
    }
    const pwErr = validatePasswordQuality(password);
    if (pwErr) {
      signupError.textContent = pwErr;
      return;
    }
    if (password !== confirm) {
      signupError.textContent = 'Passwords do not match.';
      return;
    }
    if (!accept) {
      signupError.textContent = 'You must accept the demo terms to continue.';
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        signupError.textContent = data.message || 'Failed to create account.';
        return;
      }

      // Save token & user
      try {
        localStorage.setItem('vulneraai_token', data.token);
      } catch (e) {}
      setUser(data.user);

      closeAuthModal();
      showToast('Account created and signed in.');
    } catch (err) {
      signupError.textContent = 'Network error while creating account.';
    }
  });

  // ---- Login submit (calls /api/auth/login) ----
  $('loginSubmitBtn').addEventListener('click', async () => {
    const email = $('loginEmail').value.trim();
    const password = $('loginPassword').value;
    const remember = $('loginRemember').checked;

    loginError.textContent = '';

    if (!email || !password) {
      loginError.textContent = 'Enter both email and password.';
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        loginError.textContent = data.message || 'Login failed.';
        return;
      }

      // Save token if "remember" or not – in both cases we need it for deep scans
      try {
        localStorage.setItem('vulneraai_token', data.token);
      } catch (e) {}

      // Remember flag only affects whether we persist user via setUser()
      if (remember) {
        setUser(data.user);
      } else {
        state.user = data.user;
        $('authBtnLabel').textContent = `${data.user.name || data.user.email} (Sign out)`;
      }

      closeAuthModal();
      showToast('Signed in. Deep scans unlocked.');
    } catch (err) {
      loginError.textContent = 'Network error while signing in.';
    }
  });
}
