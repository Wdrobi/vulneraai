// server.js
// VulneraAI backend API (demo) – no DB, in-memory storage only

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

// ====== Configuration ======
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'vulneraai-demo-secret';
const MAX_FREE_LIGHT_SCANS = Number(process.env.FREE_LIGHT_SCANS || 2);

// ====== Middleware ======
app.use(cors());           // allow all origins for now; tighten for prod
app.use(express.json());

// ====== In-memory "database" (demo only!) ======
const users = [];          // { id, name, email, passwordHash, createdAt }
const freeScanUsage = new Map(); // ip -> count for light scans

// ====== Helpers ======
function clientIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.connection.remoteAddress ||
    'unknown'
  );
}

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

function validateTarget(target) {
  if (!target || typeof target !== 'string') return false;
  const v = target.trim();
  if (!v) return false;
  return isValidIP(v) || isValidHostname(v);
}

// ---- Vulnerability simulation (same logic as frontend) ----
function generateVulnerabilities(isDeep) {
  const severities = isDeep
    ? ['Critical', 'High', 'High', 'Medium', 'Medium', 'Low', 'Info']
    : ['High', 'Medium', 'Medium', 'Low', 'Low'];

  const templates = [
    {
      title: 'Outdated TLS configuration',
      desc: 'The target supports weak or deprecated cipher suites that may allow downgrade or MITM attacks.',
      rem: 'Disable legacy ciphers, enforce TLS 1.2+, and use modern ECDHE/ECDSA suites with forward secrecy.'
    },
    {
      title: 'Unpatched software version',
      desc: 'The server appears to run a version with known, publicly disclosed CVEs.',
      rem: 'Align with vendor patching guidance and enable automated patch management where possible.'
    },
    {
      title: 'Verbose error handling',
      desc: 'HTTP responses leak stack traces and detailed error messages.',
      rem: 'Replace verbose errors with generic messages and centralize logging to a secure sink.'
    },
    {
      title: 'Missing HTTP security headers',
      desc: 'One or more recommended browser security headers are absent or misconfigured.',
      rem: 'Implement HSTS, CSP, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy as appropriate.'
    },
    {
      title: 'Predictable session identifiers',
      desc: 'Session tokens appear low entropy and may be guessable by an attacker.',
      rem: 'Use cryptographically secure random session identifiers and rotate on privilege changes.'
    },
    {
      title: 'Exposed admin interface',
      desc: 'An administrative or management endpoint is reachable from the public internet.',
      rem: 'Restrict access via VPN or IP allow-list and enforce strong MFA on all admin access.'
    }
  ];

  const vulns = [];
  const count = isDeep ? 10 : 5;
  for (let i = 0; i < count; i++) {
    const severity = severities[i % severities.length];
    const t = templates[i % templates.length];
    const base =
      severity === 'Critical'
        ? 9
        : severity === 'High'
        ? 8
        : severity === 'Medium'
        ? 6
        : severity === 'Low'
        ? 3
        : 1;

    const randomAdjust = Number((Math.random() * 2 - 1.2).toFixed(1));
    const score = Math.min(10, Math.max(0, base + randomAdjust));

    vulns.push({
      id: `V-${1000 + i}`,
      severity,
      score,
      title: t.title,
      description: t.desc,
      remediation: t.rem
    });
  }
  return vulns;
}

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

// ---- Auth helpers ----
function issueToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'] || '';
  const [, token] = header.split(' ');
  if (!token) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Deep scan requires authentication.'
    });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Invalid or expired token.'
    });
  }
}

// ====== Routes ======

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'vulneraai-api' });
});

// ---- Auth: signup ----
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      message: 'Name is required.'
    });
  }

  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      message: 'Valid email is required.'
    });
  }

  if (!password || password.length < 8) {
    return res.status(400).json({
      error: 'WEAK_PASSWORD',
      message: 'Password must be at least 8 characters long.'
    });
  }

  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({
      error: 'WEAK_PASSWORD',
      message: 'Password must contain both letters and numbers.'
    });
  }

  const existing = users.find(
    (u) => u.email.toLowerCase() === email.toLowerCase()
  );
  if (existing) {
    return res.status(409).json({
      error: 'EMAIL_IN_USE',
      message: 'An account with this email already exists.'
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: 'u_' + Buffer.from(email).toString('hex').slice(0, 10),
    name: name.trim(),
    email: email.toLowerCase(),
    passwordHash,
    createdAt: new Date().toISOString()
  };
  users.push(user);

  const token = issueToken(user);
  res.status(201).json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email
    }
  });
});

// ---- Auth: login ----
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      message: 'Email and password are required.'
    });
  }

  const user = users.find(
    (u) => u.email.toLowerCase() === email.toLowerCase()
  );
  if (!user) {
    return res.status(401).json({
      error: 'INVALID_CREDENTIALS',
      message: 'No account found with this email.'
    });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({
      error: 'INVALID_CREDENTIALS',
      message: 'Incorrect password.'
    });
  }

  const token = issueToken(user);
  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email
    }
  });
});

// Optional: current user info
app.get('/api/me', authMiddleware, (req, res) => {
  const user = users.find((u) => u.id === req.user.sub);
  if (!user) {
    return res.status(404).json({ error: 'NOT_FOUND', message: 'User not found.' });
  }
  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  });
});

// ---- Pricing plans ----
app.get('/api/plans', (req, res) => {
  res.json([
    {
      id: 'free',
      name: 'Free Tier',
      price: 0,
      currency: 'USD',
      monthly: true,
      features: [
        '2 light scans per visitor',
        'No signup required',
        'JSON and human-readable reports'
      ]
    },
    {
      id: 'pro',
      name: 'Pro',
      price: 49,
      currency: 'USD',
      monthly: true,
      features: [
        'Unlimited light scans',
        '30 deep scans / month',
        'API access, SSO, exports'
      ]
    },
    {
      id: 'enterprise',
      name: 'Enterprise',
      price: 299,
      currency: 'USD',
      monthly: true,
      features: [
        'Custom deep scan limits',
        'Dedicated API access',
        'Custom SLAs and RBAC'
      ]
    }
  ]);
});

// ---- Light scan (no auth, limited per IP) ----
app.post('/api/scan/light', (req, res) => {
  const { target } = req.body || {};

  if (!validateTarget(target)) {
    return res.status(400).json({
      error: 'INVALID_TARGET',
      message:
        'Target must be a valid IPv4 address or hostname (e.g., 198.51.100.24, example.com, api.example.com).'
    });
  }

  const ip = clientIp(req);
  const used = freeScanUsage.get(ip) || 0;
  if (used >= MAX_FREE_LIGHT_SCANS) {
    return res.status(429).json({
      error: 'FREE_SCANS_EXHAUSTED',
      message: 'You have exhausted your free light scans for this IP.'
    });
  }
  freeScanUsage.set(ip, used + 1);

  const vulns = generateVulnerabilities(false);
  const severitySummary = summarizeBySeverity(vulns);
  const riskScore = computeRiskScore(vulns);

  const report = {
    target: target.trim(),
    type: 'light',
    at: new Date().toISOString(),
    riskScore,
    severitySummary,
    vulnerabilities: vulns,
    meta: {
      freeScansRemaining: Math.max(
        0,
        MAX_FREE_LIGHT_SCANS - (used + 1)
      )
    }
  };

  res.json(report);
});

// ---- Deep scan (auth required) ----
app.post('/api/scan/deep', authMiddleware, (req, res) => {
  const { target } = req.body || {};

  if (!validateTarget(target)) {
    return res.status(400).json({
      error: 'INVALID_TARGET',
      message:
        'Target must be a valid IPv4 address or hostname (e.g., 198.51.100.24, example.com, api.example.com).'
    });
  }

  const vulns = generateVulnerabilities(true);
  const severitySummary = summarizeBySeverity(vulns);
  const riskScore = computeRiskScore(vulns);

  const report = {
    target: target.trim(),
    type: 'deep',
    at: new Date().toISOString(),
    riskScore,
    severitySummary,
    vulnerabilities: vulns,
    meta: {
      user: {
        id: req.user.sub,
        email: req.user.email
      }
    }
  };

  res.json(report);
});

// 404 fallback
app.use((req, res) => {
  res.status(404).json({
    error: 'NOT_FOUND',
    message: 'Endpoint not found.'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`VulneraAI API running on http://localhost:${PORT}`);
});
