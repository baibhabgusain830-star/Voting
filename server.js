const express = require('express');
const path = require('path');
const fs = require('fs');

// Load .env environment variables automatically if present
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const envLines = fs.readFileSync(envPath, 'utf-8').split(/\r?\n/);
    for (const line of envLines) {
      const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
      if (match) {
        const key = match[1];
        let val = (match[2] || '').trim();
        if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
        if (!process.env[key]) process.env[key] = val;
      }
    }
  }
} catch (e) {}

const aftercodeService = require('./services/aftercodeService');

const app = express();
const PORT = process.env.PORT || 3000;

app.use((req, res, next) => {
  const reqPath = req.path.toLowerCase();
  if (
    reqPath.endsWith('.csv') ||
    reqPath.endsWith('.sqlite') ||
    reqPath.endsWith('.sqlite3') ||
    reqPath.endsWith('.db') ||
    reqPath.endsWith('.sql') ||
    reqPath.endsWith('.env') ||
    reqPath.includes('/private_data/') ||
    reqPath === '/server.js' ||
    reqPath === '/package.json' ||
    reqPath === '/package-lock.json' ||
    reqPath.includes('.git')
  ) {
    return res.status(404).send('404 Not Found');
  }
  next();
});

app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

const aftercodeRateMap = new Map();
const AFTERCODE_RATE_WINDOW = 60 * 1000;
const AFTERCODE_MAX_REQS = 2500;

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of aftercodeRateMap.entries()) {
    if (now - entry.start > AFTERCODE_RATE_WINDOW) {
      aftercodeRateMap.delete(key);
    }
  }
}, 30 * 1000).unref();

function aftercodeRateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.ip || 'unknown';
  const now = Date.now();
  const entry = aftercodeRateMap.get(ip);
  if (!entry || now - entry.start > AFTERCODE_RATE_WINDOW) {
    aftercodeRateMap.set(ip, { count: 1, start: now });
    return next();
  }
  entry.count += 1;
  if (entry.count > AFTERCODE_MAX_REQS) {
    return res.status(429).json({
      success: false,
      message: 'Too many requests from this IP. Please wait a moment and try again.'
    });
  }
  return next();
}

app.get('/api/aftercode/state', aftercodeRateLimit, async (req, res) => {
  try {
    const [repositories, stats, session] = await Promise.all([
      Promise.resolve(aftercodeService.getRepositoriesWithVotes()),
      Promise.resolve(aftercodeService.getEventStats()),
      aftercodeService.resolveVoterSessionFromRequest(req)
    ]);

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    return res.status(200).json({
      success: true,
      repositories,
      stats,
      votingWindow: aftercodeService.getVotingWindowConfig(),
      session,
      authConfig: aftercodeService.getAuthInfrastructureInfo()
    });
  } catch (err) {
    console.error('[AfterCode API] /api/aftercode/state error:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to load AfterCode voting state.'
    });
  }
});

app.post('/api/aftercode/auth/verify', aftercodeRateLimit, async (req, res) => {
  try {
    const { email, registrationId } = req.body || {};
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_EMAIL',
        message: 'Please enter the valid email address used on Unstop.'
      });
    }

    const check = aftercodeService.findEligibleParticipant(email, registrationId);
    if (!check.eligible) {
      return res.status(403).json({
        success: false,
        eligible: false,
        code: 'NOT_ELIGIBLE',
        message: check.reason
      });
    }

    const token = aftercodeService.createSignedSessionToken(check.participant, 'unstop_session');
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.setHeader(
      'Set-Cookie',
      `${aftercodeService.COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=${aftercodeService.SESSION_MAX_AGE_SEC}; HttpOnly; SameSite=Lax${isSecure ? '; Secure' : ''}`
    );

    const session = await aftercodeService.resolveVoterSessionFromRequest({
      headers: {
        ...req.headers,
        cookie: `${aftercodeService.COOKIE_NAME}=${encodeURIComponent(token)}`
      }
    });

    return res.status(200).json({
      success: true,
      eligible: true,
      message: `Verified as ${check.participant.name} (${check.participant.registrationId}).`,
      session
    });
  } catch (err) {
    console.error('[AfterCode API] /api/aftercode/auth/verify error:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Authentication verification failed.'
    });
  }
});

app.post('/api/aftercode/auth/logout', (req, res) => {
  res.setHeader(
    'Set-Cookie',
    `${aftercodeService.COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`
  );
  return res.status(200).json({
    success: true,
    message: 'Signed out of AfterCode voting session.'
  });
});

app.post('/api/aftercode/vote', aftercodeRateLimit, async (req, res) => {
  try {
    const session = await aftercodeService.resolveVoterSessionFromRequest(req);
    if (!session.authenticated || !session.user?.email) {
      return res.status(401).json({
        success: false,
        code: 'AUTH_REQUIRED',
        message: 'Rule #1: You must sign in with your registered Unstop email before voting.'
      });
    }

    const { repoId } = req.body || {};
    const ip = req.headers['x-forwarded-for'] || req.ip || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const result = await aftercodeService.castVoteAtomically({
      voterEmail: session.user.email,
      registrationId: session.user.registrationId,
      repoId,
      ip,
      userAgent
    });

    if (!result.success) {
      return res.status(result.status || 400).json(result);
    }

    const updatedSession = await aftercodeService.resolveVoterSessionFromRequest(req);
    return res.status(200).json({
      ...result,
      repositories: aftercodeService.getRepositoriesWithVotes(),
      stats: aftercodeService.getEventStats(),
      session: updatedSession
    });
  } catch (err) {
    console.error('[AfterCode API] /api/aftercode/vote error:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Unexpected server error while recording your vote.'
    });
  }
});

app.get(['/', '/aftercode', '/aftercode.html', '/index.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'aftercode.html'));
});

app.use(express.static(path.join(__dirname)));

process.on('uncaughtException', (err) => {
  console.error('[CRITICAL] Uncaught Exception intercepted:', err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('[CRITICAL] Unhandled Rejection intercepted:', reason);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Grevix AfterCode Voting Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
