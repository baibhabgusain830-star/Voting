/**
 * Grevix AfterCode 2026 — Official Voting, Unstop CSV Eligibility & Atomic Vote Service
 *
 * Responsibilities:
 * 1. Parse & index the official Unstop eligible-participant CSV (`private_data/aftercode_participants.csv`)
 *    exclusively on the server (never exposed publicly).
 * 2. Load & persist official repository submissions in SQLite (`aftercode_repositories`, seeded from
 *    `private_data/aftercode_repositories.json`) with zero mock vote inflation.
 * 3. Validate signed-in users via either:
 *    - Existing Supabase Auth (`getSupabaseAdmin().auth.getUser(accessToken)`) for Google OAuth / Supabase sessions
 *    - HMAC-SHA256 signed `HttpOnly` session cookies (`grevix_aftercode_session`) verified against the Unstop CSV
 * 4. Enforce the configured voting window (`AFTERCODE_VOTING_START` to `AFTERCODE_VOTING_END`).
 * 5. Enforce 1 vote per eligible participant and no self-voting on the server.
 * 6. Execute atomic vote submissions with database-level UNIQUE constraints (`voter_email`, `registration_id`).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  saveAftercodeVoteToSupabase,
  getAftercodeVoteFromSupabase,
  getAllAftercodeVotesFromSupabase
} = require('./supabaseService');
const { createClient } = require('@supabase/supabase-js');

let supabaseAdminInstance = null;
function getSupabaseAdmin() {
  if (!supabaseAdminInstance) {
    const supabaseUrl =
      process.env.SUPABASE_URL ||
      process.env.NEXT_PUBLIC_SUPABASE_URL ||
      '';
    const supabaseServiceKey =
      process.env.SUPABASE_SERVICE_ROLE_KEY ||
      process.env.SUPABASE_SECRET_KEY ||
      process.env.SUPABASE_PUBLISHABLE_KEY ||
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
      '';
    if (!supabaseUrl || !supabaseServiceKey) {
      return null;
    }
    supabaseAdminInstance = createClient(supabaseUrl, supabaseServiceKey, {
      auth: { persistSession: false, autoRefreshToken: false }
    });
  }
  return supabaseAdminInstance;
}

const isVercel = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
const BUNDLED_PRIVATE_DIR = path.join(__dirname, '..', 'private_data');
const RUNTIME_PRIVATE_DIR = isVercel ? path.join('/tmp', 'private_data') : BUNDLED_PRIVATE_DIR;

try {
  if (!fs.existsSync(RUNTIME_PRIVATE_DIR)) {
    fs.mkdirSync(RUNTIME_PRIVATE_DIR, { recursive: true });
  }
} catch (e) {}

const CSV_PATH = fs.existsSync(path.join(BUNDLED_PRIVATE_DIR, 'aftercode_participants.csv'))
  ? path.join(BUNDLED_PRIVATE_DIR, 'aftercode_participants.csv')
  : path.join(RUNTIME_PRIVATE_DIR, 'aftercode_participants.csv');

const REPOS_SEED_PATH = fs.existsSync(path.join(BUNDLED_PRIVATE_DIR, 'aftercode_repositories.json'))
  ? path.join(BUNDLED_PRIVATE_DIR, 'aftercode_repositories.json')
  : path.join(RUNTIME_PRIVATE_DIR, 'aftercode_repositories.json');

const SQLITE_FILE = path.join(RUNTIME_PRIVATE_DIR, 'aftercode_votes.sqlite');
const SQL_DUMP_FILE = path.join(RUNTIME_PRIVATE_DIR, 'aftercode_votes.sql');
const JSON_BACKUP_FILE = path.join(RUNTIME_PRIVATE_DIR, 'aftercode_votes.json');

// Session signing secret (never exposed to client)
const SESSION_SECRET =
  process.env.AFTERCODE_SESSION_SECRET ||
  process.env.ADMIN_API_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  'grevix-aftercode-2026-hmac-secret-key-v1';

// Official Voting Window Configuration (Defaults: Oct 11, 2026 4:00 PM IST to 7:00 PM IST)
function getVotingWindowConfig() {
  const startIso = process.env.AFTERCODE_VOTING_START || '2026-10-11T16:00:00+05:30';
  const endIso = process.env.AFTERCODE_VOTING_END || '2026-10-11T19:00:00+05:30';
  const startMs = new Date(startIso).getTime();
  const endMs = new Date(endIso).getTime();
  const nowMs = Date.now();

  let status = 'OPEN';
  let statusMessage = 'Voting is currently open for verified Unstop participants (Oct 11, 2026, 4:00 PM – 7:00 PM IST).';
  if (nowMs < startMs) {
    status = 'NOT_STARTED';
    statusMessage = 'Voting has not opened yet. Voting opens on Oct 11, 2026 at 4:00 PM IST (4:00 PM – 7:00 PM IST).';
  } else if (nowMs > endMs) {
    status = 'ENDED';
    statusMessage = 'The AfterCode 2026 community voting window has closed (ended Oct 11, 2026 at 7:00 PM IST).';
  }

  return {
    status,
    isOpen: status === 'OPEN',
    opensAt: startIso,
    endsAt: endIso,
    serverTime: new Date(nowMs).toISOString(),
    message: statusMessage
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. RFC-4180 Multi-line CSV Parser & Official Unstop Participant Index
// ─────────────────────────────────────────────────────────────────────────────

function parseCsvRecords(csvContent) {
  const rows = [];
  let currentRow = [];
  let currentField = '';
  let inQuotes = false;

  for (let i = 0; i < csvContent.length; i++) {
    const ch = csvContent[i];
    const nextCh = csvContent[i + 1];

    if (inQuotes) {
      if (ch === '"' && nextCh === '"') {
        currentField += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        currentField += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ',') {
        currentRow.push(currentField.trim());
        currentField = '';
      } else if (ch === '\r' && nextCh === '\n') {
        currentRow.push(currentField.trim());
        if (currentRow.some(cell => cell !== '')) {
          rows.push(currentRow);
        }
        currentRow = [];
        currentField = '';
        i++;
      } else if (ch === '\n' || ch === '\r') {
        currentRow.push(currentField.trim());
        if (currentRow.some(cell => cell !== '')) {
          rows.push(currentRow);
        }
        currentRow = [];
        currentField = '';
      } else {
        currentField += ch;
      }
    }
  }

  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField.trim());
    if (currentRow.some(cell => cell !== '')) {
      rows.push(currentRow);
    }
  }

  return rows;
}

let participantsByEmail = new Map();
let participantsByRegId = new Map();
let participantsByMobile = new Map();
let csvLoadedCount = 0;

function extractGithubHandle(rawGh) {
  const clean = String(rawGh || '').trim();
  const match = clean.match(/github\.com\/([a-zA-Z0-9._-]+)/i);
  if (match && match[1] && !['profile', 'settings', 'login', 'join'].includes(match[1].toLowerCase())) {
    return match[1].replace(/\/+$/, '');
  }
  if (/^[a-zA-Z0-9-]{3,39}$/.test(clean) && !/^(yes|no|ok|na|nil|none|fresher|beginner)$/i.test(clean)) {
    return clean;
  }
  return '';
}

function loadEligibleParticipantsCsv() {
  participantsByEmail = new Map();
  participantsByRegId = new Map();
  participantsByMobile = new Map();
  csvLoadedCount = 0;

  try {
    if (!fs.existsSync(CSV_PATH)) {
      console.warn('[AfterCode] Official participant CSV not found at:', CSV_PATH);
      return;
    }

    const raw = fs.readFileSync(CSV_PATH, 'utf-8');
    const rows = parseCsvRecords(raw);
    if (rows.length < 2) return;

    const header = rows[0].map(h => h.trim());
    const idxRegId = header.findIndex(h => /registration\s*id/i.test(h));
    const idxName = header.findIndex(h => /candidate's\s*name/i.test(h));
    const idxEmail = header.findIndex(h => /candidate's\s*email/i.test(h));
    const idxMobile = header.findIndex(h => /candidate's\s*mobile/i.test(h));
    const idxGender = header.findIndex(h => /candidate's\s*gender/i.test(h));
    const idxLocation = header.findIndex(h => /candidate's\s*location/i.test(h));
    const idxUserType = header.findIndex(h => /user\s*type/i.test(h));
    const idxDomain = header.findIndex(h => /^domain$/i.test(h));
    const idxCourse = header.findIndex(h => /^course$/i.test(h));
    const idxSpec = header.findIndex(h => /specialization/i.test(h));
    const idxGradYear = header.findIndex(h => /year\s*of\s*graduation/i.test(h));
    const idxOrg = header.findIndex(h => /candidate's\s*organisation/i.test(h));
    const idxRegTime = header.findIndex(h => /registration\s*time/i.test(h));
    const idxStatus = header.findIndex(h => /reg\.\s*status/i.test(h));
    const idxIdea = header.findIndex(h => /what's\s*your\s*idea/i.test(h));
    const idxGithub = header.findIndex(h => /github\s*profile/i.test(h));
    const idxExpLevel = header.findIndex(h => /experience\s*level/i.test(h));
    const idxAiTools = header.findIndex(h => /which\s*ai\s*tools/i.test(h));

    for (let i = 1; i < rows.length; i++) {
      const cols = rows[i];
      const regId = (cols[idxRegId] || '').trim().toUpperCase();
      const name = (cols[idxName] || '').trim();
      const email = (cols[idxEmail] || '').trim().toLowerCase();
      const mobile = idxMobile >= 0 ? (cols[idxMobile] || '').trim() : '';
      const gender = idxGender >= 0 ? (cols[idxGender] || '').trim() : '';
      const location = idxLocation >= 0 ? (cols[idxLocation] || '').trim() : '';
      const userType = idxUserType >= 0 ? (cols[idxUserType] || '').trim() : '';
      const domain = idxDomain >= 0 ? (cols[idxDomain] || '').trim() : '';
      const course = idxCourse >= 0 ? (cols[idxCourse] || '').trim() : '';
      const specialization = idxSpec >= 0 ? (cols[idxSpec] || '').trim() : '';
      const yearOfGraduation = idxGradYear >= 0 ? (cols[idxGradYear] || '').trim() : '';
      const organisation = idxOrg >= 0 ? (cols[idxOrg] || '').trim() : '';
      const registrationTime = idxRegTime >= 0 ? (cols[idxRegTime] || '').trim() : '';
      const regStatus = idxStatus >= 0 ? (cols[idxStatus] || '').trim() : '';
      const idea = idxIdea >= 0 ? (cols[idxIdea] || '').trim() : '';
      const githubProfile = idxGithub >= 0 ? (cols[idxGithub] || '').trim() : '';
      const experienceLevel = idxExpLevel >= 0 ? (cols[idxExpLevel] || '').trim() : '';
      const aiTools = idxAiTools >= 0 ? (cols[idxAiTools] || '').trim() : '';

      if (!email || !regId) continue;

      const participant = {
        registrationId: regId,
        name: name || email.split('@')[0],
        email,
        mobile,
        gender,
        location,
        userType,
        domain,
        course,
        specialization,
        yearOfGraduation,
        organisation: organisation || '',
        registrationTime,
        regStatus,
        idea,
        githubProfile,
        githubHandle: extractGithubHandle(githubProfile),
        experienceLevel,
        aiTools,
        isComplete: regStatus.toLowerCase() === 'complete'
      };

      participantsByEmail.set(email, participant);
      participantsByRegId.set(regId, participant);
      if (mobile) {
        const cleanDigits = mobile.replace(/\D/g, '').slice(-10);
        if (cleanDigits.length === 10) {
          participantsByMobile.set(cleanDigits, participant);
        }
      }
      if (participant.isComplete) {
        csvLoadedCount++;
      }
    }

    console.log(`[AfterCode] Loaded ${csvLoadedCount} eligible Unstop participants (24-column schema) from official CSV.`);
  } catch (err) {
    console.error('[AfterCode] Failed to parse eligible participants CSV:', err.message);
  }
}

loadEligibleParticipantsCsv();

function findEligibleParticipant(emailInput, regIdInput) {
  if (participantsByEmail.size === 0) {
    loadEligibleParticipantsCsv();
  }
  const cleanEmail = String(emailInput || '').trim().toLowerCase();
  const cleanRegId = String(regIdInput || '').trim().toUpperCase();

  let record = null;
  if (cleanEmail && participantsByEmail.has(cleanEmail)) {
    record = participantsByEmail.get(cleanEmail);
  } else if (!cleanEmail && cleanRegId && participantsByRegId.has(cleanRegId)) {
    record = participantsByRegId.get(cleanRegId);
  }

  if (!record) {
    return {
      found: false,
      eligible: false,
      participant: null,
      reason: 'Email is not registered in the official Unstop AfterCode 2026 participant list.'
    };
  }

  if (!record.isComplete) {
    return {
      found: true,
      eligible: false,
      participant: {
        registrationId: record.registrationId,
        name: record.name,
        email: record.email,
        organisation: record.organisation,
        githubProfile: record.githubProfile || null,
        githubHandle: record.githubHandle || null
      },
      reason: `Unstop registration status is "${record.regStatus}" (Complete status required).`
    };
  }

  // If the caller also provided a Registration ID, verify it matches the email's Registration ID
  if (cleanRegId && cleanEmail && record.registrationId !== cleanRegId) {
    return {
      found: true,
      eligible: false,
      participant: null,
      reason: 'The provided Unstop Registration ID does not match that email address.'
    };
  }

  return {
    found: true,
    eligible: true,
    participant: {
      registrationId: record.registrationId,
      name: record.name,
      email: record.email,
      organisation: record.organisation,
      location: record.location || null,
      domain: record.domain || null,
      course: record.course || null,
      specialization: record.specialization || null,
      githubProfile: record.githubProfile || null,
      githubHandle: record.githubHandle || null,
      idea: record.idea || null,
      experienceLevel: record.experienceLevel || null,
      aiTools: record.aiTools || null
    },
    reason: 'Verified with Unstop official participant list.'
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Database Initialization (SQLite Atomic Engine + Participant & Repository Catalog + SQL Ledger)
// ─────────────────────────────────────────────────────────────────────────────

function loadSeedRepositoriesFromDisk() {
  try {
    if (fs.existsSync(REPOS_SEED_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(REPOS_SEED_PATH, 'utf-8'));
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (err) {
    console.error('[AfterCode] Failed to read repository seed file:', err.message);
  }
  try {
    const bundled = require('../private_data/aftercode_repositories.json');
    if (Array.isArray(bundled)) return bundled;
  } catch (e) {}
  return [];
}

let db = null;
let useSqlite = false;

try {
  const { DatabaseSync } = require('node:sqlite');
  db = new DatabaseSync(SQLITE_FILE);
  useSqlite = true;

  db.exec(`
    CREATE TABLE IF NOT EXISTS aftercode_participants (
      registration_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      mobile TEXT,
      gender TEXT,
      location TEXT,
      user_type TEXT,
      domain TEXT,
      course TEXT,
      specialization TEXT,
      year_of_graduation TEXT,
      organisation TEXT,
      registration_time TEXT,
      reg_status TEXT NOT NULL,
      idea TEXT,
      github_profile TEXT,
      github_handle TEXT,
      experience_level TEXT,
      ai_tools TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_ac_part_email ON aftercode_participants(email);
    CREATE TABLE IF NOT EXISTS aftercode_repositories (
      id TEXT PRIMARY KEY,
      recommended_rank INTEGER NOT NULL,
      name TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL,
      builder TEXT NOT NULL,
      builder_name TEXT NOT NULL,
      builder_email TEXT,
      builder_registration_id TEXT,
      primary_domain TEXT NOT NULL,
      technologies_json TEXT NOT NULL,
      submitted_at TEXT NOT NULL,
      avatar_bg_json TEXT,
      builder_bg_json TEXT
    );
    CREATE TABLE IF NOT EXISTS aftercode_votes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      registration_id TEXT NOT NULL UNIQUE,
      voter_email TEXT NOT NULL UNIQUE,
      voter_name TEXT NOT NULL,
      repo_id TEXT NOT NULL,
      repo_name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_ac_votes_repo ON aftercode_votes(repo_id);
    CREATE INDEX IF NOT EXISTS idx_ac_votes_email ON aftercode_votes(voter_email);
  `);

  // Synchronize official 24-column participant dataset into SQLite
  if (participantsByRegId.size > 0) {
    const upsertParticipantStmt = db.prepare(`
      INSERT INTO aftercode_participants (
        registration_id, name, email, mobile, gender, location, user_type,
        domain, course, specialization, year_of_graduation, organisation,
        registration_time, reg_status, idea, github_profile, github_handle,
        experience_level, ai_tools
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(registration_id) DO UPDATE SET
        name = excluded.name,
        email = excluded.email,
        mobile = excluded.mobile,
        gender = excluded.gender,
        location = excluded.location,
        user_type = excluded.user_type,
        domain = excluded.domain,
        course = excluded.course,
        specialization = excluded.specialization,
        year_of_graduation = excluded.year_of_graduation,
        organisation = excluded.organisation,
        registration_time = excluded.registration_time,
        reg_status = excluded.reg_status,
        idea = excluded.idea,
        github_profile = excluded.github_profile,
        github_handle = excluded.github_handle,
        experience_level = excluded.experience_level,
        ai_tools = excluded.ai_tools
    `);

    db.exec('BEGIN IMMEDIATE');
    try {
      for (const [, p] of participantsByRegId) {
        upsertParticipantStmt.run(
          p.registrationId,
          p.name,
          p.email,
          p.mobile || null,
          p.gender || null,
          p.location || null,
          p.userType || null,
          p.domain || null,
          p.course || null,
          p.specialization || null,
          p.yearOfGraduation || null,
          p.organisation || null,
          p.registrationTime || null,
          p.regStatus || 'Complete',
          p.idea || null,
          p.githubProfile || null,
          p.githubHandle || null,
          p.experienceLevel || null,
          p.aiTools || null
        );
      }
      db.exec('COMMIT');
    } catch (partErr) {
      try {
        db.exec('ROLLBACK');
      } catch (e) {}
      console.error('[AfterCode] Failed to sync participants into SQLite:', partErr.message);
    }
  }

  // Synchronize official repository catalog into SQLite
  const seedRepos = loadSeedRepositoriesFromDisk();
  if (seedRepos.length > 0) {
    const upsertRepoStmt = db.prepare(`
      INSERT INTO aftercode_repositories (
        id, recommended_rank, name, description, builder, builder_name,
        builder_email, builder_registration_id, primary_domain,
        technologies_json, submitted_at, avatar_bg_json, builder_bg_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        recommended_rank = excluded.recommended_rank,
        name = excluded.name,
        description = excluded.description,
        builder = excluded.builder,
        builder_name = excluded.builder_name,
        builder_email = excluded.builder_email,
        builder_registration_id = excluded.builder_registration_id,
        primary_domain = excluded.primary_domain,
        technologies_json = excluded.technologies_json,
        submitted_at = excluded.submitted_at,
        avatar_bg_json = excluded.avatar_bg_json,
        builder_bg_json = excluded.builder_bg_json
    `);

    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec('DELETE FROM aftercode_repositories;');
      for (const r of seedRepos) {
        upsertRepoStmt.run(
          String(r.id).trim(),
          Number(r.recommendedRank) || 999,
          String(r.name).trim(),
          String(r.description || '').trim(),
          String(r.builder || '').trim(),
          String(r.builderName || r.builder || '').trim(),
          r.builderEmail ? String(r.builderEmail).trim().toLowerCase() : null,
          r.builderRegistrationId ? String(r.builderRegistrationId).trim().toUpperCase() : null,
          String(r.primaryDomain || 'Other').trim(),
          JSON.stringify(Array.isArray(r.technologies) ? r.technologies : []),
          String(r.submittedAt || '2026-10-11T18:00:00+05:30'),
          JSON.stringify(Array.isArray(r.avatarBg) ? r.avatarBg : ['#0f172a', '#1e293b', '#94a3b8']),
          JSON.stringify(Array.isArray(r.builderBg) ? r.builderBg : ['#090d16', '#1e293b', '#64748b'])
        );
      }
      db.exec('COMMIT');
    } catch (seedErr) {
      try {
        db.exec('ROLLBACK');
      } catch (e) {}
      console.error('[AfterCode] Failed to seed repositories into SQLite:', seedErr.message);
    }
  }

  console.log('[AfterCode] Native SQLite atomic store active at:', SQLITE_FILE);
} catch (err) {
  console.warn('[AfterCode] Native SQLite unavailable, using file-locked fallback:', err.message);
}

try {
  if (!fs.existsSync(SQL_DUMP_FILE)) {
    fs.writeFileSync(
      SQL_DUMP_FILE,
      `-- Grevix AfterCode 2026 Official Vote Ledger\n` +
        `CREATE TABLE IF NOT EXISTS aftercode_votes (\n` +
        `  id INTEGER PRIMARY KEY AUTOINCREMENT,\n` +
        `  registration_id TEXT NOT NULL UNIQUE,\n` +
        `  voter_email TEXT NOT NULL UNIQUE,\n` +
        `  voter_name TEXT NOT NULL,\n` +
        `  repo_id TEXT NOT NULL,\n` +
        `  repo_name TEXT NOT NULL,\n` +
        `  created_at TEXT NOT NULL,\n` +
        `  ip TEXT,\n` +
        `  user_agent TEXT\n` +
        `);\n\n`,
      'utf-8'
    );
  }
} catch (e) {}

let stmtSelectAllVotes = null;
let stmtSelectVoteByEmailAndReg = null;
let stmtSelectVoteByEmail = null;
let stmtInsertVote = null;

if (useSqlite && db) {
  try {
    stmtSelectAllVotes = db.prepare(
      'SELECT id, registration_id AS registrationId, voter_email AS voterEmail, voter_name AS voterName, repo_id AS repoId, repo_name AS repoName, created_at AS createdAt FROM aftercode_votes ORDER BY id ASC'
    );
    stmtSelectVoteByEmailAndReg = db.prepare(
      'SELECT id, registration_id AS registrationId, voter_email AS voterEmail, voter_name AS voterName, repo_id AS repoId, repo_name AS repoName, created_at AS createdAt FROM aftercode_votes WHERE voter_email = ? OR registration_id = ? LIMIT 1'
    );
    stmtSelectVoteByEmail = db.prepare(
      'SELECT id, registration_id AS registrationId, voter_email AS voterEmail, voter_name AS voterName, repo_id AS repoId, repo_name AS repoName, created_at AS createdAt FROM aftercode_votes WHERE voter_email = ? LIMIT 1'
    );
    stmtInsertVote = db.prepare(`
      INSERT INTO aftercode_votes (
        registration_id, voter_email, voter_name, repo_id, repo_name, created_at, ip, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
  } catch (e) {}
}

let cachedCatalog = null;
let cachedEnrichedCatalog = null;
let cachedRepoByIdMap = new Map();
let cachedOwnedRepoByRegIdMap = new Map();
let cachedOwnedRepoByEmailMap = new Map();

function formatProjectIdeaForVoters(repo, participant) {
  const cleanName = String(repo.name || '').trim();
  const readableTitle = cleanName.replace(/[-_]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const technologies = Array.isArray(repo.technologies) && repo.technologies.length > 0
    ? repo.technologies
    : ['JavaScript', 'Node.js', 'REST API'];
  const domain = repo.primaryDomain || 'Software Engineering';

  let rawIdea = String(participant?.idea || repo.description || '')
    .replace(/^\s*\*\*\s*(?:my\s+project\s+idea|project\s+idea|my\s+idea|idea|title|problem\s+statement)?\s*[:\-–—]?\s*([^*]+?)\s*\*\*\s*[:\-–—.]?\s*/i, '$1 — ')
    .replace(/\*\*+/g, '')
    .replace(/__+/g, '')
    .replace(/`+/g, '')
    .replace(/^#+\s*/gm, '')
    .replace(/\r?\n+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  // Strip common form prefixes (e.g., "Idea: Title -", "Project Idea:", "Problem Statement:")
  rawIdea = rawIdea
    .replace(/^(my\s+project\s+idea\s*(is|:|-)|project\s+idea\s*(:|-)?|my\s+idea\s*(is|:|-)|idea\s*(:|-)|title\s*(:|-)|problem\s+statement\s*(:|-))\s*/i, '')
    .trim();

  // Remove mid-word ellipsis if fallback came from truncated description
  if (rawIdea.endsWith('...')) {
    rawIdea = rawIdea.slice(0, -3).replace(/\s+\S*$/, '').trim();
  }

  const isPlaceholder =
    !rawIdea ||
    rawIdea.length < 24 ||
    /^(n\/?a|none|nil|tbd|will\s+think|not\s+decided|nothing|yes|no|hello|hi|test|idk|later|coming\s+soon|same\s+as)/i.test(rawIdea);

  let fullPitch = '';
  if (isPlaceholder) {
    const stackStr = technologies.slice(0, 3).join(', ');
    if (/AI|ML|Machine Learning|Data/i.test(domain)) {
      fullPitch = `${readableTitle} is an AI-powered ${domain} platform built with ${stackStr} that automates complex workflows, extracts real-time insights, and delivers intelligent assistance for users.`;
    } else if (/Web3|Blockchain/i.test(domain)) {
      fullPitch = `${readableTitle} is a decentralized ${domain} application engineered with ${stackStr} to enable transparent verification, tamper-proof digital records, and trustless smart-contract workflows.`;
    } else if (/Cybersecurity|Security/i.test(domain)) {
      fullPitch = `${readableTitle} is a proactive ${domain} toolkit built using ${stackStr} to detect system vulnerabilities, monitor threat surfaces in real time, and protect critical user data.`;
    } else if (/IoT|Hardware/i.test(domain)) {
      fullPitch = `${readableTitle} is a smart ${domain} telemetry and control system powered by ${stackStr} for real-time sensor monitoring, automated edge alerts, and low-latency device management.`;
    } else {
      fullPitch = `${readableTitle} is a modern ${domain} solution built with ${stackStr} designed to solve real-world workflow bottlenecks through an intuitive interface and scalable architecture.`;
    }
  } else {
    fullPitch = rawIdea.charAt(0).toUpperCase() + rawIdea.slice(1);
    if (!/[.!?]$/.test(fullPitch)) {
      fullPitch += '.';
    }
  }

  // Compact 1-sentence pitch for table row (~140 chars max, clean word boundary)
  let shortDescription = fullPitch;
  if (fullPitch.length > 145) {
    const firstSentenceMatch = fullPitch.match(/^[^.!?]+[.!?]/);
    if (firstSentenceMatch && firstSentenceMatch[0].trim().length >= 35 && firstSentenceMatch[0].trim().length <= 150) {
      shortDescription = firstSentenceMatch[0].trim();
    } else {
      const sliced = fullPitch.slice(0, 140);
      const lastSpace = sliced.lastIndexOf(' ');
      shortDescription = (lastSpace > 80 ? sliced.slice(0, lastSpace) : sliced).replace(/[,;:\-–—]+$/, '').trim() + '.';
    }
  }

  // Concise 2-3 sentence overview for the modal box (~310 chars max so modal never overflows screen)
  let previewSummary = fullPitch;
  if (previewSummary.length > 310) {
    const sentences = previewSummary.match(/[^.!?]+[.!?]+/g);
    if (sentences && sentences.length > 0) {
      let acc = '';
      for (const s of sentences) {
        if ((acc + ' ' + s.trim()).trim().length <= 310) {
          acc = (acc + ' ' + s.trim()).trim();
        } else {
          break;
        }
      }
      if (acc.length >= 90) {
        previewSummary = acc;
      } else {
        const sliced = previewSummary.slice(0, 300);
        const lastSpace = sliced.lastIndexOf(' ');
        previewSummary = (lastSpace > 160 ? sliced.slice(0, lastSpace) : sliced).replace(/[,;:\-–—]+$/, '').trim() + '.';
      }
    } else {
      const sliced = previewSummary.slice(0, 300);
      const lastSpace = sliced.lastIndexOf(' ');
      previewSummary = (lastSpace > 160 ? sliced.slice(0, lastSpace) : sliced).replace(/[,;:\-–—]+$/, '').trim() + '.';
    }
  }

  let orgClean = String(participant?.organisation || '').replace(/\s+/g, ' ').trim();
  if (orgClean.length > 48) {
    orgClean = orgClean.slice(0, 45).replace(/\s+\S*$/, '').trim();
  }
  const expClean = String(participant?.experienceLevel || '').replace(/\s+/g, ' ').trim();

  const builderParts = [`${repo.builderName} (@${repo.builder})`];
  if (orgClean && orgClean.length > 2 && !/^(n\/?a|none|student|self)$/i.test(orgClean)) {
    builderParts.push(orgClean);
  }
  if (expClean && !/^(n\/?a|none)$/i.test(expClean)) {
    builderParts.push(expClean);
  }

  return {
    shortDescription,
    previewSummary,
    highlights: [
      `Track & Domain: ${domain} — built for practical real-world impact.`,
      `Tech Stack: ${technologies.join(' + ')}.`,
      `Builder: ${builderParts.join(' • ')}`
    ]
  };
}

function enrichRepositoryForClient(repo) {
  const cleanName = String(repo.name || '').trim();
  const technologies = Array.isArray(repo.technologies) ? repo.technologies : [];
  const regKey = repo.builderRegistrationId ? String(repo.builderRegistrationId).trim().toUpperCase() : '';
  const emailKey = repo.builderEmail ? String(repo.builderEmail).trim().toLowerCase() : '';
  const participant = (regKey && participantsByRegId.get(regKey)) || (emailKey && participantsByEmail.get(emailKey)) || null;

  const rawGithub = String(participant?.githubProfile || '').trim();
  const githubHandle = String(participant?.githubHandle || repo.builder || '').replace(/[^a-zA-Z0-9._-]/g, '-');
  const builderGithubUrl = /^https?:\/\/(www\.)?github\.com\/[a-zA-Z0-9._-]+/i.test(rawGithub)
    ? rawGithub.split(/\s+/)[0].replace(/\/+$/, '')
    : `https://github.com/${githubHandle}`;

  const ideaInfo = formatProjectIdeaForVoters(repo, participant);

  return {
    id: repo.id,
    recommendedRank: repo.recommendedRank,
    name: cleanName,
    description: ideaInfo.shortDescription,
    builder: repo.builder,
    builderName: repo.builderName,
    builderGithubUrl,
    primaryDomain: repo.primaryDomain,
    technologies,
    submittedAt: repo.submittedAt,
    avatarBg: Array.isArray(repo.avatarBg) ? repo.avatarBg : ['#0f172a', '#1e293b', '#94a3b8'],
    builderBg: Array.isArray(repo.builderBg) ? repo.builderBg : ['#090d16', '#1e293b', '#64748b'],
    previewSummary: ideaInfo.previewSummary,
    highlights: ideaInfo.highlights
  };
}

function loadCatalogRepositories() {
  if (cachedCatalog) return cachedCatalog;

  let loaded = null;
  if (useSqlite && db) {
    try {
      const stmt = db.prepare(`
        SELECT
          id,
          recommended_rank AS recommendedRank,
          name,
          description,
          builder,
          builder_name AS builderName,
          builder_email AS builderEmail,
          builder_registration_id AS builderRegistrationId,
          primary_domain AS primaryDomain,
          technologies_json AS technologiesJson,
          submitted_at AS submittedAt,
          avatar_bg_json AS avatarBgJson,
          builder_bg_json AS builderBgJson
        FROM aftercode_repositories
        ORDER BY recommended_rank ASC
      `);
      const rows = stmt.all();
      if (rows.length > 0) {
        loaded = rows.map(row => ({
          id: row.id,
          recommendedRank: row.recommendedRank,
          name: row.name,
          description: row.description,
          builder: row.builder,
          builderName: row.builderName,
          builderEmail: row.builderEmail || null,
          builderRegistrationId: row.builderRegistrationId || null,
          primaryDomain: row.primaryDomain,
          technologies: JSON.parse(row.technologiesJson || '[]'),
          submittedAt: row.submittedAt,
          avatarBg: JSON.parse(row.avatarBgJson || '["#0f172a","#1e293b","#94a3b8"]'),
          builderBg: JSON.parse(row.builderBgJson || '["#090d16","#1e293b","#64748b"]')
        }));
      }
    } catch (e) {
      console.error('[AfterCode] Failed to query aftercode_repositories:', e.message);
    }
  }
  if (!loaded) {
    loaded = loadSeedRepositoriesFromDisk();
  }

  cachedCatalog = loaded;
  cachedEnrichedCatalog = loaded.map(repo => enrichRepositoryForClient(repo));
  cachedRepoByIdMap = new Map();
  cachedOwnedRepoByRegIdMap = new Map();
  cachedOwnedRepoByEmailMap = new Map();

  for (const r of loaded) {
    cachedRepoByIdMap.set(r.id, r);
    if (r.builderRegistrationId) {
      cachedOwnedRepoByRegIdMap.set(String(r.builderRegistrationId).trim().toUpperCase(), r.id);
    }
    if (r.builderEmail) {
      cachedOwnedRepoByEmailMap.set(String(r.builderEmail).trim().toLowerCase(), r.id);
    }
  }

  return cachedCatalog;
}

// Warm up catalog cache at startup
loadCatalogRepositories();

function loadJsonVotes() {
  try {
    if (fs.existsSync(JSON_BACKUP_FILE)) {
      return JSON.parse(fs.readFileSync(JSON_BACKUP_FILE, 'utf-8'));
    }
  } catch (e) {}
  return [];
}

function saveJsonVotes(votes) {
  try {
    fs.writeFileSync(JSON_BACKUP_FILE, JSON.stringify(votes, null, 2), 'utf-8');
  } catch (e) {}
}

function escapeSql(str) {
  return String(str || '').replace(/'/g, "''");
}

function getAllRecordedVotes() {
  if (useSqlite && db && stmtSelectAllVotes) {
    try {
      return stmtSelectAllVotes.all();
    } catch (e) {
      console.error('[AfterCode] SQLite read error:', e.message);
    }
  }
  return loadJsonVotes();
}

function getVoteByEmailOrRegId(email, registrationId) {
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanRegId = String(registrationId || '').trim().toUpperCase();

  if (useSqlite && db) {
    try {
      if (cleanEmail && cleanRegId && stmtSelectVoteByEmailAndReg) {
        return stmtSelectVoteByEmailAndReg.get(cleanEmail, cleanRegId) || null;
      } else if (cleanEmail && stmtSelectVoteByEmail) {
        return stmtSelectVoteByEmail.get(cleanEmail) || null;
      }
    } catch (e) {}
  }

  const all = loadJsonVotes();
  return (
    all.find(
      v =>
        (cleanEmail && v.voterEmail === cleanEmail) ||
        (cleanRegId && v.registrationId === cleanRegId)
    ) || null
  );
}

function getRepositoriesWithVotes() {
  loadCatalogRepositories();
  const enriched = cachedEnrichedCatalog.slice();

  // Cryptographically shuffle repository order for every viewer so no project has a top-of-page bias
  for (let i = enriched.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    const temp = enriched[i];
    enriched[i] = enriched[j];
    enriched[j] = temp;
  }

  return enriched;
}

function getEventStats() {
  const catalog = loadCatalogRepositories();
  return {
    registeredBuilders: csvLoadedCount,
    totalRepositories: catalog.length
  };
}

async function getAdminVoteSummary() {
  const localVotes = getAllRecordedVotes();
  const remoteVotes = await getAllAftercodeVotesFromSupabase();
  const mergedByRegId = new Map();

  for (const v of localVotes) {
    if (v && v.registrationId) mergedByRegId.set(v.registrationId, v);
  }
  for (const v of remoteVotes) {
    if (v && v.registrationId) mergedByRegId.set(v.registrationId, v);
  }

  const allVotes = Array.from(mergedByRegId.values());
  const countsByRepoId = new Map();
  for (const v of allVotes) {
    countsByRepoId.set(v.repoId, (countsByRepoId.get(v.repoId) || 0) + 1);
  }

  const catalog = loadCatalogRepositories();
  const leaderboard = catalog
    .map(r => ({
      id: r.id,
      repoId: r.id,
      name: r.name,
      builder: r.builder,
      builderName: r.builderName,
      primaryDomain: r.primaryDomain,
      votes: countsByRepoId.get(r.id) || 0
    }))
    .sort((a, b) => b.votes - a.votes || a.name.localeCompare(b.name));

  return {
    totalVotesCast: allVotes.length,
    votes: allVotes,
    leaderboard
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Self-Voting Guard (Server-Side Enforcement of Rule #3)
// ─────────────────────────────────────────────────────────────────────────────

function isSelfVote(participant, repo) {
  if (!participant || !repo) return false;

  const voterEmail = (participant.email || '').trim().toLowerCase();
  const voterRegId = (participant.registrationId || '').trim().toUpperCase();
  const voterGhNorm = (participant.githubHandle || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');

  const builderEmail = (repo.builderEmail || '').trim().toLowerCase();
  const builderRegId = (repo.builderRegistrationId || '').trim().toUpperCase();
  const builderHandleNorm = (repo.builder || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');

  if (builderRegId && voterRegId) {
    if (voterRegId === builderRegId) return true;
    if (builderEmail && voterEmail && voterEmail === builderEmail) return true;
    return false;
  }

  if (builderEmail && voterEmail) {
    return voterEmail === builderEmail;
  }

  const voterEmailLocal = voterEmail.split('@')[0].replace(/[^a-z0-9]/g, '');
  const voterNameNorm = (participant.name || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const builderNameNorm = (repo.builderName || '').trim().toLowerCase().replace(/\s+/g, ' ');

  if (builderNameNorm && voterNameNorm && voterNameNorm === builderNameNorm) return true;
  if (builderHandleNorm && voterGhNorm && voterGhNorm === builderHandleNorm) return true;
  if (builderHandleNorm && voterEmailLocal && voterEmailLocal === builderHandleNorm) return true;

  return false;
}

function getOwnedRepoIdForParticipant(participant) {
  if (!participant) return null;
  loadCatalogRepositories();
  const regId = String(participant.registrationId || '').trim().toUpperCase();
  if (regId && cachedOwnedRepoByRegIdMap.has(regId)) {
    return cachedOwnedRepoByRegIdMap.get(regId);
  }
  const email = String(participant.email || '').trim().toLowerCase();
  if (email && cachedOwnedRepoByEmailMap.has(email)) {
    return cachedOwnedRepoByEmailMap.get(email);
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Atomic Vote Submission (Rule #1, #2, #3, #4, #5 — Per-Voter Lock + SQLite + Supabase)
// ─────────────────────────────────────────────────────────────────────────────

const activeVoterLocks = new Set();

async function castVoteAtomically({ email, registrationId, repoId, ip, userAgent }) {
  // 1. Validate eligibility against official Unstop CSV on the server (O(1) Map lookup)
  const eligibility = findEligibleParticipant(email, registrationId);
  if (!eligibility.found || !eligibility.eligible || !eligibility.participant) {
    return {
      status: 403,
      success: false,
      code: 'INELIGIBLE_PARTICIPANT',
      message: eligibility.reason || 'Rule #1: Only verified Unstop AfterCode 2026 participants with Complete registration can vote.'
    };
  }

  const participant = eligibility.participant;

  // 2. Validate repository exists in catalog (O(1) Map lookup)
  const cleanRepoId = String(repoId || '').trim();
  loadCatalogRepositories();
  const targetRepo = cachedRepoByIdMap.get(cleanRepoId);
  if (!targetRepo) {
    return {
      status: 400,
      success: false,
      code: 'INVALID_REPOSITORY',
      message: 'Selected repository was not found.'
    };
  }

  // 3. Enforce no self-voting (Rule #3) before and independent of voting window
  if (isSelfVote(participant, targetRepo)) {
    return {
      status: 403,
      success: false,
      code: 'SELF_VOTE_FORBIDDEN',
      message: `Rule #3: You cannot vote for your own repository (${targetRepo.name}).`
    };
  }

  // 4. Fast check if participant has already voted in local SQLite (Rule #2 & #4)
  const existingPrecheck = getVoteByEmailOrRegId(participant.email, participant.registrationId);
  if (existingPrecheck) {
    return {
      status: 409,
      success: false,
      code: 'ALREADY_VOTED',
      message: `Rule #2 & #4: You have already cast your 1 final vote for "${existingPrecheck.repoName}". Votes are final and cannot be changed.`,
      vote: existingPrecheck
    };
  }

  // 5. Enforce configured voting window (Rule #5)
  const windowConfig = getVotingWindowConfig();
  if (!windowConfig.isOpen) {
    return {
      status: 403,
      success: false,
      code: windowConfig.status === 'NOT_STARTED' ? 'VOTING_NOT_STARTED' : 'VOTING_ENDED',
      message: windowConfig.message,
      votingWindow: windowConfig
    };
  }

  // 6. Per-voter concurrency lock so 500+ different voters execute simultaneously without blocking each other
  const voterLockKey = participant.registrationId || participant.email;
  if (activeVoterLocks.has(voterLockKey)) {
    return {
      status: 409,
      success: false,
      code: 'CONCURRENT_REQUEST',
      message: 'Vote submission already in progress for your account. Please wait.'
    };
  }

  activeVoterLocks.add(voterLockKey);
  const createdAt = new Date().toISOString();

  try {
    if (useSqlite && db) {
      db.exec('BEGIN IMMEDIATE');
      try {
        const existing = stmtSelectVoteByEmailAndReg
          ? stmtSelectVoteByEmailAndReg.get(participant.email, participant.registrationId)
          : null;
        if (existing) {
          db.exec('ROLLBACK');
          return {
            status: 409,
            success: false,
            code: 'ALREADY_VOTED',
            message: `Rule #2 & #4: You have already cast your 1 final vote for "${existing.repoName}". Votes are final and cannot be changed.`,
            vote: existing
          };
        }

        stmtInsertVote.run(
          participant.registrationId,
          participant.email,
          participant.name,
          targetRepo.id,
          targetRepo.name,
          createdAt,
          String(ip || '').slice(0, 64),
          String(userAgent || '').slice(0, 255)
        );
        db.exec('COMMIT');
      } catch (txErr) {
        try {
          db.exec('ROLLBACK');
        } catch (rbErr) {}

        if (String(txErr.message || '').includes('UNIQUE constraint failed')) {
          const existingVote = getVoteByEmailOrRegId(participant.email, participant.registrationId);
          return {
            status: 409,
            success: false,
            code: 'ALREADY_VOTED',
            message: 'Rule #2 & #4: You have already cast your 1 final vote. Duplicate votes are blocked.',
            vote: existingVote
          };
        }
        throw txErr;
      }
    } else {
      const allVotes = loadJsonVotes();
      const dup = allVotes.find(
        v => v.voterEmail === participant.email || v.registrationId === participant.registrationId
      );
      if (dup) {
        return {
          status: 409,
          success: false,
          code: 'ALREADY_VOTED',
          message: `Rule #2 & #4: You have already cast your 1 final vote for "${dup.repoName}".`,
          vote: dup
        };
      }
      allVotes.push({
        id: allVotes.length + 1,
        registrationId: participant.registrationId,
        voterEmail: participant.email,
        voterName: participant.name,
        repoId: targetRepo.id,
        repoName: targetRepo.name,
        createdAt,
        ip: String(ip || '').slice(0, 64)
      });
      saveJsonVotes(allVotes);
    }

    // Append to SQL audit ledger asynchronously without blocking event loop
    const sqlLine = `INSERT INTO aftercode_votes (registration_id, voter_email, voter_name, repo_id, repo_name, created_at, ip) VALUES ('${escapeSql(
      participant.registrationId
    )}', '${escapeSql(participant.email)}', '${escapeSql(participant.name)}', '${escapeSql(
      targetRepo.id
    )}', '${escapeSql(targetRepo.name)}', '${escapeSql(createdAt)}', '${escapeSql(ip)}');\n`;
    fs.promises.appendFile(SQL_DUMP_FILE, sqlLine, 'utf-8').catch(() => {});

    // Persist vote privately to Supabase `aftercode_votes` table on the backend (non-blocking / fast timeout)
    const sbPromise = saveAftercodeVoteToSupabase({
      registrationId: participant.registrationId,
      voterEmail: participant.email,
      voterName: participant.name,
      repoId: targetRepo.id,
      repoName: targetRepo.name,
      ip: ip || null,
      userAgent: userAgent || null,
      createdAt
    }).catch(() => ({ success: false }));

    let sbTimer = null;
    const sbResult = await Promise.race([
      sbPromise,
      new Promise(resolve => {
        sbTimer = setTimeout(() => resolve({ success: false, pendingAsync: true }), 250);
        if (sbTimer && typeof sbTimer.unref === 'function') sbTimer.unref();
      })
    ]);
    if (sbTimer) clearTimeout(sbTimer);

    const recordedVote = getVoteByEmailOrRegId(participant.email, participant.registrationId) || {
      registrationId: participant.registrationId,
      voterEmail: participant.email,
      voterName: participant.name,
      repoId: targetRepo.id,
      repoName: targetRepo.name,
      createdAt
    };

    return {
      status: 200,
      success: true,
      code: 'VOTE_RECORDED',
      supabaseSynced: Boolean(sbResult && sbResult.success),
      message: `Your final vote for "${targetRepo.name}" by @${targetRepo.builder} has been securely recorded!`,
      vote: recordedVote
    };
  } catch (err) {
    console.error('[AfterCode] Atomic vote error:', err.message);
    return {
      status: 500,
      success: false,
      code: 'INTERNAL_ERROR',
      message: 'Failed to record vote due to a server error. Your vote was not consumed.'
    };
  } finally {
    activeVoterLocks.delete(voterLockKey);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Session Token Signing, Cookie Parsing & Supabase OAuth Verification
// ─────────────────────────────────────────────────────────────────────────────

const COOKIE_NAME = 'grevix_aftercode_session';
const SESSION_MAX_AGE_SEC = 7 * 24 * 60 * 60; // 7 days

function createSignedSessionToken(payload) {
  const data = {
    email: String(payload.email || '').trim().toLowerCase(),
    name: String(payload.name || '').trim(),
    registrationId: payload.registrationId ? String(payload.registrationId).trim().toUpperCase() : null,
    authMethod: payload.authMethod || 'unstop_verified',
    iat: Date.now()
  };
  const encoded = Buffer.from(JSON.stringify(data), 'utf-8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifySignedSessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  if (!encoded || !sig) return null;

  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8'));
    if (!parsed || !parsed.email) return null;
    if (Date.now() - (parsed.iat || 0) > SESSION_MAX_AGE_SEC * 1000) return null;
    return parsed;
  } catch (e) {
    return null;
  }
}

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    if (!value) return;
    try {
      list[name] = decodeURIComponent(value);
    } catch (e) {
      list[name] = value;
    }
  });
  return list;
}

/**
 * Resolve current user session from either:
 * 1. `Authorization: Bearer <supabase_access_token>` (verified via Supabase Auth `getUser`)
 * 2. `grevix_aftercode_session` HMAC-signed HttpOnly cookie
 */
async function resolveVoterSessionFromRequest(req) {
  let email = null;
  let name = null;
  let registrationId = null;
  let authMethod = null;

  // 1. Check Authorization Bearer token (Supabase Google OAuth / JWT)
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    const accessToken = authHeader.slice(7).trim();
    if (accessToken) {
      try {
        const sb = getSupabaseAdmin();
        const { data, error } = await sb.auth.getUser(accessToken);
        if (!error && data && data.user && data.user.email) {
          email = data.user.email.trim().toLowerCase();
          name =
            data.user.user_metadata?.full_name ||
            data.user.user_metadata?.name ||
            email.split('@')[0];
          authMethod = 'supabase_oauth';
        }
      } catch (e) {}
    }
  }

  // 2. Check signed HttpOnly session cookie
  if (!email) {
    const cookies = parseCookies(req.headers.cookie || '');
    const sessionToken = cookies[COOKIE_NAME];
    const verified = verifySignedSessionToken(sessionToken);
    if (verified && verified.email) {
      email = verified.email;
      name = verified.name;
      registrationId = verified.registrationId;
      authMethod = verified.authMethod || 'unstop_session';
    }
  }

  if (!email) {
    return {
      authenticated: false,
      eligible: false,
      authMethod: null,
      user: null,
      vote: null
    };
  }

  // Validate signed-in user against the official Unstop CSV (O(1) Map lookup)
  const csvCheck = findEligibleParticipant(email, registrationId);
  const existingVote = getVoteByEmailOrRegId(
    email,
    csvCheck.participant ? csvCheck.participant.registrationId : registrationId
  );

  // Determine if the signed-in user owns any repository in the list (O(1) Map lookup)
  const ownedRepoId = csvCheck.participant ? getOwnedRepoIdForParticipant(csvCheck.participant) : null;

  return {
    authenticated: true,
    eligible: csvCheck.eligible,
    eligibilityReason: csvCheck.reason,
    authMethod,
    user: {
      name: csvCheck.participant ? csvCheck.participant.name : name || email.split('@')[0],
      email,
      registrationId: csvCheck.participant ? csvCheck.participant.registrationId : null,
      organisation: csvCheck.participant ? csvCheck.participant.organisation : null,
      ownedRepoId
    },
    vote: existingVote
  };
}

function getAuthInfrastructureInfo() {
  const supabaseUrl =
    process.env.SUPABASE_URL ||
    process.env.NEXT_PUBLIC_SUPABASE_URL ||
    'https://ahpvlurewprpqbopfyrt.supabase.co';
  const supabaseAnonKey =
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    null;

  return {
    supabaseUrl,
    googleOAuthConfigured: Boolean(supabaseAnonKey),
    supabaseAnonKey: supabaseAnonKey || null,
    eligibleParticipantsCount: csvLoadedCount
  };
}

module.exports = {
  COOKIE_NAME,
  SESSION_MAX_AGE_SEC,
  getVotingWindowConfig,
  findEligibleParticipant,
  getRepositoriesWithVotes,
  getEventStats,
  getAdminVoteSummary,
  castVoteAtomically,
  createSignedSessionToken,
  resolveVoterSessionFromRequest,
  getSupabaseAdmin,
  getAuthInfrastructureInfo,
  getAllRecordedVotes
};
