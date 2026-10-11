/**
 * supabaseService.js
 * Server-side Supabase integration using the SERVICE ROLE KEY.
 * This key has full bypass of Row Level Security — NEVER expose it to the client.
 * All tables have RLS enabled with "No public access" policies,
 * so only this server-side service (with service role key) can read/write data.
 */

// Automatically load .env file if present
try {
  const fs = require('fs');
  const path = require('path');
  const envPath = path.join(__dirname, '..', '.env');
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

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_PUBLISHABLE_KEY ||
  process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
  '';

// Initialize Supabase admin client (service role — bypasses RLS)
let supabase = null;

function getSupabaseAdmin() {
  if (!supabase && SUPABASE_URL && SUPABASE_SERVICE_KEY) {
    supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false }
    });
  }
  return supabase;
}

// ─────────────────────────────────────────────
// JOIN APPLICATIONS — store "interested in joining" submissions
// ─────────────────────────────────────────────

/**
 * Save a join application to Supabase.
 * Table: join_applications (id, email, github, interest, status, ip, submitted_at)
 * @returns {Promise<{success: boolean, isDuplicate: boolean, field?: string}>}
 */
async function saveJoinApplication({ email, github, interest, ip }) {
  const sb = getSupabaseAdmin();
  try {
    const { error } = await sb.from('join_applications').insert([{
      email: email.trim().toLowerCase(),
      github: github.trim(),
      interest: interest.trim(),
      status: 'Received',
      ip: ip || null
    }]);

    if (error) {
      // Unique constraint violation = duplicate
      if (error.code === '23505') {
        const field = error.message.includes('github') ? 'github' : 'email';
        return { success: false, isDuplicate: true, field };
      }
      console.error('[Supabase] saveJoinApplication error:', error.message);
      return { success: false, isDuplicate: false, error: error.message };
    }

    return { success: true, isDuplicate: false };
  } catch (err) {
    console.error('[Supabase] saveJoinApplication exception:', err.message);
    return { success: false, isDuplicate: false, error: err.message };
  }
}

// ─────────────────────────────────────────────
// AMBASSADOR PROOF SUBMISSIONS — store proof image + metadata
// ─────────────────────────────────────────────

/**
 * Upload a proof screenshot to Supabase Storage (private bucket: ambassador-proofs).
 * @param {Buffer} fileBuffer - The file buffer
 * @param {string} ambassadorCode - e.g. GRVX001
 * @param {string} filename - original filename
 * @param {string} mimeType - e.g. image/png
 * @returns {Promise<{success: boolean, path?: string, url?: string, error?: string}>}
 */
async function uploadProofScreenshot(fileBuffer, ambassadorCode, filename, mimeType) {
  const sb = getSupabaseAdmin();
  try {
    const safeCode = (ambassadorCode || 'UNKNOWN').replace(/[^A-Za-z0-9]/g, '');
    const ts = Date.now();
    const safeFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '_').toLowerCase();
    const storagePath = `proofs/${safeCode}/${ts}_${safeFilename}`;

    const { error } = await sb.storage
      .from('ambassador-proofs')
      .upload(storagePath, fileBuffer, {
        contentType: mimeType || 'image/png',
        upsert: false
      });

    if (error) {
      console.error('[Supabase] uploadProofScreenshot error:', error.message);
      return { success: false, error: error.message };
    }

    return { success: true, path: storagePath };
  } catch (err) {
    console.error('[Supabase] uploadProofScreenshot exception:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Save ambassador proof submission metadata to Supabase.
 * Table: ambassador_proof_submissions (id, ambassador_code, screenshot_path, message, ip, submitted_at)
 */
async function saveProofSubmission({ ambassadorCode, screenshotPath, message, ip }) {
  const sb = getSupabaseAdmin();
  try {
    const { error } = await sb.from('ambassador_proof_submissions').insert([{
      ambassador_code: (ambassadorCode || '').toUpperCase().trim(),
      screenshot_path: screenshotPath || null,
      message: (message || '').trim() || null,
      ip: ip || null
    }]);

    if (error) {
      console.error('[Supabase] saveProofSubmission error:', error.message);
      return { success: false, error: error.message };
    }

    return { success: true };
  } catch (err) {
    console.error('[Supabase] saveProofSubmission exception:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Get all ambassador proof submissions (admin only).
 */
async function getAllProofSubmissions() {
  const sb = getSupabaseAdmin();
  const { data, error } = await sb
    .from('ambassador_proof_submissions')
    .select('*')
    .order('submitted_at', { ascending: false });

  if (error) throw new Error(error.message);
  return data || [];
}

/**
 * Get all join applications (admin only).
 */
async function getAllJoinApplications() {
  const sb = getSupabaseAdmin();
  const { data, error } = await sb
    .from('join_applications')
    .select('*')
    .order('submitted_at', { ascending: false });

  if (error) throw new Error(error.message);
  return data || [];
}

/**
 * Save an ambassador code registration to Supabase table: ambassadors
 */
async function saveAmbassador({ code, name, email, ip }) {
  const sb = getSupabaseAdmin();
  try {
    const { data, error } = await sb.from('ambassadors').insert([{
      code: code.trim().toUpperCase(),
      name: name.trim(),
      email: email.trim().toLowerCase(),
      ip: ip || null
    }]).select();

    if (error) {
      console.error('[Supabase] saveAmbassador error:', error.message);
      return { success: false, error: error.message };
    }
    return { success: true, data };
  } catch (err) {
    console.error('[Supabase] saveAmbassador exception:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Check if ambassador email is already in Supabase
 */
async function getAmbassadorByEmail(email) {
  const sb = getSupabaseAdmin();
  try {
    const { data, error } = await sb
      .from('ambassadors')
      .select('*')
      .eq('email', email.trim().toLowerCase())
      .maybeSingle();

    if (error) return null;
    return data;
  } catch (e) {
    return null;
  }
}

/**
 * Get all registered ambassadors from Supabase (admin only)
 */
async function getAllAmbassadorsFromSupabase() {
  const sb = getSupabaseAdmin();
  const { data, error } = await sb
    .from('ambassadors')
    .select('*')
    .order('id', { ascending: true });

  if (error) throw new Error(error.message);
  return data || [];
}

/**
 * Get existing or atomically generate next unique ambassador code in Supabase.
 * Format: GRVX001, GRVX002, GRVX003, ... (unlimited sequential numbers)
 * Guaranteed: One Gmail/Email ID -> exactly one unique code across all devices and instances.
 */
async function getOrGenerateCodeSupabase(rawName, rawEmail, ip = '127.0.0.1') {
  const name = String(rawName || '').trim();
  const email = String(rawEmail || '').trim().toLowerCase();

  if (!name || name.length < 2) {
    throw new Error('Please enter your full name (minimum 2 characters).');
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    throw new Error('Please enter a valid Gmail or email address.');
  }

  const sb = getSupabaseAdmin();

  // 1. Check if email already registered in Supabase
  const existing = await getAmbassadorByEmail(email);
  if (existing && existing.code) {
    return {
      success: true,
      code: existing.code,
      alreadyRegistered: true,
      name: existing.name || name
    };
  }

  // 2. Fetch all existing codes to determine the next sequential number
  const { data: rows, error: listErr } = await sb
    .from('ambassadors')
    .select('code');

  if (listErr) {
    console.error('[Supabase] Failed to fetch ambassadors for code generation:', listErr.message);
    throw new Error('Unable to connect to database. Please try again.');
  }

  const existingCodes = new Set();
  let maxSeq = 0;
  for (const r of rows || []) {
    if (r.code) {
      existingCodes.add(r.code.toUpperCase());
      const match = r.code.match(/GRVX(\d+)/i);
      if (match) {
        const num = parseInt(match[1], 10);
        if (num > maxSeq) maxSeq = num;
      }
    }
  }

  let nextSeq = Math.max(maxSeq + 1, (rows ? rows.length : 0) + 1);
  let generatedCode = 'GRVX' + String(nextSeq).padStart(3, '0');
  while (existingCodes.has(generatedCode)) {
    nextSeq++;
    generatedCode = 'GRVX' + String(nextSeq).padStart(3, '0');
  }

  // 3. Insert into Supabase table
  const { data: inserted, error: insertErr } = await sb
    .from('ambassadors')
    .insert([{
      code: generatedCode,
      name,
      email,
      ip: ip || null
    }])
    .select()
    .maybeSingle();

  if (insertErr) {
    // If concurrent insert occurred on the same email, fetch and return it
    if (insertErr.message && insertErr.message.includes('ambassadors_email_key')) {
      const raceExisting = await getAmbassadorByEmail(email);
      if (raceExisting) {
        return {
          success: true,
          code: raceExisting.code,
          alreadyRegistered: true,
          name: raceExisting.name || name
        };
      }
    }

    // If code collision occurred concurrently, retry next sequence
    if (insertErr.message && insertErr.message.includes('ambassadors_code_key')) {
      nextSeq++;
      generatedCode = 'GRVX' + String(nextSeq).padStart(3, '0');
      const retryInsert = await sb
        .from('ambassadors')
        .insert([{
          code: generatedCode,
          name,
          email,
          ip: ip || null
        }])
        .select()
        .maybeSingle();

      if (!retryInsert.error) {
        return {
          success: true,
          code: generatedCode,
          alreadyRegistered: false,
          name
        };
      }
    }

    console.error('[Supabase] Ambassador insert error:', insertErr.message);
    throw new Error('Failed to register ambassador code: ' + insertErr.message);
  }

  return {
    success: true,
    code: generatedCode,
    alreadyRegistered: false,
    name
  };
}

// ─────────────────────────────────────────────
// AFTERCODE 2026 VOTES — private backend vote storage in Supabase
// Table: aftercode_votes (id, registration_id, voter_email, voter_name, repo_id, repo_name, ip, user_agent, created_at)
// ─────────────────────────────────────────────

async function saveAftercodeVoteToSupabase({
  registrationId,
  voterEmail,
  voterName,
  repoId,
  repoName,
  ip,
  userAgent,
  createdAt
}) {
  const sb = getSupabaseAdmin();
  try {
    const { data, error } = await sb
      .from('aftercode_votes')
      .insert([
        {
          registration_id: String(registrationId || '').trim().toUpperCase(),
          voter_email: String(voterEmail || '').trim().toLowerCase(),
          voter_name: String(voterName || '').trim(),
          repo_id: String(repoId || '').trim(),
          repo_name: String(repoName || '').trim(),
          ip: ip || null,
          user_agent: userAgent ? String(userAgent).slice(0, 255) : null,
          created_at: createdAt || new Date().toISOString()
        }
      ])
      .select()
      .maybeSingle();

    if (error) {
      if (error.code === '23505') {
        return { success: false, isDuplicate: true, error: error.message };
      }
      return { success: false, isDuplicate: false, error: error.message };
    }

    return { success: true, isDuplicate: false, data };
  } catch (err) {
    return { success: false, isDuplicate: false, error: err.message };
  }
}

async function getAftercodeVoteFromSupabase(email, registrationId) {
  const sb = getSupabaseAdmin();
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanRegId = String(registrationId || '').trim().toUpperCase();

  try {
    let query = sb
      .from('aftercode_votes')
      .select('id, registration_id, voter_email, voter_name, repo_id, repo_name, created_at')
      .limit(1);

    if (cleanEmail && cleanRegId) {
      query = query.or(`voter_email.eq.${cleanEmail},registration_id.eq.${cleanRegId}`);
    } else if (cleanEmail) {
      query = query.eq('voter_email', cleanEmail);
    } else if (cleanRegId) {
      query = query.eq('registration_id', cleanRegId);
    } else {
      return null;
    }

    const { data, error } = await query.maybeSingle();
    if (error || !data) return null;

    return {
      id: data.id,
      registrationId: data.registration_id,
      voterEmail: data.voter_email,
      voterName: data.voter_name,
      repoId: data.repo_id,
      repoName: data.repo_name,
      createdAt: data.created_at
    };
  } catch (e) {
    return null;
  }
}

async function getAllAftercodeVotesFromSupabase() {
  const sb = getSupabaseAdmin();
  try {
    const { data, error } = await sb
      .from('aftercode_votes')
      .select('id, registration_id, voter_email, voter_name, repo_id, repo_name, created_at, ip')
      .order('created_at', { ascending: true });

    if (error || !Array.isArray(data)) return [];
    return data.map(row => ({
      id: row.id,
      registrationId: row.registration_id,
      voterEmail: row.voter_email,
      voterName: row.voter_name,
      repoId: row.repo_id,
      repoName: row.repo_name,
      createdAt: row.created_at,
      ip: row.ip || null
    }));
  } catch (e) {
    return [];
  }
}

module.exports = {
  getSupabaseAdmin,
  saveJoinApplication,
  uploadProofScreenshot,
  saveProofSubmission,
  getAllProofSubmissions,
  getAllJoinApplications,
  saveAmbassador,
  getAmbassadorByEmail,
  getAllAmbassadorsFromSupabase,
  getOrGenerateCodeSupabase,
  saveAftercodeVoteToSupabase,
  getAftercodeVoteFromSupabase,
  getAllAftercodeVotesFromSupabase
};
