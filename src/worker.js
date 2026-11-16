import { neon } from '@neondatabase/serverless';

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
const PBKDF2_ITERATIONS = 310000;
const COOKIE_NAME = 'vaani_session';
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, private',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      ...headers
    }
  });
}

function query(sql, parts, ...values) {
  let statement = String(parts[0] || '');
  const placeholder = String.fromCharCode(36);
  for (let index = 1; index < parts.length; index++) {
    statement += placeholder + index + String(parts[index] || '');
  }
  return sql.query(statement, values);
}

function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function fromBase64url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt,
    iterations: PBKDF2_ITERATIONS,
    hash: 'SHA-256'
  }, key, 256);
  return 'pbkdf2_sha256$' + PBKDF2_ITERATIONS + '$' + base64url(salt) + '$' + base64url(new Uint8Array(bits));
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterationText, saltText, digestText] = String(stored || '').split('$');
    const iterations = Number(iterationText);
    if (algorithm !== 'pbkdf2_sha256' || !Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false;
    const salt = fromBase64url(saltText);
    const expected = fromBase64url(digestText);
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    }, key, expected.length * 8);
    const actual = new Uint8Array(bits);
    if (actual.length !== expected.length) return false;
    let difference = 0;
    for (let index = 0; index < actual.length; index++) difference |= actual[index] ^ expected[index];
    return difference === 0;
  } catch {
    return false;
  }
}

function readCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  for (const part of cookie.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return null;
}

function sessionCookie(token) {
  return COOKIE_NAME + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + SESSION_TTL_SECONDS;
}

function clearedSessionCookie() {
  return COOKIE_NAME + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';
}

function isSameOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function readJson(request) {
  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > 12000) throw new Error('Request is too large.');
  const text = await request.text();
  if (text.length > 12000) throw new Error('Request is too large.');
  try {
    return JSON.parse(text || '{}');
  } catch {
    throw new Error('Invalid JSON body.');
  }
}

function publicUser(row) {
  return {
    id: row.id,
    email: row.email,
    name: row.display_name,
    displayName: row.display_name,
    accountType: row.account_type,
    role: row.role,
    isDeveloper: row.is_developer === true,
    isPro: false,
    pro: false
  };
}

function publicBot(row) {
  return {
    id: row.id,
    name: row.name,
    handle: row.handle,
    astrologySystem: row.astrology_system,
    specialty: row.specialty,
    bio: row.bio,
    isAI: row.is_ai === true,
    enabled: row.enabled === true
  };
}

async function sessionUser(request, sql) {
  const token = readCookie(request, COOKIE_NAME);
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const rows = await query(sql, [
    'SELECT u.id, u.email, u.display_name, u.account_type, u.role, u.is_developer ' +
    'FROM app_sessions s JOIN app_users u ON u.id = s.user_id ' +
    'WHERE s.token_hash = ', ' AND s.expires_at > now() LIMIT 1'
  ], tokenHash);
  return rows[0] ? publicUser(rows[0]) : null;
}

async function createSession(request, sql, user) {
  const token = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
  await query(sql, [
    'INSERT INTO app_sessions (token_hash, user_id, expires_at) VALUES (',
    ', ',
    ', ',
    ')'
  ], tokenHash, user.id, expiresAt);
  await query(sql, ['UPDATE app_users SET last_login_at = now() WHERE id = ', ''], user.id);
  return json({ ok: true, user: publicUser(user) }, 200, { 'Set-Cookie': sessionCookie(token) });
}

async function authenticate(request, env, sql, developerOnly = false) {
  if (!isSameOrigin(request)) return json({ error: 'Request origin could not be verified.' }, 403);
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!email || !password || email.length > 254 || password.length > 256) {
    return json({ error: 'Email or password is incorrect.' }, 401);
  }

  const rows = await query(sql, [
    'SELECT id, email, display_name, account_type, role, is_developer, password_hash ' +
    'FROM app_users WHERE lower(email) = ', ' LIMIT 1'
  ], email);
  const user = rows[0];
  const passwordOk = await verifyPassword(password, user?.password_hash);
  if (!user || !passwordOk) return json({ error: 'Email or password is incorrect.' }, 401);
  if (developerOnly && !(user.role === 'developer' && user.is_developer === true)) {
    return json({ error: 'This account does not have developer access.' }, 403);
  }
  if (!developerOnly && user.role === 'developer') {
    return json({ error: 'Use the Developer tab for this account.' }, 403);
  }
  return createSession(request, sql, user);
}

async function signUp(request, sql) {
  if (!isSameOrigin(request)) return json({ error: 'Request origin could not be verified.' }, 403);
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  const displayName = String(body.name || '').trim();
  const accountType = body.accountType === 'astrologer' ? 'astrologer' : 'seeker';
  const password = String(body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return json({ error: 'Enter a valid email address.' }, 400);
  }
  if (displayName.length < 2 || displayName.length > 48) return json({ error: 'Name must be 2–48 characters.' }, 400);
  if (password.length < 8 || password.length > 256) return json({ error: 'Password must be at least 8 characters.' }, 400);

  const passwordHash = await hashPassword(password);
  const id = crypto.randomUUID();
  try {
    const rows = await query(sql, [
      'INSERT INTO app_users (id, email, display_name, account_type, role, is_developer, password_hash, email_verified) VALUES (',
      ', ',
      ', ',
      ', ',
      ', ',
      ', ',
      ', ',
      ', false) RETURNING id, email, display_name, account_type, role, is_developer'
    ], id, email, displayName, accountType, 'user', false, passwordHash);
    return createSession(request, sql, rows[0]);
  } catch (error) {
    if (String(error?.code || '') === '23505') return json({ error: 'An account with that email already exists.' }, 409);
    throw error;
  }
}

async function requireDeveloper(request, sql) {
  const user = await sessionUser(request, sql);
  if (!user) return { response: json({ error: 'Please sign in again.' }, 401) };
  if (user.role !== 'developer' || user.isDeveloper !== true) {
    return { response: json({ error: 'Developer access required.' }, 403) };
  }
  return { user };
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Static website requests must keep working even before the database secret is configured.
  if (!path.startsWith('/api/')) {
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return json({ error: 'Static asset binding ASSETS is not configured.' }, 500);
  }

  if (!env.DATABASE_URL) return json({ error: 'DATABASE_URL secret is not configured on this Worker.' }, 503);
  const sql = neon(env.DATABASE_URL);

  if (request.method === 'GET' && path === '/api/health') {
    const rows = await query(sql, ['SELECT now() AS database_time']);
    return json({ ok: true, database: 'connected', time: rows[0].database_time });
  }

  if (request.method === 'POST' && path === '/api/auth/sign-in') {
    return authenticate(request, env, sql, false);
  }
  if (request.method === 'POST' && path === '/api/developer/sign-in') {
    return authenticate(request, env, sql, true);
  }
  if (request.method === 'POST' && path === '/api/auth/sign-up') {
    return signUp(request, sql);
  }
  if (request.method === 'GET' && path === '/api/auth/session') {
    const user = await sessionUser(request, sql);
    return json({ user });
  }
  if (request.method === 'POST' && path === '/api/auth/sign-out') {
    if (!isSameOrigin(request)) return json({ error: 'Request origin could not be verified.' }, 403);
    const token = readCookie(request, COOKIE_NAME);
    if (token) await query(sql, ['DELETE FROM app_sessions WHERE token_hash = ', ''], await sha256Hex(token));
    return json({ ok: true }, 200, { 'Set-Cookie': clearedSessionCookie() });
  }

  if (request.method === 'GET' && path === '/api/bots') {
    const rows = await query(sql, [
      'SELECT id, name, handle, astrology_system, specialty, bio, is_ai, enabled ' +
      'FROM ai_bots WHERE enabled = true ORDER BY name'
    ]);
    return json({ bots: rows.map(publicBot) });
  }

  if (path === '/api/developer/bots' && request.method === 'GET') {
    const access = await requireDeveloper(request, sql);
    if (access.response) return access.response;
    const rows = await query(sql, [
      'SELECT id, name, handle, astrology_system, specialty, bio, is_ai, enabled ' +
      'FROM ai_bots ORDER BY name'
    ]);
    return json({ bots: rows.map(publicBot) });
  }

  const botMatch = path.match(/^\/api\/developer\/bots\/([a-z0-9_-]+)$/i);
  if (botMatch && request.method === 'PATCH') {
    if (!isSameOrigin(request)) return json({ error: 'Request origin could not be verified.' }, 403);
    const access = await requireDeveloper(request, sql);
    if (access.response) return access.response;
    const body = await readJson(request);
    if (typeof body.enabled !== 'boolean') return json({ error: 'enabled must be true or false.' }, 400);
    const rows = await query(sql, [
      'UPDATE ai_bots SET enabled = ', ', updated_at = now() WHERE id = ', ' ' +
      'RETURNING id, name, handle, astrology_system, specialty, bio, is_ai, enabled'
    ], body.enabled, botMatch[1]);
    if (!rows[0]) return json({ error: 'Bot not found.' }, 404);
    return json({ bot: publicBot(rows[0]) });
  }

  return json({ error: 'API route not found.' }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handleApi(request, env);
    } catch (error) {
      console.error('Vaani Worker error:', error?.message || error);
      return json({ error: 'The server could not complete this request.' }, 500);
    }
  }
};
