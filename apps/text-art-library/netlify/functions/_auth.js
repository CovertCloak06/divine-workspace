// Shared auth helper for all editor-write functions.
//
// Source of truth precedence:
//   1) Netlify Blob `auth/password` (format "<saltHex>:<hashHex>", PBKDF2-SHA256)
//   2) Process env EDITOR_PASSWORD (plaintext) — used until the user rotates
//
// Once the blob exists it is the ONLY accepted password. Env var becomes
// inert. To "factory reset" the blob password, delete `auth/password` from
// the Netlify Blobs dashboard.

import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';

export function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}

export function hashPassword(plain, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const hash = crypto.pbkdf2Sync(plain, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
  return `${saltHex}:${hash.toString('hex')}`;
}

function verifyHash(plain, stored) {
  const [saltHex, hashHex] = (stored || '').split(':');
  if (!saltHex || !hashHex) return false;
  let expected;
  try { expected = Buffer.from(hashHex, 'hex'); }
  catch { return false; }
  const actual = crypto.pbkdf2Sync(
    plain, Buffer.from(saltHex, 'hex'),
    PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST,
  );
  if (actual.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(actual, expected); }
  catch { return false; }
}

/* Extract the password string the client provided via Authorization: Bearer */
export function extractBearer(event) {
  const h = event.headers || {};
  const raw = h.authorization || h.Authorization || '';
  return raw.replace(/^Bearer\s+/i, '');
}

/* Returns true iff `provided` matches the current editor password.
 * Reads from blob first; falls back to env var when blob is empty. */
export async function verifyPassword(provided) {
  if (!provided) return false;
  try {
    const store = getStore('frostline');
    const stored = await store.get('auth/password');
    if (stored) return verifyHash(provided, stored);
  } catch {
    // blob unavailable — fall through to env var
  }
  const envPw = process.env.EDITOR_PASSWORD;
  if (!envPw) return false;
  // constant-time compare for env var path too
  const a = Buffer.from(provided);
  const b = Buffer.from(envPw);
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(a, b); } catch { return false; }
}

/* Convenience for handlers: verify Bearer from event. */
export async function verifyRequest(event) {
  return verifyPassword(extractBearer(event));
}
