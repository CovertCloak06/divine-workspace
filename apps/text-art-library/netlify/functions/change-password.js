// Frostline — POST /change-password
// Body: { currentPassword, newPassword }
// Auth: must provide currentPassword that matches the active password
//       (blob hash if present, env var otherwise).
// On success: hashes newPassword with PBKDF2-SHA256 (random salt) and writes
// to blob `auth/password`. From the next request onward the env var is
// ignored and only the new password is accepted.

import { connectLambda, getStore } from '@netlify/blobs';
import { verifyPassword, hashPassword, newSalt } from './_auth.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
};

const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json', ...CORS },
  body: JSON.stringify(obj),
});

const MIN_LEN = 4;
const MAX_LEN = 128;

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Bad JSON' }); }

  const { currentPassword, newPassword } = body;
  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    return json(400, { error: 'currentPassword and newPassword are required strings' });
  }
  if (newPassword.length < MIN_LEN || newPassword.length > MAX_LEN) {
    return json(400, { error: `newPassword must be ${MIN_LEN}–${MAX_LEN} characters` });
  }
  if (newPassword === currentPassword) {
    return json(400, { error: 'New password must differ from current' });
  }

  const ok = await verifyPassword(currentPassword);
  if (!ok) return json(401, { error: 'Current password is incorrect' });

  try {
    const store = getStore('frostline');
    const stored = hashPassword(newPassword, newSalt());
    await store.set('auth/password', stored);
    return json(200, { ok: true });
  } catch (err) {
    return json(500, { error: 'Blob write failed', detail: String(err).slice(0, 200) });
  }
};
