import { createPublicKey, verify as verifySignature } from 'node:crypto';

const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const MAX_TOKEN_LENGTH = 16_384;
const MAX_CERT_BYTES = 100_000;
const REFRESH_INTERVAL_MS = 30_000;
const MAX_KEY_TTL_SECONDS = 21_600;

export class GoogleAuthenticationError extends Error {
  constructor(code = 'AUTH_INVALID') {
    super(code === 'AUTH_UNAVAILABLE' ? '로그인 인증에 연결하지 못했습니다.' : '로그인을 다시 진행해 주세요.');
    this.code = code;
  }
}

function invalid() { throw new GoogleAuthenticationError(); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function decodeSegment(segment) {
  if (!segment || !/^[A-Za-z0-9_-]+$/.test(segment)) invalid();
  try { return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')); } catch { invalid(); }
}

function validateClaims(claims, audience, seconds) {
  if (!object(claims) || !['https://accounts.google.com', 'accounts.google.com'].includes(claims.iss)) invalid();
  if (typeof audience !== 'string' || !audience || claims.aud !== audience || (claims.azp != null && claims.azp !== audience)) invalid();
  if (!Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat) || claims.iat <= 0 || claims.exp <= seconds || claims.iat > seconds + 60 || claims.exp <= claims.iat || claims.exp - claims.iat > 86400 || claims.exp > seconds + 86400) invalid();
  if (claims.nbf != null && (!Number.isSafeInteger(claims.nbf) || claims.nbf > seconds + 60)) invalid();
  if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255 || /[\u0000-\u0020\u007f]/.test(claims.sub)) invalid();
  if (claims.email_verified !== true || typeof claims.email !== 'string' || claims.email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(claims.email)) invalid();
}

async function readCertificates(response) {
  if (!response.ok || Number(response.headers.get('content-length') || 0) > MAX_CERT_BYTES) throw new Error('CERT_RESPONSE');
  const reader = response.body?.getReader();
  if (!reader) throw new Error('CERT_RESPONSE');
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_CERT_BYTES) throw new Error('CERT_RESPONSE');
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/** Native Node RSA verification; no tokens are sent to a token inspection endpoint or logged. */
export function createGoogleTokenVerifier({ fetchImpl = fetch, now = Date.now } = {}) {
  let keys = new Map();
  let expiresAt = 0;
  let refreshAllowedAt = 0;
  let pendingRefresh = null;

  async function refresh() {
    if (pendingRefresh) return pendingRefresh;
    if (now() < refreshAllowedAt) throw new GoogleAuthenticationError('AUTH_UNAVAILABLE');
    refreshAllowedAt = now() + REFRESH_INTERVAL_MS;
    pendingRefresh = (async () => {
      try {
        const response = await fetchImpl(JWKS_URL, { headers: { Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(5000) });
        const document = await readCertificates(response);
        if (!object(document) || !Array.isArray(document.keys) || !document.keys.length || document.keys.length > 20) throw new Error('CERT_RESPONSE');
        const next = new Map();
        for (const jwk of document.keys) {
          if (!object(jwk) || jwk.kty !== 'RSA' || (jwk.alg && jwk.alg !== 'RS256') || (jwk.use && jwk.use !== 'sig') || typeof jwk.kid !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(jwk.kid)) continue;
          if (typeof jwk.n !== 'string' || !/^[A-Za-z0-9_-]+$/.test(jwk.n) || typeof jwk.e !== 'string' || !/^[A-Za-z0-9_-]+$/.test(jwk.e)) throw new Error('CERT_RESPONSE');
          const modulusLength = Buffer.from(jwk.n, 'base64url').length;
          if (modulusLength < 256 || modulusLength > 1024 || next.has(jwk.kid)) throw new Error('CERT_RESPONSE');
          next.set(jwk.kid, createPublicKey({ key: jwk, format: 'jwk' }));
        }
        if (!next.size) throw new Error('CERT_RESPONSE');
        const maxAge = /(?:^|,)\s*max-age\s*=\s*"?(\d+)"?/i.exec(response.headers.get('cache-control') || '');
        const age = Math.max(0, Number(response.headers.get('age') || 0) || 0);
        const ttl = Math.max(0, Math.min(Number(maxAge?.[1] || 300), MAX_KEY_TTL_SECONDS) - age);
        keys = next;
        expiresAt = now() + ttl * 1000;
      } catch { throw new GoogleAuthenticationError('AUTH_UNAVAILABLE'); }
    })();
    try { await pendingRefresh; } finally { pendingRefresh = null; }
  }

  return async function verifyGoogleIdToken(token, audience) {
    if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) invalid();
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0].length > 4096 || !/^[A-Za-z0-9_-]+$/.test(parts[2])) invalid();
    const header = decodeSegment(parts[0]);
    const claims = decodeSegment(parts[1]);
    if (!object(header) || header.alg !== 'RS256' || (header.typ != null && header.typ !== 'JWT') || typeof header.kid !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(header.kid)) invalid();
    validateClaims(claims, audience, Math.floor(now() / 1000));
    let refreshed = false;
    if (!keys.size || now() >= expiresAt) { await refresh(); refreshed = true; }
    if (!keys.has(header.kid) && !refreshed && now() >= refreshAllowedAt) await refresh();
    const key = keys.get(header.kid);
    if (!key) invalid();
    let verified = false;
    try { verified = verifySignature('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), key, Buffer.from(parts[2], 'base64url')); } catch { invalid(); }
    if (!verified) invalid();
    // Fetching certificates can take time; check expiry again after signature verification.
    validateClaims(claims, audience, Math.floor(now() / 1000));
    const name = typeof claims.name === 'string' ? claims.name.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 120) : '';
    return { userId: 'google:' + claims.sub, email: claims.email, displayName: name || claims.email.slice(0, 120) };
  };
}
