import { randomUUID } from 'node:crypto';
import { serveStore } from '../server/store-bridge.mjs';
import { createGoogleTokenVerifier, GoogleAuthenticationError } from '../server/google-identity.mjs';

const DEFAULT_ORIGIN = 'https://felice-mpas.vercel.app';
const verifyGoogleToken = createGoogleTokenVerifier();
const HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };
function reply(body, status = 200) { return new Response(JSON.stringify(body), { status, headers: HEADERS }); }
function fail(code, message, status) { return reply({ ok: false, error: { code, message } }, status); }
function clientId(config) {
  const value = config.GOOGLE_CLIENT_ID;
  return typeof value === 'string' && value.length <= 300 && /^[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(value) ? value : '';
}
function appOrigin(config) {
  const value = config.APP_ORIGIN || DEFAULT_ORIGIN;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value ? value : '';
  } catch { return ''; }
}

function readCursor(url) {
  const offset = url.searchParams.get('offset') ?? '0';
  const version = url.searchParams.get('version');
  if (!/^(0|[1-9][0-9]{0,9})$/.test(offset) || (version != null && (version.length > 100 || /[\u0000-\u001f\u007f]/.test(version)))) return null;
  return { offset: Number(offset), version };
}

function snapshotPage(data, cursor, maxPageBytes) {
  if (typeof data.updatedAt !== 'string') return fail('STORE_UNAVAILABLE', '공동 저장소 응답을 확인하지 못했습니다.', 503);
  if (cursor.offset > data.properties.length) return fail('INVALID_INPUT', '조회 위치를 확인해 주세요.', 400);
  if (cursor.offset > 0 && cursor.version !== data.updatedAt) return fail('SNAPSHOT_CHANGED', '자료가 변경되었습니다. 다시 불러옵니다.', 409);
  const pageBody = (properties, nextOffset) => ({ ok: true, data: { properties, groups: data.groups, updatedAt: data.updatedAt }, page: { nextOffset, version: data.updatedAt } });
  const baseBytes = Buffer.byteLength(JSON.stringify(pageBody([], null)), 'utf8');
  if (baseBytes > maxPageBytes) return fail('STORE_UNAVAILABLE', '공동 저장소 응답을 확인하지 못했습니다.', 503);
  let end = cursor.offset;
  let itemsBytes = 0;
  while (end < data.properties.length) {
    const candidateBytes = itemsBytes + Buffer.byteLength(JSON.stringify(data.properties[end]), 'utf8') + (end > cursor.offset ? 1 : 0);
    const nextOffset = end + 1 < data.properties.length ? end + 1 : null;
    const totalBytes = baseBytes + candidateBytes + (nextOffset === null ? 0 : String(nextOffset).length - 4);
    if (totalBytes > maxPageBytes) break;
    itemsBytes = candidateBytes;
    end++;
  }
  if (end === cursor.offset && end < data.properties.length) return fail('STORE_UNAVAILABLE', '공동 저장소 응답을 확인하지 못했습니다.', 503);
  return reply(pageBody(data.properties.slice(cursor.offset, end), end < data.properties.length ? end : null));
}

export function createStoreHandler({ getConfig = () => process.env, verifyIdToken = verifyGoogleToken, fetchImpl = fetch, maxPageBytes = 3_500_000 } = {}) {
  return async function handleStore(request) {
    try {
      if (!['GET', 'POST'].includes(request.method)) return fail('METHOD_NOT_ALLOWED', '허용되지 않은 요청입니다.', 405);
      const config = getConfig();
      const oauthClientId = clientId(config);
      const origin = appOrigin(config);
      const url = new URL(request.url);
      if (request.method === 'GET' && url.searchParams.getAll('action').length > 1) return fail('INVALID_ACTION', '지원하지 않는 요청입니다.', 400);
      if (request.method === 'GET' && url.searchParams.get('action') === 'config') {
        if (!oauthClientId || !origin) return fail('AUTH_NOT_CONFIGURED', '로그인 설정이 필요합니다.', 503);
        return reply({ ok: true, data: { clientId: oauthClientId } });
      }
      const identityRequest = request.method === 'GET' && url.searchParams.get('action') === 'identity';
      if (request.method === 'GET' && url.searchParams.has('action') && !['snapshot', 'identity'].includes(url.searchParams.get('action'))) return fail('INVALID_ACTION', '지원하지 않는 요청입니다.', 400);
      if (request.method === 'GET' && !identityRequest) {
        const cursor = readCursor(url);
        if (!cursor) return fail('INVALID_INPUT', '조회 위치를 확인해 주세요.', 400);
        // The public principal is created only for this fixed read path, never from browser input.
        const response = await serveStore(request, { config, user: { userId: 'public-reader' }, fetchImpl, uuid: randomUUID });
        if (!response.ok) return response;
        const result = await response.json();
        return snapshotPage(result.data, cursor, maxPageBytes);
      }
      if (!oauthClientId || !origin) return fail('AUTH_NOT_CONFIGURED', '로그인 설정이 필요합니다.', 503);
      if (request.method === 'POST' && !new Set([url.origin, origin]).has(request.headers.get('origin'))) return fail('FORBIDDEN', '요청을 확인해 주세요.', 403);
      const authorization = request.headers.get('authorization');
      if (!authorization) return fail('AUTH_REQUIRED', '로그인이 필요합니다.', 401);
      const token = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(authorization);
      if (!token || authorization.length > 16_400) return fail('AUTH_INVALID', '로그인을 다시 진행해 주세요.', 401);
      let user;
      try { user = await verifyIdToken(token[1], oauthClientId); }
      catch (error) {
        if (error instanceof GoogleAuthenticationError && error.code === 'AUTH_UNAVAILABLE') return fail('AUTH_UNAVAILABLE', '로그인 인증에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.', 503);
        return fail('AUTH_INVALID', '로그인을 다시 진행해 주세요.', 401);
      }
      if (identityRequest) return reply({ ok: true, data: { userId: user.userId } });
      return await serveStore(request, { config, user, fetchImpl, uuid: randomUUID, allowedOrigins: [origin] });
    } catch { return fail('SERVER_ERROR', '요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.', 500); }
  };
}

const handler = createStoreHandler();
// Vercel's Node.js runtime supports Web-standard Request/Response method exports.
export const GET = handler;
export const POST = handler;
