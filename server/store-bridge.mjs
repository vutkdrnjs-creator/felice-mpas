const MUTATIONS = new Set(['saveProperty', 'deleteProperty', 'saveGroup', 'deleteGroup']);
const LIMIT = 48_000;
const ID = /^[a-zA-Z0-9_-]{1,100}$/;
const REQUEST_ID = /^[a-zA-Z0-9_-]{16,100}$/;
const HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };

function reply(body, status = 200) { return new Response(JSON.stringify(body), { status, headers: HEADERS }); }
function fail(code, message, status = 400) { return reply({ ok: false, error: { code, message } }, status); }
function field(value, max, required = false) {
  if (typeof value !== 'string' || value.length > max || (required && !value.trim())) throw new Error('INVALID_INPUT');
  return value;
}
function recordId(value, required = false) {
  if (!required && (value === undefined || value === '')) return '';
  if (typeof value !== 'string' || !ID.test(value)) throw new Error('INVALID_INPUT');
  return value;
}
function revision(value, existing) {
  if (!existing) return 0;
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('INVALID_INPUT');
  return value;
}
export function cleanPayload(action, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('INVALID_INPUT');
  const id = recordId(value.id, action.startsWith('delete'));
  const rev = revision(value.revision, !!id);
  if (action.startsWith('delete')) return { id, revision: rev };
  if (action === 'saveGroup') {
    const color = field(value.color, 7, true);
    if (!/^#[0-9a-fA-F]{6}$/.test(color)) throw new Error('INVALID_INPUT');
    return { id, revision: rev, name: field(value.name, 50, true).trim(), color };
  }
  if (action !== 'saveProperty') throw new Error('INVALID_ACTION');
  if (!Number.isFinite(value.lat) || !Number.isFinite(value.lng) || value.lat < -90 || value.lat > 90 || value.lng < -180 || value.lng > 180) throw new Error('INVALID_INPUT');
  return { id, revision: rev, title: field(value.title, 120, true).trim(), address: field(value.address ?? '', 300).trim(), lat: value.lat, lng: value.lng, groupId: recordId(value.groupId), memo: field(value.memo ?? '', 10000) };
}

export async function serveStore(request, { config, user, fetchImpl = fetch, uuid = () => crypto.randomUUID(), allowedOrigins = [] }) {
  if (!user?.userId) return fail('AUTH_REQUIRED', '로그인이 필요합니다.', 401);
  if (!['GET', 'POST'].includes(request.method)) return fail('METHOD_NOT_ALLOWED', '허용되지 않은 요청입니다.', 405);
  if (request.method === 'POST' && !new Set([new URL(request.url).origin, ...allowedOrigins]).has(request.headers.get('origin'))) return fail('FORBIDDEN', '요청을 확인해 주세요.', 403);
  if (!config.STORE_APPS_SCRIPT_URL || !config.STORE_BRIDGE_SECRET) return fail('STORE_NOT_CONFIGURED', '공동 저장 연결이 필요합니다.', 503);
  if (!/^https:\/\/script\.google\.com\/macros\/s\/[a-zA-Z0-9_-]+\/exec$/.test(config.STORE_APPS_SCRIPT_URL) || config.STORE_BRIDGE_SECRET.length < 32) return fail('STORE_NOT_CONFIGURED', '공동 저장 연결이 필요합니다.', 503);
  let action = 'snapshot', payload = {}, requestId = uuid();
  if (request.method === 'POST') {
    if (!request.headers.get('content-type')?.startsWith('application/json')) return fail('INVALID_INPUT', '입력값을 확인해 주세요.');
    if (Number(request.headers.get('content-length') || 0) > LIMIT) return fail('INVALID_INPUT', '입력 내용이 너무 깁니다.', 413);
    try {
      const text = await request.text();
      if (text.length > LIMIT) return fail('INVALID_INPUT', '입력 내용이 너무 깁니다.', 413);
      const input = JSON.parse(text);
      if (!MUTATIONS.has(input.action) || !REQUEST_ID.test(input.requestId ?? '')) return fail('INVALID_INPUT', '입력값을 확인해 주세요.');
      action = input.action; payload = cleanPayload(action, input.payload); requestId = input.requestId;
    } catch { return fail('INVALID_INPUT', '입력값을 확인해 주세요.'); }
  }
  try {
    const response = await fetchImpl(config.STORE_APPS_SCRIPT_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, redirect: 'follow',
      body: JSON.stringify({ secret: config.STORE_BRIDGE_SECRET, action, payload, requestId, actor: String(user.displayName || user.email || user.userId).slice(0, 120) }),
      signal: AbortSignal.timeout(25_000),
    });
    if (!response.ok) return fail('STORE_UNAVAILABLE', '공동 저장소에 연결하지 못했습니다.', 503);
    const text = await response.text();
    if (text.length > 12_000_000) return fail('STORE_UNAVAILABLE', '공동 저장소 응답을 확인하지 못했습니다.', 503);
    const result = JSON.parse(text);
    if (result.ok !== true) {
      const messages = {
        CONFLICT: '다른 사용자가 수정했습니다. 새로고침 후 다시 확인해 주세요.',
        NOT_FOUND: '삭제되었거나 찾을 수 없는 항목입니다.',
        GROUP_IN_USE: '소속 매물을 다른 그룹으로 이동한 뒤 삭제해 주세요.',
        INVALID_INPUT: '입력값을 확인해 주세요.',
        GROUP_NOT_FOUND: '그룹이 변경되었습니다. 새로고침 후 다시 확인해 주세요.',
        DUPLICATE_GROUP: '같은 이름의 그룹이 있습니다.',
        REQUEST_ID_REUSED: '요청을 다시 확인해 주세요.',
        STORE_LIMIT: '공동 저장소 용량을 확인해 주세요.',
        BUSY: '다른 저장 작업이 진행 중입니다. 잠시 후 다시 시도해 주세요.',
      };
      const code = result.error?.code;
      if (Object.hasOwn(messages, code)) return fail(code, messages[code], ['CONFLICT','GROUP_IN_USE','REQUEST_ID_REUSED'].includes(code) ? 409 : 400);
      return fail('STORE_UNAVAILABLE', '공동 저장소에 연결하지 못했습니다.', 503);
    }
    if (!Object.hasOwn(result, 'data') || (action === 'snapshot' && (!Array.isArray(result.data?.properties) || !Array.isArray(result.data?.groups)))) return fail('STORE_UNAVAILABLE', '공동 저장소 응답을 확인하지 못했습니다.', 503);
    // Never return the transport envelope, credentials, or provider diagnostics.
    return reply({ ok: true, data: result.data });
  } catch { return fail('STORE_UNAVAILABLE', '공동 저장소에 연결하지 못했습니다.', 503); }
}
