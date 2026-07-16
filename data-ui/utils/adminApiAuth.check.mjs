#!/usr/bin/env node
/**
 * B02: pure unit checks for Admin API 401/403 classification.
 * Run: node --experimental-strip-types utils/adminApiAuth.check.mjs
 * (or after build transpile — here we inline the same logic for zero deps)
 */
function asAdminApiAuthError(err, path) {
  const status = Number(err?.statusCode || err?.status || err?.response?.status || 0) || 0
  if (status !== 401 && status !== 403) return null
  const data = err?.data && typeof err.data === 'object' ? err.data : {}
  const message =
    (typeof data.message === 'string' && data.message)
    || err?.message
    || (status === 401 ? 'Authentication required' : 'Permission denied')
  return {
    kind: status === 401 ? 'unauthorized' : 'forbidden',
    status,
    code: typeof data.error === 'string' ? data.error : undefined,
    message: String(message),
    path,
  }
}

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg)
    process.exit(1)
  }
}

const u = asAdminApiAuthError({ statusCode: 401, data: { error: 'unauthorized', message: 'missing token' } }, '/admin/listeners')
assert(u && u.kind === 'unauthorized' && u.code === 'unauthorized', '401 maps to unauthorized')
assert(u.message.includes('missing'), '401 message preserved')

const f = asAdminApiAuthError({ status: 403, data: { error: 'forbidden', message: 'missing permission policy:write' } }, '/admin/tickets')
assert(f && f.kind === 'forbidden', '403 maps to forbidden')
assert(f.path === '/admin/tickets', 'path attached')

const n = asAdminApiAuthError({ statusCode: 500, message: 'boom' })
assert(n === null, '500 is not auth error')

console.log('adminApiAuth.check: OK')
