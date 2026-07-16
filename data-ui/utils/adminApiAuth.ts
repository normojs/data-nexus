/** Pure Admin API auth-error helpers (no Nuxt imports — unit-testable). */

export type AdminApiAuthError = {
  kind: 'unauthorized' | 'forbidden'
  status: number
  code?: string
  message: string
  path?: string
}

function extractStatus(err: any): number {
  return Number(err?.statusCode || err?.status || err?.response?.status || 0) || 0
}

function extractBody(err: any): { error?: string, message?: string } {
  const data = err?.data
  if (data && typeof data === 'object') {
    return {
      error: typeof data.error === 'string' ? data.error : undefined,
      message: typeof data.message === 'string' ? data.message : undefined,
    }
  }
  return {}
}

/**
 * Map ofetch/HTTP errors into a structured auth failure when status is 401/403.
 * Returns null for non-auth failures so callers can keep their own messaging.
 */
export function asAdminApiAuthError(err: unknown, path?: string): AdminApiAuthError | null {
  const e = err as any
  const status = extractStatus(e)
  if (status !== 401 && status !== 403) return null
  const body = extractBody(e)
  const message =
    body.message
    || e?.message
    || (status === 401 ? 'Authentication required' : 'Permission denied')
  return {
    kind: status === 401 ? 'unauthorized' : 'forbidden',
    status,
    code: body.error,
    message: String(message),
    path,
  }
}
