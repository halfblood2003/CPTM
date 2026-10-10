// Single place where the API token and all HTTP calls live.
//
// Important: on 401 we clear the stored token and notify the app so it can show
// the login screen again. Silently swallowing auth failures is what makes a
// misconfigured token look like an empty, broken UI.

const TOKEN_KEY = 'cptm-token'
let onUnauthorized = null

export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else localStorage.removeItem(TOKEN_KEY)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

async function req(method, path, body) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-CPTM-Token': getToken(),
    },
    body: body ? JSON.stringify(body) : undefined,
  })

  if (res.status === 401) {
    clearToken()
    if (onUnauthorized) onUnauthorized()
    throw new Error('unauthorized')
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      detail = (await res.json()).detail || detail
    } catch {}
    throw new Error(detail)
  }
  return res.json()
}

export const api = {
  health: () => req('GET', '/health'),
  // Token-gated: this is the call that decides whether the login screen shows.
  authCheck: () => req('GET', '/auth/check'),
  listTools: () => req('GET', '/tools'),
  getTool: (name) => req('GET', `/tools/${name}`),
  createTool: (spec) => req('POST', '/tools', spec),
  updateTool: (name, spec) => req('PUT', `/tools/${name}`, spec),
  deleteTool: (name) => req('DELETE', `/tools/${name}`),
  listJobs: (limit = 50) => req('GET', `/jobs?limit=${limit}`),
  getJob: (id) => req('GET', `/jobs/${id}`),
  getOutput: (id) => req('GET', `/jobs/${id}/output`),
  getFindings: (id) => req('GET', `/jobs/${id}/findings`),
  launch: (tool, params) => req('POST', '/jobs/launch', { tool, params }),
  cancel: (id) => req('POST', `/jobs/${id}/cancel`),
}

export function artifactUrl(jobId, path) {
  return `/api/jobs/${jobId}/artifacts/${encodeURIComponent(path)}`
}

// Artifacts are served through a token-gated endpoint, so a plain <a href>
// cannot authenticate. Fetch with the header, then hand the browser a blob URL.
export async function downloadArtifact(jobId, path, filename) {
  const res = await fetch(artifactUrl(jobId, path), {
    headers: { 'X-CPTM-Token': getToken() },
  })
  if (res.status === 401) {
    clearToken()
    if (onUnauthorized) onUnauthorized()
    throw new Error('unauthorized')
  }
  if (!res.ok) throw new Error(`download failed (${res.status})`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename || path.split('/').pop()
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10000)
}
