/** 会话失效时通知外层回到登录页 */
export const AUTH_EVENT = 'edr:unauthorized'

function onUnauthorized(resp) {
  if (resp.status === 401) {
    window.dispatchEvent(new CustomEvent(AUTH_EVENT))
    throw new Error('登录已过期，请重新登录')
  }
}

async function apiJson(url, opts = {}) {
  const init = {
    credentials: 'include',
    ...opts,
    headers: { ...(opts.headers || {}) },
  }
  if (opts.json != null) {
    init.headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(opts.json)
  }
  const resp = await fetch(url, init)
  if (!opts.noAuthEvent) onUnauthorized(resp)
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`
    try {
      const j = await resp.json()
      msg = j.detail || j.error || msg
    } catch { /* ignore */ }
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
  if (resp.status === 204) return null
  return resp.json()
}

// ---------- EDR 登录 / 账号 / 配置 ----------

export function edrSession() {
  return apiJson('/api/edr/auth/session', { noAuthEvent: true })
}

export function edrLogin(username, password) {
  return apiJson('/api/edr/auth/login', { method: 'POST', json: { username, password }, noAuthEvent: true })
}

export function edrLogout() {
  return apiJson('/api/edr/auth/logout', { method: 'POST', json: {}, noAuthEvent: true })
}

export function edrChangePassword(currentPassword, newPassword) {
  return apiJson('/api/edr/auth/change-password', {
    method: 'POST',
    json: { current_password: currentPassword, new_password: newPassword },
  })
}

export function edrListUsers() {
  return apiJson('/api/edr/users')
}

export function edrCreateUser(payload) {
  return apiJson('/api/edr/users', { method: 'POST', json: payload })
}

export function edrUpdateUser(id, payload) {
  return apiJson(`/api/edr/users/${encodeURIComponent(id)}`, { method: 'PATCH', json: payload })
}

export function edrResetPassword(id, password) {
  return apiJson(`/api/edr/users/${encodeURIComponent(id)}/reset-password`, { method: 'POST', json: { password } })
}

export function edrDeleteUser(id) {
  return apiJson(`/api/edr/users/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export function edrGetSettings() {
  return apiJson('/api/edr/settings')
}

export function edrSaveSettings(payload) {
  return apiJson('/api/edr/settings', { method: 'PUT', json: payload })
}

export function rotateEnrollKey() {
  return apiJson('/api/agent/enroll-key/rotate', { method: 'POST', json: {} })
}

export function getAgentCredentials() {
  return apiJson('/api/agent/credentials')
}

export function setSharedKeyPolicy(allow) {
  return apiJson('/api/agent/credentials/policy', { method: 'POST', json: { allow_shared_key: !!allow } })
}

export function revokeAgent(agentId, revoked = true) {
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}/revoke`, { method: 'POST', json: { revoked: !!revoked } })
}

export function getPolicyHistory(scope = 'global') {
  return apiJson(`/api/agent/policy/history?scope=${encodeURIComponent(scope)}`)
}

export function getPolicyRollout(scope = 'global') {
  return apiJson(`/api/agent/policy/rollout?scope=${encodeURIComponent(scope)}`)
}

export function rollbackPolicy(rev, scope = 'global') {
  return apiJson('/api/agent/policy/rollback', { method: 'POST', json: { rev, scope } })
}

export function getProcessEntity(agentId, entityId) {
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}/process/${encodeURIComponent(entityId)}`)
}

export function listProcessEntities(agentId, { q = '', alive = '' } = {}) {
  const p = new URLSearchParams({ q, alive })
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}/processes?${p}`)
}

export function huntDns({ q = '', agentId = '', nxOnly = false, matchIoc = true, limit = 300 } = {}) {
  const p = new URLSearchParams({
    q,
    agent_id: agentId,
    nx_only: nxOnly ? '1' : '0',
    match_ioc: matchIoc ? '1' : '0',
    limit: String(limit),
  })
  return apiJson(`/api/agent/dns?${p}`)
}

export function getAgentRelease() {
  return apiJson('/api/agent/release')
}

/** 内存 YARA 规则包（只读，Agent 自动拉取） */
export function getAgentSyncManifest() {
  return apiJson('/api/edr/agent-sync/manifest')
}

export function bumpAgentSync(part = 'manual') {
  return apiJson('/api/edr/agent-sync/bump', { method: 'POST', json: { part } })
}

export function getAgentIntegrations() {
  return apiJson('/api/edr/agent-integrations')
}

/** 修改端上/云端检测开关；端上项保存后 sync_rev 自动 +1，云端项立即生效 */
export function saveAgentIntegrations(payload) {
  const body = payload && typeof payload === 'object' && ('defaults' in payload || 'server' in payload)
    ? payload
    : { defaults: payload || {} }
  return apiJson('/api/edr/agent-integrations', { method: 'PUT', json: body })
}

export function getMemoryYaraRules() {
  return apiJson('/api/edr/memory-yara')
}

/** 内存 YARA 规则组/单条开关（保存后 bump sync，Agent 下次同步生效） */
export function saveMemoryYaraControls(payload) {
  return apiJson('/api/edr/memory-yara/controls', { method: 'PUT', json: payload || {} })
}

export function buildAgentRelease() {
  return apiJson('/api/agent/release/build', { method: 'POST', json: {} })
}

export function listAgents(onlineWithinSec = 45) {
  const sec = Math.max(12, Math.min(3600, Number(onlineWithinSec) || 45))
  return apiJson(`/api/agent/list?online_within_sec=${sec}`)
}

export function getSnapshot(agentId, module) {
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}/snapshot/${encodeURIComponent(module)}`)
}

export function agentProtocol() {
  return apiJson('/api/agent/protocol')
}

export function listEvents({ status = '', agentId = '', limit = 100, sync = false } = {}) {
  const q = new URLSearchParams()
  if (status) q.set('status', status)
  if (agentId) q.set('agent_id', agentId)
  q.set('limit', String(limit))
  if (sync) q.set('sync', '1')
  return apiJson(`/api/agent/events?${q}`)
}

export function updateEvent(id, status) {
  return apiJson(`/api/agent/events/${id}`, { method: 'PATCH', json: { status } })
}

export function getEvent(id) {
  return apiJson(`/api/agent/events/${id}`)
}

export function getRelatedEvents(id, limit = 20) {
  return apiJson(`/api/agent/events/${encodeURIComponent(id)}/related?limit=${limit}`)
}

export function enrichEventDetail(id) {
  return apiJson('/api/edr/events/enrich-details', { method: 'POST', json: { event_id: id } })
}

export function enrichEventDetails(limit = 200) {
  return apiJson('/api/edr/events/enrich-details', { method: 'POST', json: { limit } })
}

export function getEdrOverview(onlineWithinSec = 45) {
  return apiJson(`/api/edr/overview?online_within_sec=${onlineWithinSec}`)
}

export function deleteEvent(id) {
  return apiJson(`/api/agent/events/${id}`, { method: 'DELETE' })
}

export function deleteEventsBulk({ status = '', agentId = '', severity = '' } = {}) {
  const qs = new URLSearchParams()
  if (status) qs.set('status', status)
  if (agentId) qs.set('agent_id', agentId)
  if (severity) qs.set('severity', severity)
  return apiJson(`/api/agent/events?${qs}`, { method: 'DELETE' })
}

export function agentRuleStats() {
  return apiJson('/api/agent/rules')
}

export function listAgentRules() {
  return apiJson('/api/agent/rules')
}

export function createAgentRule(payload) {
  return apiJson('/api/agent/rules', { method: 'POST', json: payload })
}

export function updateAgentRule(id, payload) {
  return apiJson(`/api/agent/rules/${encodeURIComponent(id)}`, { method: 'PUT', json: payload })
}

export function patchAgentRule(id, payload) {
  return apiJson(`/api/agent/rules/${encodeURIComponent(id)}`, { method: 'PATCH', json: payload })
}

export function deleteAgentRule(id) {
  return apiJson(`/api/agent/rules/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

/** 批量启停 Agent 规则（all_filtered / all_elastic / all_custom / all_sensor / all） */
export function bulkAgentRulesEnabled(payload) {
  return apiJson('/api/agent/rules/bulk-enabled', { method: 'POST', json: payload })
}

/** 批量启停 Elastic EVM（config/elastic_evm_import.json） */
export function bulkElasticEvmEnabled(payload) {
  return apiJson('/api/edr/elastic-detection/evm/bulk-enabled', { method: 'POST', json: payload })
}

/** Elastic 官方 TOML 规则详情（query / 说明 / 转换状态） */
export function getElasticDetectionRuleDetail(ruleId) {
  const base = String(ruleId || '').replace(/\.(evm|fim)$/i, '')
  return apiJson(`/api/edr/elastic-detection/rule/${encodeURIComponent(base)}`)
}

export function deleteAgent(agentId) {
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}`, { method: 'DELETE' })
}

export function createAgentCommand(agentId, action, params = {}) {
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}/commands`, {
    method: 'POST',
    json: { action, params },
  })
}

export function listAgentCommands(agentId) {
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}/commands`)
}

export function listAllAgentCommands(agentId = '', limit = 80) {
  const qs = new URLSearchParams()
  if (agentId) qs.set('agent_id', agentId)
  qs.set('limit', String(limit))
  return apiJson(`/api/agent/commands?${qs}`)
}

export function getFleetDrift(onlineWithinSec = 45) {
  return apiJson(`/api/agent/fleet/drift?online_within_sec=${onlineWithinSec}`)
}

export function listAgentDiagnostics(agentId = '', limit = 50) {
  const qs = new URLSearchParams()
  if (agentId) qs.set('agent_id', agentId)
  qs.set('limit', String(limit))
  return apiJson(`/api/agent/diagnostics?${qs}`)
}

export async function downloadAgentDiagnostics(agentId, commandId) {
  const url = `/api/agent/${encodeURIComponent(agentId)}/diagnostics/${encodeURIComponent(commandId)}/download`
  const resp = await fetch(url, { credentials: 'include' })
  onUnauthorized(resp)
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`
    try {
      const j = await resp.json()
      msg = j.detail || j.error || msg
    } catch { /* ignore */ }
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
  const blob = await resp.blob()
  const cd = resp.headers.get('Content-Disposition') || ''
  let filename = 'forensic-agent-diagnostics.zip'
  const m = cd.match(/filename="?([^";]+)"?/)
  if (m) filename = m[1]
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

export function listTimeline({ agentId = '', etype = '', q = '', kind = '', limit = 100 } = {}) {
  const qs = new URLSearchParams()
  if (agentId) qs.set('agent_id', agentId)
  if (etype) qs.set('etype', etype)
  if (q) qs.set('q', q)
  if (kind) qs.set('kind', kind)
  qs.set('limit', String(limit))
  return apiJson(`/api/agent/timeline?${qs}`)
}

export function huntAgents(q, limit = 100) {
  return apiJson(`/api/agent/hunt?q=${encodeURIComponent(q)}&limit=${limit}`)
}

export function investigateLogs(params = {}) {
  const qs = new URLSearchParams()
  const keys = ['q', 'agent_id', 'hostname', 'etype', 'nature', 'path', 'hash_q', 'range', 'limit', 'offset', 'hide_proc_noise']
  for (const k of keys) {
    const v = params[k]
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v))
  }
  if (!qs.has('limit')) qs.set('limit', '200')
  if (!qs.has('range')) qs.set('range', 'today')
  if (!qs.has('hide_proc_noise')) qs.set('hide_proc_noise', '1')
  return apiJson(`/api/agent/investigate?${qs}`)
}

export function investigateLogDetail(id) {
  return apiJson(`/api/agent/investigate/${encodeURIComponent(id)}`)
}

export function getAgentPolicy(scope = 'global') {
  return apiJson(`/api/agent/policy?scope=${encodeURIComponent(scope)}`)
}

export function setAgentPolicy(policy, scope = 'global') {
  return apiJson('/api/agent/policy', { method: 'PUT', json: { scope, policy } })
}

export function listWhitelist() {
  return apiJson('/api/agent/whitelist')
}

export function addWhitelist(kind, value, note = '', extra = {}) {
  return apiJson('/api/agent/whitelist', { method: 'POST', json: { kind, value, note, ...extra } })
}

export function deleteWhitelist(id) {
  return apiJson(`/api/agent/whitelist/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export function setWhitelistEnabled(id, enabled) {
  return apiJson(`/api/agent/whitelist/${encodeURIComponent(id)}`, { method: 'PATCH', json: { enabled } })
}

export function eventAllowCandidates(id) {
  return apiJson(`/api/agent/events/${id}/allow-candidates`)
}

export function listAgentGroups() {
  return apiJson('/api/agent/groups')
}

export function upsertAgentGroup(payload) {
  return apiJson('/api/agent/groups', { method: 'PUT', json: payload })
}

export function listAgentAudit(limit = 100) {
  return apiJson(`/api/agent/audit?limit=${limit}`)
}

export function listIoc() {
  return apiJson('/api/agent/ioc')
}

export function addIoc(ioc_type, value, severity = 'high', note = '') {
  return apiJson('/api/agent/ioc', { method: 'POST', json: { ioc_type, value, severity, note } })
}

export function importIoc(text, ioc_type = 'hash', severity = 'high') {
  return apiJson('/api/agent/ioc/import', { method: 'POST', json: { text, ioc_type, severity } })
}

export function deleteIoc(id) {
  return apiJson(`/api/agent/ioc/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export function getAgentTags(agentId = '') {
  const q = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ''
  return apiJson(`/api/agent/tags${q}`)
}

export function setAgentTags(agentId, tags) {
  return apiJson(`/api/agent/${encodeURIComponent(agentId)}/tags`, { method: 'PUT', json: { tags } })
}

export function listSeqRules() {
  return apiJson('/api/agent/seq-rules')
}

export function upsertSeqRule(payload) {
  return apiJson('/api/agent/seq-rules', { method: 'PUT', json: payload })
}

export function deleteSeqRule(id) {
  return apiJson(`/api/agent/seq-rules/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export function iocLibStatus() {
  return apiJson('/api/agent/ioc/lib-status')
}

export function attckBoard({ agentId = '', days = 0 } = {}) {
  const qs = new URLSearchParams()
  if (agentId) qs.set('agent_id', agentId)
  if (days) qs.set('days', String(days))
  return apiJson(`/api/agent/attck-board?${qs}`)
}

export function getNotifyConfig() {
  return apiJson('/api/agent/notify')
}

export function setNotifyConfig(cfg) {
  return apiJson('/api/agent/notify', { method: 'PUT', json: cfg })
}

export function testNotify() {
  return apiJson('/api/agent/notify/test', { method: 'POST' })
}

export function storeStats() {
  return apiJson('/api/agent/store/stats')
}

export function storePurge() {
  return apiJson('/api/agent/store/purge', { method: 'POST' })
}

export function storeSearch(q, agentId = '', limit = 200) {
  const qs = new URLSearchParams({ q, limit: String(limit) })
  if (agentId) qs.set('agent_id', agentId)
  return apiJson(`/api/agent/store/search?${qs}`)
}

export function attackStory({ agentId = '', eventId = 0, limit = 80 } = {}) {
  const qs = new URLSearchParams()
  if (agentId) qs.set('agent_id', agentId)
  if (eventId) qs.set('event_id', String(eventId))
  qs.set('limit', String(limit))
  return apiJson(`/api/agent/attack-story?${qs}`)
}

export function threatProcessTree({ agentId = '', eventId = 0, maxNodes = 56 } = {}) {
  const qs = new URLSearchParams()
  if (agentId) qs.set('agent_id', agentId)
  if (eventId) qs.set('event_id', String(eventId))
  qs.set('max_nodes', String(maxNodes))
  return apiJson(`/api/agent/threat-process-tree?${qs}`)
}

export function listUpgradePackages() {
  return apiJson('/api/agent/upgrade-packages')
}

export async function uploadUpgradePackage(file, version, note = '') {
  const fd = new FormData()
  fd.append('file', file)
  fd.append('version', version || '')
  fd.append('note', note || '')
  const resp = await fetch('/api/agent/upgrade-packages', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  onUnauthorized(resp)
  if (!resp.ok) {
    let msg = `上传失败 HTTP ${resp.status}`
    try {
      const j = await resp.json()
      msg = j.detail || j.error || msg
    } catch { /* ignore */ }
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
  return resp.json()
}

export function deleteUpgradePackage(id) {
  return apiJson(`/api/agent/upgrade-packages/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export function pushUpgradePackage(id, agentIds) {
  return apiJson(`/api/agent/upgrade-packages/${encodeURIComponent(id)}/push`, {
    method: 'POST',
    json: { agent_ids: agentIds },
  })
}

/** SSE：有变更时回调；返回关闭函数 */
export function subscribeAgentStream(onEvent) {
  let es = null
  let closed = false
  let lastRev = 0
  let retryTimer = null

  const connect = () => {
    if (closed) return
    try {
      es = new EventSource(`/api/agent/stream?last_rev=${lastRev}`, { withCredentials: true })
    } catch {
      retryTimer = setTimeout(connect, 3000)
      return
    }
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data || '{}')
        if (data.kind === 'server_shutdown') {
          closed = true
          try { es.close() } catch { /* ignore */ }
          es = null
          return
        }
        if (data.rev != null) lastRev = data.rev
        onEvent?.(data)
      } catch { /* ignore */ }
    }
    es.onerror = () => {
      try { es.close() } catch { /* ignore */ }
      es = null
      if (!closed) retryTimer = setTimeout(connect, 2500)
    }
  }
  connect()
  return () => {
    closed = true
    if (retryTimer) clearTimeout(retryTimer)
    try { es?.close() } catch { /* ignore */ }
  }
}

export async function downloadInstallPackage(onProgress) {
  const resp = await fetch('/api/agent/install-package', { credentials: 'include' })
  onUnauthorized(resp)
  if (!resp.ok) {
    let msg = `下载失败 HTTP ${resp.status}`
    try {
      const j = await resp.json()
      msg = j.detail || msg
    } catch { /* ignore */ }
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
  let name = 'ForensicAgent_install.zip'
  const cd = resp.headers.get('content-disposition') || ''
  const m = cd.match(/filename="?([^";]+)"?/i)
  if (m?.[1]) name = m[1]

  const total = Number(resp.headers.get('content-length') || 0)
  let blob
  if (resp.body && typeof onProgress === 'function') {
    const reader = resp.body.getReader()
    const chunks = []
    let received = 0
    onProgress({ phase: 'download', received: 0, total })
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
      received += value.byteLength
      onProgress({ phase: 'download', received, total })
    }
    blob = new Blob(chunks, { type: 'application/zip' })
  } else {
    blob = await resp.blob()
  }
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 2000)
}
