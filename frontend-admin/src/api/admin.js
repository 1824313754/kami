import apiClient from './client'

export async function fetchSession() {
  const { data } = await apiClient.get('/session')
  return data
}

export async function login(payload) {
  const { data } = await apiClient.post('/login', payload)
  return data
}

export async function logout() {
  const { data } = await apiClient.post('/logout')
  return data
}

export async function changeOwnPassword(payload) {
  const { data } = await apiClient.post('/password', payload)
  return data
}

export async function fetchDashboard(params) {
  const { data } = await apiClient.get('/dashboard', { params })
  return data
}

export async function fetchFiles(params) {
  const { data } = await apiClient.get('/files', { params })
  return data
}

export async function fetchFileDetail(fileId, params) {
  const { data } = await apiClient.get(`/files/${fileId}`, { params })
  return data
}

export async function uploadFiles(formData) {
  const { data } = await apiClient.post('/files/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function deleteFiles(payload) {
  const { data } = await apiClient.post('/files/delete', payload)
  return data
}

export async function downloadFiles(payload) {
  const { data } = await apiClient.post('/files/download', payload)
  return data
}

export async function recoverFiles(payload) {
  const { data } = await apiClient.post('/files/recover', payload)
  return data
}

export async function liveCheckFiles(payload) {
  const { data } = await apiClient.post('/files/live-check', payload)
  return data
}

export async function fetchCdkeys(params) {
  const { data } = await apiClient.get('/cdkeys', { params })
  return data
}

export function exportCdkeysUrl(params = {}) {
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === null || value === undefined || value === '') return
    search.set(key, String(value))
  })
  const query = search.toString()
  return `/admin/cdkeys/export${query ? `?${query}` : ''}`
}

export async function fetchCdkeyDetail(cdkeyId, params) {
  const { data } = await apiClient.get(`/cdkeys/${cdkeyId}`, { params })
  return data
}

export async function createCdkeys(payload) {
  const { data } = await apiClient.post('/cdkeys/create', payload)
  return data
}

export async function importCdkeys(payload) {
  const { data } = await apiClient.post('/cdkeys/import', payload)
  return data
}

export async function deleteCdkeys(payload) {
  const { data } = await apiClient.post('/cdkeys/delete', payload)
  return data
}

export async function deleteCdkeysByCodes(payload) {
  const { data } = await apiClient.post('/cdkeys/delete-by-codes', payload)
  return data
}

export async function updateOverIssue(payload) {
  const { data } = await apiClient.post('/cdkeys/over-issue', payload)
  return data
}

export async function fetchAudit(params) {
  const { data } = await apiClient.get('/audit', { params })
  return data
}

export async function fetchUsers() {
  const { data } = await apiClient.get('/users')
  return data
}

export async function createUser(payload) {
  const { data } = await apiClient.post('/users', payload)
  return data
}

export async function toggleUser(userId) {
  const { data } = await apiClient.post(`/users/${userId}/toggle`)
  return data
}

export async function updateUsername(userId, payload) {
  const { data } = await apiClient.post(`/users/${userId}/username`, payload)
  return data
}

export async function updateUserPassword(userId, payload) {
  const { data } = await apiClient.post(`/users/${userId}/password`, payload)
  return data
}

export async function deleteUser(userId) {
  const { data } = await apiClient.post(`/users/${userId}/delete`)
  return data
}

export async function fetchSettings() {
  const { data } = await apiClient.get('/settings')
  return data
}

export async function saveSettings(payload) {
  const { data } = await apiClient.post('/settings', payload)
  return data
}

export async function fetchJob(jobId, params) {
  const { data } = await apiClient.get(`/jobs/${jobId}`, { params })
  return data
}

export async function fetchJobs(params) {
  const { data } = await apiClient.get('/jobs', { params })
  return data
}

export async function terminateJob(jobId, params) {
  const { data } = await apiClient.post(`/jobs/${jobId}/terminate`, null, { params })
  return data
}

export async function fetchQuerySession() {
  const { data } = await apiClient.get('/../query/session')
  return data
}

export async function fetchQueryStock() {
  const { data } = await apiClient.get('/../query/stock')
  return data
}

export async function fetchQueryTotpAccounts(payload) {
  const { data } = await apiClient.post('/../query/2fa/accounts', payload)
  return data
}

export async function fetchQueryTotpCode(payload) {
  const { data } = await apiClient.post('/../query/2fa/code', payload)
  return data
}

export async function submitQueryAccess(payload) {
  const { data } = await apiClient.post('/../query/access', payload)
  return data
}

export async function fetchQueryJob(jobId, params) {
  const { data } = await apiClient.get(`/../query/jobs/${jobId}`, { params })
  return data
}

export async function fetchQueryResult(params) {
  const { data } = await apiClient.get('/../query/result', { params })
  return data
}

export async function startQueryReauth(payload) {
  const { data } = await apiClient.post('/../query/reauth', payload)
  return data
}

export async function terminateQueryReauth(jobId, params) {
  const { data } = await apiClient.post(`/../query/reauth/${jobId}/terminate`, null, { params })
  return data
}

export async function downloadQueryReauth(jobId, format, params, onProgress) {
  return apiClient.get(`/../query/reauth/${jobId}/download`, {
    params: { ...params, format },
    responseType: 'blob',
    onDownloadProgress: (event) => onProgress?.(event),
  })
}

export async function downloadQueryFiles(params, onProgress) {
  return apiClient.get('/../../query/files/download', {
    params,
    responseType: 'blob',
    onDownloadProgress: (event) => onProgress?.(event),
  })
}

export async function downloadQuerySub(params, onProgress) {
  return apiClient.get('/../../query/files/download-sub', {
    params,
    responseType: 'blob',
    onDownloadProgress: (event) => onProgress?.(event),
  })
}

export async function importTwoFactor(payload) {
  const { data } = await apiClient.post('/files/import-2fa', payload)
  return data
}

export async function downloadQueryTwoFactor(params) {
  return apiClient.get('/../../query/files/download-2fa', { params, responseType: 'blob' })
}
