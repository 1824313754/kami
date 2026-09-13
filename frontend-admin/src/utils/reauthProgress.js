function emailKey(value) {
  return String(value || '').trim().toLowerCase()
}

function latestAccountEvents(events) {
  const byEmail = new Map()
  for (const event of events || []) {
    const text = String(event?.text || '')
    const separator = text.indexOf('｜')
    if (separator <= 0) continue
    const email = text.slice(0, separator).trim()
    if (!email.includes('@')) continue
    byEmail.set(emailKey(email), {
      text: text.slice(separator + 1).trim(),
      time: event?.time || '',
    })
  }
  return byEmail
}

function statusFromResult(result) {
  if (result?.result === '成功') return '授权成功'
  if (result?.result === '失败') return '授权失败'
  return ''
}

function statusPriority(value) {
  return {
    授权中: 0,
    等待授权: 1,
    授权失败: 2,
    授权成功: 3,
    已跳过: 4,
    无需授权: 5,
  }[value] ?? 6
}

export function buildReauthAccountRows(job) {
  const liveRows = Array.isArray(job?.live_check_result_rows) ? job.live_check_result_rows : []
  const resultRows = Array.isArray(job?.result_rows) ? job.result_rows : []
  const resultByEmail = new Map(resultRows.map((item) => [emailKey(item?.email), item]))
  const eventByEmail = latestAccountEvents(job?.events)
  const seen = new Set()
  const rows = []

  for (const item of liveRows) {
    const key = emailKey(item?.email)
    if (!key) continue
    seen.add(key)
    const result = resultByEmail.get(key)
    const event = eventByEmail.get(key)
    const required = item.reauth_required == null
      ? String(item.http_status || '') === '401'
      : Boolean(item.reauth_required)
    const reauthStatus = item.reauth_status || statusFromResult(result) || (required ? '等待授权' : '无需授权')
    const progressLog = item.progress_log
      || (result ? (result.result === '成功' ? '重登授权成功，令牌已回写原账号' : `重登授权失败：${result.reason || '-'}`) : '')
      || event?.text
      || item.message
      || '-'
    const progressLogs = Array.isArray(item.progress_logs) && item.progress_logs.length
      ? item.progress_logs
      : (event ? [event] : [])
    rows.push({
      ...item,
      id: `${job?.id || 'reauth'}-${key}`,
      email: item.email || '-',
      reauth_required: required,
      reauth_status: reauthStatus,
      progress_log: progressLog,
      progress_time: item.progress_time || result?.operation_time || event?.time || item.live_checked_at || '-',
      progress_logs: progressLogs,
      result: result?.result || (reauthStatus === '授权成功' ? '成功' : (reauthStatus === '授权失败' ? '失败' : '-')),
      reason: result?.reason || item.message || '-',
      operation_time: result?.operation_time || item.progress_time || '-',
    })
  }

  for (const result of resultRows) {
    const key = emailKey(result?.email)
    if (!key || seen.has(key)) continue
    const reauthStatus = statusFromResult(result) || '等待授权'
    rows.push({
      ...result,
      id: `${job?.id || 'reauth'}-${key}`,
      email: result.email || '-',
      live_status: '-',
      http_status: '401',
      reauth_required: true,
      reauth_status: reauthStatus,
      progress_log: result.result === '成功' ? '重登授权成功，令牌已回写原账号' : `重登授权失败：${result.reason || '-'}`,
      progress_time: result.operation_time || '-',
      progress_logs: [{
        time: result.operation_time || '-',
        text: result.result === '成功' ? '重登授权成功，令牌已回写原账号' : `重登授权失败：${result.reason || '-'}`,
      }],
    })
  }

  return rows.sort((left, right) => {
    const requiredDiff = Number(right.reauth_required) - Number(left.reauth_required)
    if (requiredDiff !== 0) return requiredDiff
    const statusDiff = statusPriority(left.reauth_status) - statusPriority(right.reauth_status)
    if (statusDiff !== 0) return statusDiff
    return String(left.email || '').localeCompare(String(right.email || ''))
  })
}

export function reauthStatusTagType(status) {
  if (status === '授权成功') return 'success'
  if (status === '授权失败') return 'danger'
  if (status === '授权中') return 'primary'
  if (status === '等待授权') return 'warning'
  return 'info'
}

export function reauthAccountRowClass({ row }) {
  return row?.reauth_required ? 'is-reauth-required' : ''
}
