<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheck, CloseBold, Download, Key, Message, RefreshRight, Search, VideoPause } from '@element-plus/icons-vue'
import { useRoute, useRouter } from 'vue-router'
import { downloadQueryFiles, downloadQueryTwoFactor, downloadQueryReauth, downloadQuerySub, fetchQueryJob, fetchQueryTotpCode, fetchQueryTotpAccounts, fetchQueryResult, fetchQuerySession, fetchQueryStock, startQueryReauth, submitQueryAccess, terminateQueryReauth } from '../api/admin'
import { showRequestError } from '../utils/message'
import { buildReauthAccountRows, reauthAccountRowClass, reauthStatusTagType } from '../utils/reauthProgress'

const route = useRoute()
const router = useRouter()
const activeWorkflow = ref('extract')
const loading = ref(false)
const polling = ref(false)
const totpEnabled = ref(false)
const stock = ref({ available_files: 0, by_business_type: {}, updated_at: '-' })
const page = ref(1)
const pageSize = ref(10)
const reauthLiveCheckPage = ref(1)
const reauthLiveCheckPageSize = ref(10)
const totpAccountsLoading = ref(false)
const totpLoading = ref(false)
const totpCooldown = ref(0)
const downloadState = ref({
  active: false,
  label: '',
  phase: '',
})
const form = reactive({
  code: '',
  reauth_codes: '',
  totp_cdkey: '',
  totp_email: '',
  live_check: true,
  reauth_workers: 10,
})
const totpLookup = reactive({
  loadedCode: '',
  accounts: [],
  password: '',
  code: '',
  hasLoadedCode: false,
})
const reauth = ref({
  job: null,
  polling: false,
})
const reauthStopping = ref(false)
const result = ref({
  files: [],
  cdkeys: [],
  job: null,
})
let timer = null
let stockTimer = null
let reauthTimer = null
let totpCooldownTimer = null
let totpExpiryTimer = null

const currentJobId = computed(() => String(route.query.job_id || '').trim())
const currentAccessToken = computed(() => String(route.query.token || '').trim())
const currentReauthJobId = computed(() => String(route.query.reauth_job_id || '').trim())
const currentReauthToken = computed(() => String(route.query.reauth_token || '').trim())
const hasActiveJob = computed(() => Boolean(currentJobId.value))
const hasReauthJob = computed(() => Boolean(currentReauthJobId.value))
const isDone = computed(() => result.value?.job?.status === 'done')
const isError = computed(() => result.value?.job?.status === 'error')
const canDownload = computed(() => isDone.value && (result.value?.files?.length || 0) > 0)
const reauthDone = computed(() => reauth.value.job?.status === 'done')
const reauthRunning = computed(() => ['queued', 'running'].includes(reauth.value.job?.status))
const reauthAccountRows = computed(() => buildReauthAccountRows(reauth.value.job))
const reauthRequiredCount = computed(() => reauthAccountRows.value.filter((item) => item.reauth_required).length)
const pagedReauthAccountRows = computed(() => {
  const startIndex = (reauthLiveCheckPage.value - 1) * reauthLiveCheckPageSize.value
  return reauthAccountRows.value.slice(startIndex, startIndex + reauthLiveCheckPageSize.value)
})
const totpRefreshText = computed(() => {
  if (!totpLookup.hasLoadedCode) return '获取验证码'
  if (totpCooldown.value > 0) return `${totpCooldown.value} 秒后刷新`
  return '刷新验证码'
})
const extractStatusText = computed(() => {
  if (!hasActiveJob.value) return '待提交'
  if (isDone.value) return '已完成'
  if (isError.value) return '失败'
  return '进行中'
})
const reauthStatusText = computed(() => {
  if (!hasReauthJob.value && !reauth.value.job) return '待提交'
  if (reauthDone.value) return '已完成'
  if (reauth.value.job?.status === 'error') return '失败'
  return '进行中'
})
const reauthProgressPercent = computed(() => {
  if (reauthDone.value) return 100
  const total = Math.max(reauth.value.job?.total || 0, 1)
  const processed = Math.max(reauth.value.job?.processed || 0, 0)
  return Math.min(99, Math.round((processed / total) * 100))
})

const extractedCount = computed(() => Math.max(result.value?.files?.length ?? 0, 0))
const totalNeeded = computed(() => Math.max(result.value?.job?.display_needed ?? result.value?.job?.needed ?? result.value?.files?.length ?? 0, 0))
const progressDone = computed(() => {
  if (isDone.value) return Math.max(totalNeeded.value, extractedCount.value)
  return extractedCount.value
})
const progressScale = computed(() => Math.max(totalNeeded.value, progressDone.value, 1))
const progressPercent = computed(() => {
  const percent = Math.round((progressDone.value / progressScale.value) * 100)
  return Math.min(isDone.value ? 100 : 99, Math.max(0, percent))
})
const progressHeadline = computed(() => `${progressDone.value} / ${totalNeeded.value}`)
const progressLabel = computed(() => '提取进度')

const stockByType = computed(() => {
  const summary = stock.value?.by_business_type || {}
  const options = stock.value?.business_type_options || []
  if (options.length) {
    return options.map((item) => ({
      key: item.key,
      label: item.label || item.key,
      value: summary[item.key] ?? 0,
    }))
  }
  return Object.entries(summary).map(([key, value]) => ({
    key,
    label: key,
    value: value ?? 0,
  }))
})

const emptyDescription = computed(() => {
  if (isError.value) return '任务失败，当前没有可展示的提取结果'
  if (isDone.value) return '当前任务没有可下载的提取结果'
  return '正在整理首批结果，文件列表会自动更新'
})

const pagedFiles = computed(() => {
  const startIndex = (page.value - 1) * pageSize.value
  return sortedFiles.value.slice(startIndex, startIndex + pageSize.value)
})

const sortedFiles = computed(() => {
  const rows = [...(result.value?.files || [])]
  return rows.sort((left, right) => {
    const quotaDiff = quotaSortValue(right?.quota) - quotaSortValue(left?.quota)
    if (quotaDiff !== 0) return quotaDiff
    return String(left?.email || '').localeCompare(String(right?.email || ''))
  })
})

function applyJobSnapshot(job) {
  result.value = {
    ...result.value,
    job: job || result.value.job,
    files: job?.extracted_files || result.value.files,
  }
}

function resetResultState() {
  result.value = {
    files: [],
    cdkeys: [],
    job: null,
  }
  page.value = 1
}

function quotaSortValue(value) {
  const match = String(value || '').match(/(\d+)\s*%/)
  return match ? Number(match[1]) : -1
}

function resolveFilename(disposition, fallback) {
  const match = /filename\*=UTF-8''([^;]+)|filename=\"?([^\";]+)\"?/i.exec(disposition || '')
  const raw = match?.[1] || match?.[2]
  if (!raw) return fallback
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

function saveBlobFile(blob, filename) {
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

async function runDownload(label, requestFn, fallbackName, twoFactorRequest = null) {
  downloadState.value = {
    active: true,
    label,
    phase: '正在打包下载文件',
  }
  try {
    const [response, twoFactorResponse] = await Promise.all([
      requestFn(queryAccessParams.value),
      twoFactorRequest?.(queryAccessParams.value),
    ])
    const filename = resolveFilename(response.headers['content-disposition'], fallbackName)
    downloadState.value.phase = '正在写入浏览器下载'
    saveBlobFile(response.data, filename)
    if (twoFactorResponse) {
      const twoFactorFilename = resolveFilename(twoFactorResponse.headers['content-disposition'], 'accounts-2fa.txt')
      saveBlobFile(twoFactorResponse.data, twoFactorFilename)
    }
    downloadState.value.phase = '下载已开始'
    ElMessage.success(`${label}${twoFactorResponse ? '及 2FA TXT' : ''}已开始保存`)
  } catch (error) {
    downloadState.value.phase = '下载失败'
    if (error?.response?.data instanceof Blob) {
      try { error.response.data = JSON.parse(await error.response.data.text()) } catch { /* Keep the request error. */ }
    }
    showRequestError(error)
  } finally {
    setTimeout(() => {
      downloadState.value = {
        active: false,
        label: '',
        phase: '',
      }
    }, 1200)
  }
}

function downloadZip() {
  if (!canDownload.value) return
  return runDownload('CPA 压缩包下载', downloadQueryFiles, 'query-files.zip', downloadQueryTwoFactor)
}

function downloadTwoFactor() {
  if (!canDownload.value) return
  return runDownload('2FA TXT 下载', downloadQueryTwoFactor, 'accounts-2fa.txt')
}

function downloadSub() {
  if (!canDownload.value) return
  return runDownload('sub2api JSON 下载', downloadQuerySub, 'query-files-sub2api.json', downloadQueryTwoFactor)
}

function downloadReauth(format) {
  if (!reauthDone.value || !reauth.value.job?.id) return
  const isCard = format.startsWith('card-')
  const kind = format.replace('card-', '')
  const title = { cpa: 'CPA', sub2api: 'sub2api', '2fa': '2FA TXT' }[kind]
  const extension = { cpa: 'zip', sub2api: 'json', '2fa': 'txt' }[kind]
  const label = `${isCard ? '原卡密最新' : '重登授权'} ${title} 下载`
  const fallback = `${format}.${extension}`
  return runDownload(
    label,
      () => downloadQueryReauth(reauth.value.job.id, format, reauthAccessParams.value),
      fallback,
    )
}

const queryAccessParams = computed(() => ({
  job_id: currentJobId.value,
  token: currentAccessToken.value,
}))

const reauthAccessParams = computed(() => ({
  token: currentReauthToken.value || currentAccessToken.value,
}))

async function loadStock() {
  try {
    const data = await fetchQueryStock()
    stock.value = data.inventory
  } catch (error) {
    showRequestError(error)
  }
}

function stopStockPolling() {
  if (stockTimer) {
    clearInterval(stockTimer)
    stockTimer = null
  }
}

function startStockPolling() {
  stopStockPolling()
  stockTimer = setInterval(() => {
    loadStock()
  }, 15000)
}

function stopTotpCooldown() {
  if (totpCooldownTimer) {
    clearInterval(totpCooldownTimer)
    totpCooldownTimer = null
  }
}

function startTotpCooldown(seconds = 5) {
  stopTotpCooldown()
  totpCooldown.value = Math.max(1, Number(seconds) || 5)
  totpCooldownTimer = setInterval(() => {
    totpCooldown.value -= 1
    if (totpCooldown.value <= 0) {
      totpCooldown.value = 0
      stopTotpCooldown()
    }
  }, 1000)
}

async function loadTotpAccounts() {
  const code = form.totp_cdkey.trim()
  if (!code || totpAccountsLoading.value) return
  totpAccountsLoading.value = true
  try {
    const data = await fetchQueryTotpAccounts({ code })
    totpLookup.loadedCode = code
    totpLookup.accounts = data.accounts || []
    totpLookup.password = ''
    totpLookup.code = ''
    totpLookup.hasLoadedCode = false
    form.totp_email = totpLookup.accounts[0] || ''
    ElMessage.success(`已加载 ${totpLookup.accounts.length} 个邮箱`)
  } catch (error) {
    showRequestError(error)
  } finally {
    totpAccountsLoading.value = false
  }
}

function handleTotpAccountChange() {
  totpLookup.password = ''
  totpLookup.code = ''
  totpLookup.hasLoadedCode = false
}

async function loadTotpCode() {
  if (!totpLookup.loadedCode || !form.totp_email || totpLoading.value || totpCooldown.value > 0) return
  totpLoading.value = true
  const selectedCode = totpLookup.loadedCode
  const selectedEmail = form.totp_email
  try {
    const data = await fetchQueryTotpCode({
      code: selectedCode,
      email: selectedEmail,
    })
    if (totpLookup.loadedCode !== selectedCode || form.totp_email !== selectedEmail) return
    totpLookup.password = data.password || ''
    totpLookup.code = data.code || ''
    totpLookup.hasLoadedCode = true
    clearTimeout(totpExpiryTimer)
    totpExpiryTimer = setTimeout(() => { totpLookup.code = '' }, data.expires_in * 1000)
    startTotpCooldown(5)
  } catch (error) {
    const retryAfter = Number(error?.response?.data?.retry_after || 0)
    if (retryAfter > 0) startTotpCooldown(retryAfter)
    showRequestError(error)
  } finally {
    totpLoading.value = false
  }
}

async function loadResult(jobId = currentJobId.value) {
  if (!jobId) return
  const data = await fetchQueryResult({ job_id: jobId, token: currentAccessToken.value })
  if (jobId !== currentJobId.value) return
  result.value = data
  if (data.reauth_job && !currentReauthJobId.value) {
    reauth.value.job = data.reauth_job
    if (['queued', 'running'].includes(data.reauth_job.status) && !reauth.value.polling) {
      reauth.value.polling = true
      reauthTimer = setTimeout(() => pollReauth(data.reauth_job.id), 200)
    }
  }
  if (data?.job?.status === 'done') {
    await loadStock()
  }
}

function stopPolling() {
  polling.value = false
  if (timer) {
    clearTimeout(timer)
    timer = null
  }
}

function stopReauthPolling() {
  reauth.value.polling = false
  if (reauthTimer) {
    clearTimeout(reauthTimer)
    reauthTimer = null
  }
}

async function pollReauth(jobId) {
  try {
    const data = await fetchQueryJob(jobId, reauthAccessParams.value)
    if (reauth.value.job?.id !== jobId) return
    reauth.value.job = data.job
    if (['done', 'error'].includes(data.job?.status)) {
      reauthStopping.value = false
      stopReauthPolling()
      if (data.job?.status === 'done') {
        ElMessage.success('重登授权完成，成功结果已回写')
      }
      return
    }
  } catch (error) {
    stopReauthPolling()
    showRequestError(error)
    return
  }
  reauthTimer = setTimeout(() => pollReauth(jobId), 1200)
}

async function handleReauth() {
  if (!form.reauth_codes.trim() || reauthRunning.value) return
  activeWorkflow.value = 'oauth'
  reauthStopping.value = false
  reauthLiveCheckPage.value = 1
  stopReauthPolling()
  try {
    const data = await startQueryReauth({
      codes: form.reauth_codes,
      workers: form.reauth_workers,
    })
    reauth.value = {
      job: {
        id: data.job_id,
        status: 'queued',
        total: data.total || 0,
        processed: 0,
        live_check_total: data.total || 0,
        live_check_checked: 0,
        live_check_result_rows: [],
        result_rows: [],
      },
      polling: true,
    }
    await router.replace({
      name: 'query',
      query: { ...route.query, reauth_job_id: data.job_id, reauth_token: data.access_token },
    })
    ElMessage.success(data.reused ? '已回到正在运行的重登授权任务' : '重登授权已开始')
  } catch (error) {
    showRequestError(error)
  }
}

async function handleStopReauth() {
  if (!reauthRunning.value || reauthStopping.value || reauth.value.job?.cancel_requested) return
  try {
    await ElMessageBox.confirm(
      '确认停止当前重登授权任务？正在执行的账号会完成当前步骤，其余账号不再启动。',
      '停止任务',
      { type: 'warning' },
    )
    reauthStopping.value = true
    const data = await terminateQueryReauth(reauth.value.job.id, reauthAccessParams.value)
    reauth.value.job = data.job
    ElMessage.success(data.message || '停止请求已提交')
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  } finally {
    reauthStopping.value = false
  }
}

async function syncReauthJob(jobId) {
  stopReauthPolling()
  if (!jobId) {
    reauth.value = { job: null, polling: false }
    return
  }
  try {
    const data = await fetchQueryJob(jobId, reauthAccessParams.value)
    if (jobId !== currentReauthJobId.value) return
    reauth.value.job = data.job
    if (['queued', 'running'].includes(data.job?.status)) {
      reauth.value.polling = true
      reauthTimer = setTimeout(() => pollReauth(jobId), 1200)
    }
  } catch (error) {
    showRequestError(error)
  }
}

async function tickJob(jobId = currentJobId.value) {
  if (!jobId) return
  try {
    const data = await fetchQueryJob(jobId, { token: currentAccessToken.value })
    if (jobId !== currentJobId.value) return
    applyJobSnapshot(data.job)
    if (data.job?.status === 'done') {
      polling.value = false
      await loadResult(jobId)
      return
    }
    if (data.job?.status === 'error') {
      polling.value = false
      return
    }
  } catch (error) {
    polling.value = false
    showRequestError(error)
    return
  }
  if (polling.value && jobId === currentJobId.value) {
    timer = setTimeout(() => tickJob(jobId), 1100)
  }
}

async function startPolling(jobId = currentJobId.value) {
  if (!jobId) return
  stopPolling()
  if (['done', 'error'].includes(result.value?.job?.status)) return
  polling.value = true
  await tickJob(jobId)
}

async function syncJobState(jobId) {
  stopPolling()
  if (!jobId) {
    resetResultState()
    return
  }
  if (result.value?.job?.id !== jobId) {
    resetResultState()
  }
  try {
    const data = await fetchQueryJob(jobId, { token: currentAccessToken.value })
    if (jobId !== currentJobId.value) return
    applyJobSnapshot(data.job)
    if (data.job?.status === 'done') {
      await loadResult(jobId)
      return
    }
    if (data.job?.status === 'error') return
    await startPolling(jobId)
  } catch (error) {
    showRequestError(error)
  }
}

async function handleSubmit() {
  activeWorkflow.value = 'extract'
  loading.value = true
  try {
    const data = await submitQueryAccess(form)
    resetResultState()
    await router.replace({
      name: 'query',
      query: { ...route.query, job_id: data.job_id, token: data.access_token },
    })
    ElMessage.success(data.reused ? '已跳转到当前提取进度' : '任务已开始')
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

async function backToInput() {
  stopPolling()
  resetResultState()
  const query = { ...route.query }
  delete query.job_id
  delete query.token
  await router.replace({ name: 'query', query })
  await loadStock()
}

async function clearReauthResult() {
  stopReauthPolling()
  reauthStopping.value = false
  reauthLiveCheckPage.value = 1
  reauth.value = { job: null, polling: false }
  const query = { ...route.query }
  delete query.reauth_job_id
  delete query.reauth_token
  await router.replace({ name: 'query', query })
}

watch(
  () => [currentJobId.value, currentAccessToken.value],
  async ([jobId, token], [previousJobId, previousToken] = []) => {
    if (jobId === previousJobId && token === previousToken) return
    if (jobId) activeWorkflow.value = 'extract'
    await syncJobState(jobId)
  },
  { immediate: true },
)

watch(
  () => form.totp_cdkey,
  (value) => {
    if (String(value || '').trim() === totpLookup.loadedCode) return
    totpLookup.loadedCode = ''
    totpLookup.accounts = []
    totpLookup.password = ''
    totpLookup.code = ''
    totpLookup.hasLoadedCode = false
    form.totp_email = ''
  },
)

watch(
  () => [currentReauthJobId.value, currentReauthToken.value],
  async ([jobId, token], [previousJobId, previousToken] = []) => {
    if (jobId === previousJobId && token === previousToken) return
    reauthLiveCheckPage.value = 1
    if (jobId) activeWorkflow.value = 'oauth'
    await syncReauthJob(jobId)
  },
  { immediate: true },
)

watch(
  [() => reauthAccountRows.value.length, reauthLiveCheckPageSize],
  ([total, size]) => {
    const lastPage = Math.max(1, Math.ceil(total / size))
    if (reauthLiveCheckPage.value > lastPage) reauthLiveCheckPage.value = lastPage
  },
)

onMounted(async () => {
  try {
    const data = await fetchQuerySession()
    stock.value = data.inventory
    totpEnabled.value = data.totp_enabled === true
    if (!totpEnabled.value && activeWorkflow.value === 'totp') activeWorkflow.value = 'extract'
    startStockPolling()
  } catch (error) {
    showRequestError(error)
  }
})

onBeforeUnmount(() => {
  stopPolling()
  stopReauthPolling()
  stopStockPolling()
  stopTotpCooldown()
  clearTimeout(totpExpiryTimer)
})
</script>

<template>
  <div class="query-shell">
    <header class="query-page-header">
      <div class="query-page-title">
        <span>QUERY</span>
        <h1>卡密服务台</h1>
      </div>
      <div class="query-stock-strip">
        <div v-for="item in stockByType" :key="item.key" class="query-stock-item">
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
        </div>
        <small>{{ stock.updated_at || '-' }} 更新</small>
      </div>
    </header>

    <main class="query-workspace">
      <el-tabs v-model="activeWorkflow" class="query-workflow-tabs">
        <el-tab-pane name="extract">
          <template #label>
            <span class="query-tab-label">
              <el-icon><Key /></el-icon>
              卡密提取
              <i v-if="hasActiveJob" :class="{ 'is-done': isDone, 'is-error': isError }" />
            </span>
          </template>

          <div class="query-tab-content" :class="{ 'has-task': hasActiveJob }">
            <el-form label-position="top" class="query-operation-form">
              <div class="query-section-heading">
                <div>
                  <span>卡密提取</span>
                  <h2>提交卡密</h2>
                </div>
                <strong class="query-state" :class="{ 'is-running': hasActiveJob && !isDone && !isError, 'is-done': isDone, 'is-error': isError }">
                  {{ extractStatusText }}
                </strong>
              </div>

              <el-form-item label="卡密">
                <el-input v-model="form.code" type="textarea" :rows="7" resize="vertical" placeholder="每行一张卡密" />
              </el-form-item>

              <div class="query-form-toolbar">
                <el-checkbox v-model="form.live_check">提取前测活</el-checkbox>
                <el-button type="primary" :icon="Key" :loading="loading" :disabled="!form.code.trim()" @click="handleSubmit">
                  {{ hasActiveJob ? '重新提取' : '开始提取' }}
                </el-button>
              </div>
            </el-form>

            <transition name="query-stage-fade" mode="out-in">
              <section v-if="hasActiveJob" key="query-progress" class="query-task-section">
                <div class="query-task-heading">
                  <div>
                    <span>提取任务</span>
                    <h2>{{ isDone ? '提取完成' : (isError ? '提取失败' : '正在提取') }}</h2>
                  </div>
                  <div class="query-task-actions">
                    <transition name="query-download-pill">
                      <div v-if="downloadState.active" class="query-download-chip">
                        <strong>{{ downloadState.label }}</strong>
                        <span>{{ downloadState.phase }}</span>
                      </div>
                    </transition>
                    <el-button :icon="CloseBold" @click="backToInput">清除结果</el-button>
                    <el-button v-if="canDownload" :icon="Download" plain @click="downloadZip">CPA 压缩包</el-button>
                    <el-button v-if="canDownload" type="primary" :icon="Download" @click="downloadSub">sub2api JSON</el-button>
                    <el-button v-if="canDownload" :icon="Download" @click="downloadTwoFactor">2FA TXT</el-button>
                  </div>
                </div>

                <div class="query-progress-line" :class="{ 'is-running': polling && !isDone && !isError, 'is-done': isDone, 'is-error': isError }">
                  <div class="query-progress-track">
                    <el-progress :percentage="progressPercent" :stroke-width="12" :show-text="false" />
                  </div>
                  <strong>{{ progressHeadline }}</strong>
                  <span>{{ progressLabel }} · {{ progressPercent }}%</span>
                </div>

                <el-alert v-if="isError" :title="result.job?.error || '提取失败'" type="error" show-icon :closable="false" />

                <div class="query-result-head">
                  <div>
                    <span>提取结果</span>
                    <h3>账号列表</h3>
                  </div>
                  <small v-if="result.files.length">按额度从高到低</small>
                </div>

                <div class="query-table-wrap">
                  <el-table :data="pagedFiles" class="main-table">
                    <el-table-column prop="email" label="邮箱名称" min-width="220" show-overflow-tooltip />
                    <el-table-column prop="quota" label="额度" width="140" />
                    <el-table-column prop="quota_period" label="额度周期" width="120" />
                    <el-table-column prop="plan_type" label="套餐类型" width="120" />
                    <el-table-column prop="registered_at" label="注册时间" width="180" />
                    <el-table-column prop="live_checked_at" label="测活时间" width="180" />
                    <el-table-column prop="http_status" label="状态码" width="110" />
                    <el-table-column prop="extracted_at" label="提取时间" width="180" />
                  </el-table>
                </div>

                <div class="pager-line" v-if="result.files.length">
                  <el-pagination
                    v-model:current-page="page"
                    v-model:page-size="pageSize"
                    layout="total, sizes, prev, pager, next"
                    :total="sortedFiles.length"
                    :page-sizes="[10, 20, 50, 100]"
                  />
                </div>

                <el-empty v-if="!result.files.length" :description="emptyDescription" />
              </section>
            </transition>
          </div>
        </el-tab-pane>

        <el-tab-pane name="oauth">
          <template #label>
            <span class="query-tab-label">
              <el-icon><RefreshRight /></el-icon>
              重登授权
              <i v-if="hasReauthJob" :class="{ 'is-done': reauthDone, 'is-error': reauth.job?.status === 'error' }" />
            </span>
          </template>

          <div class="query-tab-content" :class="{ 'has-task': reauth.job }">
            <el-form label-position="top" class="query-operation-form">
              <div class="query-section-heading">
                <div>
                  <span>重登授权</span>
                  <h2>提交卡密</h2>
                </div>
                <strong class="query-state" :class="{ 'is-running': reauthRunning, 'is-done': reauthDone, 'is-error': reauth.job?.status === 'error' }">
                  {{ reauthStatusText }}
                </strong>
              </div>

              <el-form-item label="卡密">
                <el-input v-model="form.reauth_codes" type="textarea" :rows="7" resize="vertical" placeholder="每行一张卡密" />
              </el-form-item>

              <div class="query-form-toolbar query-oauth-toolbar">
                <label class="query-worker-option">
                  <span>并发数</span>
                  <el-input-number v-model="form.reauth_workers" :min="1" :max="10" controls-position="right" />
                </label>
                <el-button
                  type="primary"
                  :icon="RefreshRight"
                  :loading="reauthRunning"
                  :disabled="!form.reauth_codes.trim() || reauthRunning"
                  @click="handleReauth"
                >
                  开始重登授权
                </el-button>
              </div>
            </el-form>

            <section v-if="reauth.job" class="query-task-section">
              <div class="query-task-heading">
                <div>
                  <span>重登授权任务</span>
                  <h2>{{ reauth.job.phase || '等待开始' }}</h2>
                </div>
                <div class="query-task-actions">
                  <transition name="query-download-pill">
                    <div v-if="downloadState.active" class="query-download-chip">
                      <strong>{{ downloadState.label }}</strong>
                      <span>{{ downloadState.phase }}</span>
                    </div>
                  </transition>
                  <el-button
                    v-if="reauthRunning"
                    type="danger"
                    plain
                    :icon="VideoPause"
                    :loading="reauthStopping"
                    :disabled="reauth.job.cancel_requested"
                    @click="handleStopReauth"
                  >
                    {{ reauth.job.cancel_requested ? '停止中' : '停止任务' }}
                  </el-button>
                  <el-button :icon="CloseBold" @click="clearReauthResult">清除结果</el-button>
                </div>
              </div>

              <div class="query-progress-line" :class="{ 'is-running': reauthRunning, 'is-done': reauthDone, 'is-error': reauth.job.status === 'error' }">
                <div class="query-progress-track">
                  <el-progress
                    :percentage="reauthProgressPercent"
                    :status="reauth.job.status === 'error' ? 'exception' : (reauthDone ? 'success' : '')"
                    :stroke-width="12"
                    :show-text="false"
                  />
                </div>
                <strong>{{ reauth.job.processed || 0 }} / {{ reauth.job.total || 0 }}</strong>
                <span>成功 {{ reauth.job.success || 0 }} · 失败 {{ reauth.job.failure || 0 }}</span>
              </div>

              <el-alert v-if="reauth.job.status === 'error'" :title="reauth.job.error || '重登授权失败'" type="error" show-icon :closable="false" />

              <div v-if="reauthDone" class="query-download-groups">
                <div class="query-download-group">
                  <div>
                    <CircleCheck />
                    <span>本次重登授权成功文件</span>
                  </div>
                  <el-button :icon="Download" plain @click="downloadReauth('cpa')">CPA ZIP</el-button>
                  <el-button type="primary" :icon="Download" @click="downloadReauth('sub2api')">sub2api JSON</el-button>
                  <el-button :icon="Download" @click="downloadReauth('2fa')">2FA TXT</el-button>
                </div>
                <div class="query-download-group">
                  <div>
                    <Key />
                    <span>原卡密最新文件</span>
                  </div>
                  <el-button :icon="Download" plain @click="downloadReauth('card-cpa')">CPA ZIP</el-button>
                  <el-button :icon="Download" @click="downloadReauth('card-sub2api')">sub2api JSON</el-button>
                  <el-button :icon="Download" @click="downloadReauth('card-2fa')">2FA TXT</el-button>
                </div>
              </div>

              <div class="query-result-head reauth-account-head">
                <div>
                  <span>账户进度</span>
                  <h3>测活与授权结果</h3>
                </div>
                <small>
                  测活 {{ reauth.job.live_check_checked || 0 }} / {{ reauth.job.live_check_total || 0 }}
                  · 需授权 {{ reauthRequiredCount }}
                </small>
              </div>

              <div v-if="reauthAccountRows.length" class="query-table-wrap">
                <el-table
                  :data="pagedReauthAccountRows"
                  :row-class-name="reauthAccountRowClass"
                  class="main-table query-reauth-account-table"
                >
                  <el-table-column type="expand" width="44">
                    <template #default="{ row }">
                      <div class="reauth-account-log-history" role="log">
                        <div v-for="(entry, index) in row.progress_logs || []" :key="`${entry.time}-${index}`">
                          <time>{{ entry.time || '-' }}</time>
                          <span>{{ entry.text || '-' }}</span>
                        </div>
                        <span v-if="!row.progress_logs?.length">暂无账户日志</span>
                      </div>
                    </template>
                  </el-table-column>
                  <el-table-column prop="email" label="账号邮箱" min-width="210" show-overflow-tooltip />
                  <el-table-column label="测活" width="110">
                    <template #default="{ row }">
                      <div class="reauth-live-cell">
                        <el-tag :type="row.live_status === '正常' ? 'success' : (row.live_status === '跳过' ? 'info' : 'danger')" effect="plain">
                          {{ row.live_status || '-' }}
                        </el-tag>
                        <small>HTTP {{ row.http_status || '-' }}</small>
                      </div>
                    </template>
                  </el-table-column>
                  <el-table-column label="授权状态" width="110">
                    <template #default="{ row }">
                      <el-tag :type="reauthStatusTagType(row.reauth_status)" effect="plain">
                        {{ row.reauth_status }}
                      </el-tag>
                    </template>
                  </el-table-column>
                  <el-table-column label="当前日志" min-width="360">
                    <template #default="{ row }">
                      <div class="reauth-account-progress-cell">
                        <span>{{ row.progress_log || '-' }}</span>
                        <time>{{ row.progress_time || '-' }}</time>
                      </div>
                    </template>
                  </el-table-column>
                  <el-table-column prop="quota" label="额度" width="90" />
                  <el-table-column prop="quota_period" label="额度周期" width="105" />
                  <el-table-column prop="plan_type" label="套餐" width="100" />
                </el-table>
              </div>
              <div v-if="reauthAccountRows.length" class="pager-line query-live-check-pager">
                <el-pagination
                  v-model:current-page="reauthLiveCheckPage"
                  v-model:page-size="reauthLiveCheckPageSize"
                  layout="total, sizes, prev, pager, next"
                  :total="reauthAccountRows.length"
                  :page-sizes="[10, 20, 50, 100]"
                />
              </div>
              <el-empty v-else description="等待首个账户测活结果" />
            </section>
          </div>
        </el-tab-pane>

        <el-tab-pane v-if="totpEnabled" name="totp">
          <template #label>
            <span class="query-tab-label">
              <el-icon><Message /></el-icon>
              2FA 验证码
            </span>
          </template>

          <div class="query-totp-workbench">
            <el-form label-position="top" class="query-totp-controls">
              <div class="query-section-heading">
                <div>
                  <span>2FA 验证码</span>
                  <h2>选择账号邮箱</h2>
                </div>
                <strong v-if="totpLookup.accounts.length" class="query-totp-count">
                  {{ totpLookup.accounts.length }} 个
                </strong>
              </div>

              <el-form-item label="卡密">
                <el-input
                  v-model="form.totp_cdkey"
                  clearable
                  placeholder="输入一张卡密"
                  @keyup.enter="loadTotpAccounts"
                />
              </el-form-item>
              <el-button
                type="primary"
                :icon="Search"
                :loading="totpAccountsLoading"
                :disabled="!form.totp_cdkey.trim()"
                @click="loadTotpAccounts"
              >
                加载邮箱
              </el-button>

              <el-form-item v-if="totpLookup.accounts.length" label="账号邮箱">
                <el-select
                  v-model="form.totp_email"
                  filterable
                  placeholder="选择账号邮箱"
                  @change="handleTotpAccountChange"
                >
                  <el-option v-for="email in totpLookup.accounts" :key="email" :label="email" :value="email" />
                </el-select>
              </el-form-item>
            </el-form>

            <section class="query-totp-reader">
              <div class="query-task-heading">
                <div>
                  <span>2FA 验证码</span>
                  <h2>账号登录信息</h2>
                </div>
                <el-button
                  :icon="RefreshRight"
                  :loading="totpLoading"
                  :disabled="!totpLookup.loadedCode || !form.totp_email || totpCooldown > 0"
                  @click="loadTotpCode"
                >
                  {{ totpRefreshText }}
                </el-button>
              </div>

              <dl v-if="form.totp_email" class="query-totp-fields">
                <div class="query-totp-field">
                  <dt>
                    <span>邮箱</span>
                    <small>用于登录账号</small>
                  </dt>
                  <dd>{{ form.totp_email }}</dd>
                </div>
                <div class="query-totp-field">
                  <dt>
                    <span>密码</span>
                    <small>账号登录密码</small>
                  </dt>
                  <dd :class="{ 'is-placeholder': !totpLookup.password }">{{ totpLookup.password || '点击获取验证码后显示' }}</dd>
                </div>
                <div class="query-totp-field query-totp-field-code">
                  <dt>
                    <span>2FA 动态码</span>
                    <small>两步验证 · 每 30 秒更新</small>
                  </dt>
                  <dd>
                    <strong v-if="totpLookup.code">{{ totpLookup.code }}</strong>
                    <span v-else class="is-placeholder">{{ totpLookup.hasLoadedCode ? '动态码已过期，请刷新' : '点击上方按钮获取' }}</span>
                  </dd>
                </div>
              </dl>
              <el-empty v-else description="输入卡密并选择账号后，查看登录信息" />
            </section>
          </div>
        </el-tab-pane>
      </el-tabs>
    </main>
  </div>
</template>
