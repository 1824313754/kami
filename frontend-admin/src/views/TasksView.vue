<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import { useSessionStore } from '../stores/session'
import { fetchJob, terminateJob } from '../api/admin'
import { showRequestError } from '../utils/message'
import { buildReauthAccountRows, reauthAccountRowClass, reauthStatusTagType } from '../utils/reauthProgress'

const route = useRoute()
const router = useRouter()
const sessionStore = useSessionStore()
const loading = ref(false)
const polling = ref(false)
const activeJob = ref(null)
const detailPage = ref(1)
const detailPageSize = ref(20)
const detailFilter = ref('all')
const taskFilters = ref({
  date: '',
  kind: '',
  status: '',
})
let timer = null

const jobs = computed(() => sessionStore.jobs || [])
const runningJobs = computed(() => jobs.value.filter((item) => !['done', 'error'].includes(item.status)))
const errorJobs = computed(() => jobs.value.filter((item) => item.status === 'error'))
const canTerminateLatestJob = computed(() => latestJob.value && ['queued', 'running'].includes(latestJob.value.status) && !latestJob.value.cancel_requested)
const currentJobId = computed(() => String(route.query.job_id || '').trim())
const latestJob = computed(() => {
  if (activeJob.value?.id) {
    return activeJob.value
  }
  return jobs.value[0] || null
})

const taskScope = computed(() => sessionStore.session?.pool?.scope || {})
const hasTaskFilters = computed(() => Boolean(taskFilters.value.date || taskFilters.value.kind || taskFilters.value.status))
const currentScopeLabel = computed(() => {
  const pool = sessionStore.session?.pool
  const businessType = pool?.business_type || ''
  const businessOption = (sessionStore.session?.business_type_options || []).find((item) => item.key === businessType)
  const business = businessOption?.label || businessType || '-'
  return `${pool?.owner_label || '-'} · ${business}`
})
const filteredSummaryText = computed(() => {
  if (!hasTaskFilters.value) return '当前业务全部任务'
  const parts = []
  if (taskFilters.value.date) parts.push(taskFilters.value.date)
  if (taskFilters.value.kind) parts.push(taskLabel({ kind: taskFilters.value.kind }))
  if (taskFilters.value.status) parts.push(jobStatusText(taskFilters.value.status))
  return parts.join(' / ')
})

const taskKindOptions = [
  { label: '文件上传', value: 'upload' },
  { label: '文件下载', value: 'file_download' },
  { label: '文件删除', value: 'file_delete' },
  { label: '文件测活', value: 'file_live_check' },
  { label: '前台提取', value: 'query_access' },
  { label: '重登授权', value: 'query_reauth' },
]

const taskStatusOptions = [
  { label: '排队中', value: 'queued' },
  { label: '运行中', value: 'running' },
  { label: '已完成', value: 'done' },
  { label: '失败', value: 'error' },
]

function taskTimeValue(item) {
  return item?.operation_time || item?.updated_at || item?.completed_at || item?.started_at || item?.created_at || ''
}

function taskDateKey(item) {
  const value = String(taskTimeValue(item) || '').trim()
  return value.match(/\d{4}-\d{2}-\d{2}/)?.[0] || 'unknown'
}

function formatDateKey(date) {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

function taskDateLabel(key) {
  if (key === 'unknown') return '未记录日期'
  const today = new Date()
  const yesterday = new Date()
  yesterday.setDate(today.getDate() - 1)
  if (key === formatDateKey(today)) return '今天'
  if (key === formatDateKey(yesterday)) return '昨天'
  return key
}

const taskDateGroups = computed(() => {
  const groups = []
  const groupByKey = new Map()
  for (const item of jobs.value) {
    const key = taskDateKey(item)
    if (!groupByKey.has(key)) {
      const group = { key, label: taskDateLabel(key), items: [] }
      groupByKey.set(key, group)
      groups.push(group)
    }
    groupByKey.get(key).items.push(item)
  }
  return groups
})

function taskLabel(item) {
  const kindMap = {
    file_live_check: '文件测活',
    upload: '文件上传',
    file_download: '文件下载',
    file_delete: '文件删除',
    query_access: '前台提取',
    query_reauth: '重登授权',
  }
  return kindMap[item?.kind] || item?.kind || '-'
}

function taskTraceCode(item) {
  return item?.extraction_no || item?.batch_no || ''
}

const isOutcomeTask = computed(() => ['upload', 'file_download', 'file_delete', 'query_reauth'].includes(latestJob.value?.kind || ''))
const operationTimeLabel = computed(() => {
  const kind = latestJob.value?.kind || ''
  if (kind === 'upload') return '上传时间'
  if (kind === 'file_download') return '下载时间'
  if (kind === 'file_delete') return '删除时间'
  return '操作时间'
})

const showOperationTime = computed(() => ['upload', 'file_download', 'file_delete'].includes(latestJob.value?.kind || ''))
const detailRows = computed(() => {
  const resultRows = latestJob.value?.result_rows || []
  const rows = latestJob.value?.kind === 'query_reauth'
    ? buildReauthAccountRows(latestJob.value)
    : resultRows
  return rows.map((item, index) => ({
    id: item.id || `${latestJob.value?.id || 'job'}-${item._key || item.email || index}`,
    batch_no: item.batch_no || latestJob.value?.batch_no || '-',
    email: item.email || '-',
    registered_at: item.registered_at || '-',
    live_checked_at: item.live_checked_at || '-',
    quota: item.quota || '-',
    quota_period: item.quota_period || '-',
    plan_type: item.plan_type || '-',
    http_status: item.http_status || '-',
    result: item.result || '-',
    reason: item.reason || item.message || '-',
    operation_time: item.operation_time || '-',
    live_status: item.live_status || '-',
    reauth_required: Boolean(item.reauth_required),
    reauth_status: item.reauth_status || '-',
    progress_log: item.progress_log || '-',
    progress_time: item.progress_time || '-',
    progress_logs: item.progress_logs || [],
  }))
})

function isFailureRow(item) {
  if (latestJob.value?.kind === 'query_reauth') {
    return item.result === '失败' || item.reauth_status === '授权失败'
  }
  if (isOutcomeTask.value) {
    return item.result === '失败'
  }
  const statusText = String(item.http_status || '').trim()
  if (!statusText || statusText === '-') return false
  const statusCode = Number(statusText)
  if (!Number.isFinite(statusCode)) return false
  return statusCode !== 200
}

const filteredDetailRows = computed(() => {
  if (detailFilter.value !== 'failure') return detailRows.value
  return detailRows.value.filter((item) => isFailureRow(item))
})

const progressProcessed = computed(() => {
  if (!latestJob.value) return 0
  return Number(latestJob.value.processed ?? latestJob.value.checked ?? 0) || 0
})

const progressTotal = computed(() => {
  if (!latestJob.value) return 0
  return Number(latestJob.value.total ?? latestJob.value.needed ?? 0) || 0
})

const progressRemaining = computed(() => {
  return Math.max(progressTotal.value - progressProcessed.value, 0)
})

const progressPercent = computed(() => {
  if (!latestJob.value) return 0
  if (!progressTotal.value) return latestJob.value.status === 'done' ? 100 : 0
  return Math.min(100, Math.round((progressProcessed.value / progressTotal.value) * 100))
})

const pagedDetailRows = computed(() => {
  const startIndex = (detailPage.value - 1) * detailPageSize.value
  return filteredDetailRows.value.slice(startIndex, startIndex + detailPageSize.value)
})

const taskStatPills = computed(() => {
  if (!latestJob.value) return []
  const job = latestJob.value
  const items = [
    { key: 'processed', label: '已处理', value: progressProcessed.value, tone: 'neutral' },
    { key: 'remaining', label: '剩余', value: progressRemaining.value, tone: 'neutral' },
  ]
  if (Number(job.success || 0) > 0) {
    items.push({ key: 'success', label: '正常', value: Number(job.success || 0), tone: 'success' })
  }
  if (Number(job.failure || 0) > 0) {
    items.push({
      key: 'failure',
      label: '异常',
      value: Number(job.failure || 0),
      tone: 'danger',
      clickable: true,
      active: detailFilter.value === 'failure',
    })
  }
  if (Number(job.skipped || 0) > 0) {
    items.push({ key: 'skipped', label: '跳过', value: Number(job.skipped || 0), tone: 'muted' })
  }
  if (Number(job.overwrite || 0) > 0) {
    items.push({ key: 'overwrite', label: '覆盖', value: Number(job.overwrite || 0), tone: 'warn' })
  }
  return items
})

async function refreshAll() {
  try {
    loading.value = true
    await sessionStore.refreshJobs(taskFilters.value)
    await syncSelectionAfterListRefresh()
    ElMessage.success('任务列表已刷新')
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

async function terminateLatestJob() {
  if (!canTerminateLatestJob.value) return
  try {
    await ElMessageBox.confirm(
      '确认终止这个未结束任务？系统会把任务标记为中断，并释放残留锁定状态。',
      '终止任务',
      { type: 'warning' },
    )
    loading.value = true
    stopPolling()
    const data = await terminateJob(latestJob.value.id, taskScope.value)
    activeJob.value = data.job || null
    await sessionStore.refreshJobs(taskFilters.value)
    ElMessage.success(data.message || '任务已终止')
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  } finally {
    loading.value = false
  }
}

async function applyTaskFilters() {
  loading.value = true
  try {
    stopPolling()
    activeJob.value = null
    resetDetailFilter()
    resetDetailPager()
    await sessionStore.refreshJobs(taskFilters.value)
    await syncSelectionAfterListRefresh()
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function resetTaskFilters() {
  taskFilters.value = { date: '', kind: '', status: '' }
  applyTaskFilters()
}

function setTaskDate(offset) {
  const target = new Date()
  target.setDate(target.getDate() + offset)
  taskFilters.value = {
    ...taskFilters.value,
    date: formatDateKey(target),
  }
  applyTaskFilters()
}

function jobStatusText(status) {
  const map = {
    queued: '排队中',
    running: '运行中',
    done: '已完成',
    error: '失败',
  }
  return map[status] || status || '-'
}

function jobStatusType(status) {
  if (status === 'done') return 'success'
  if (status === 'error') return 'danger'
  if (status === 'running') return 'warning'
  return 'info'
}

async function selectJob(jobId) {
  if (!jobId) return
  await router.replace({ name: 'tasks', query: { job_id: String(jobId) } })
}

async function showJob(jobId) {
  if (!jobId) return
  if (String(jobId) === currentJobId.value) {
    await syncCurrentJob(jobId)
    return
  }
  await selectJob(jobId)
}

async function syncSelectionAfterListRefresh() {
  const currentInList = currentJobId.value && jobs.value.some((item) => String(item.id) === currentJobId.value)
  if (currentInList) {
    await syncCurrentJob(currentJobId.value)
    return
  }
  if (jobs.value[0]?.id) {
    await showJob(jobs.value[0].id)
    return
  }
  activeJob.value = null
  if (currentJobId.value) {
    await router.replace({ name: 'tasks' })
  }
}

function downloadJobFile() {
  if (!latestJob.value?.download_url) return
  window.location.href = latestJob.value.download_url
}

function stopPolling() {
  polling.value = false
  if (timer) {
    clearTimeout(timer)
    timer = null
  }
}

function resetDetailPager() {
  detailPage.value = 1
}

function resetDetailFilter() {
  detailFilter.value = 'all'
}

function toggleDetailFilter(key) {
  if (key !== 'failure') return
  detailFilter.value = detailFilter.value === 'failure' ? 'all' : 'failure'
  resetDetailPager()
}

async function syncCurrentJob(jobId = currentJobId.value) {
  stopPolling()
  if (!jobId) {
    activeJob.value = null
    return
  }
  try {
    const data = await fetchJob(jobId, taskScope.value)
    activeJob.value = data.job || null
    if (!['done', 'error'].includes(data.job?.status)) {
      polling.value = true
      timer = setTimeout(() => syncCurrentJob(jobId), 1200)
    }
  } catch (error) {
    showRequestError(error)
  }
}

async function ensureLatestSelection() {
  if (currentJobId.value || !jobs.value[0]?.id) return
  await selectJob(jobs.value[0].id)
}

watch(
  () => currentJobId.value,
  async (jobId, previousJobId) => {
    if (jobId === previousJobId) return
    resetDetailFilter()
    resetDetailPager()
    await syncCurrentJob(jobId)
  },
  { immediate: true },
)

watch(
  () => latestJob.value?.id,
  () => {
    resetDetailFilter()
    resetDetailPager()
  },
)

watch(
  () => [filteredDetailRows.value.length, detailPageSize.value],
  () => {
    const maxPage = Math.max(1, Math.ceil(filteredDetailRows.value.length / detailPageSize.value))
    if (detailPage.value > maxPage) {
      detailPage.value = maxPage
    }
  },
)

watch(
  () => [
    sessionStore.session?.pool?.owner_id ?? '',
    sessionStore.session?.pool?.business_type || 'free',
    sessionStore.session?.pool?.group_tag || 'default',
  ],
  async () => {
    stopPolling()
    activeJob.value = null
    resetDetailFilter()
    resetDetailPager()
    await sessionStore.refreshJobs(taskFilters.value)
    await syncSelectionAfterListRefresh()
  },
)

onMounted(async () => {
  try {
    loading.value = true
    await sessionStore.refreshJobs(taskFilters.value)
    await ensureLatestSelection()
    if (currentJobId.value) {
      await syncCurrentJob(currentJobId.value)
    }
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
})

onBeforeUnmount(stopPolling)
</script>

<template>
  <div class="page-stack">
    <el-card shadow="never" class="page-card list-card" v-loading="loading">
      <div class="card-heading">
        <div>
          <h2>任务进度</h2>
          <p>查看上传、下载、删除、测活、提取和游客重登授权任务；支持按日期快速定位历史记录。</p>
        </div>
        <div class="action-strip">
          <el-button plain @click="refreshAll">刷新任务</el-button>
        </div>
      </div>

      <div class="task-filter-panel">
        <div class="task-filter-copy">
          <strong>{{ currentScopeLabel }}</strong>
          <span>{{ filteredSummaryText }} · 命中 {{ jobs.length }} 条</span>
        </div>
        <div class="task-filter-form">
          <el-date-picker
            v-model="taskFilters.date"
            type="date"
            value-format="YYYY-MM-DD"
            placeholder="选择日期"
            clearable
          />
          <el-select v-model="taskFilters.kind" placeholder="任务类型" clearable>
            <el-option v-for="item in taskKindOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
          <el-select v-model="taskFilters.status" placeholder="任务状态" clearable>
            <el-option v-for="item in taskStatusOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
          <el-button type="primary" @click="applyTaskFilters">查询</el-button>
          <div class="task-filter-quick">
            <el-button text @click="setTaskDate(0)">今天</el-button>
            <el-button text @click="setTaskDate(-1)">昨天</el-button>
            <el-button text :disabled="!hasTaskFilters" @click="resetTaskFilters">清空</el-button>
          </div>
        </div>
      </div>

      <div class="task-workbench">
        <aside class="task-history-panel">
          <div class="task-history-head">
            <strong>{{ hasTaskFilters ? '筛选结果' : '历史任务' }}</strong>
            <span>运行中 {{ runningJobs.length }} · 失败 {{ errorJobs.length }}</span>
          </div>
          <div class="task-history-list">
            <div v-for="group in taskDateGroups" :key="group.key" class="task-history-day">
              <div class="task-history-day-head">
                <strong>{{ group.label }}</strong>
                <span>{{ group.items.length }} 条</span>
              </div>
              <button
                v-for="item in group.items"
                :key="item.id"
                type="button"
                class="task-history-item"
                :class="{ 'is-active': item.id === latestJob?.id }"
                @click="selectJob(item.id)"
              >
                <span class="task-history-title">
                  <strong>{{ taskLabel(item) }}</strong>
                  <el-tag size="small" :type="jobStatusType(item.status)" effect="plain">{{ jobStatusText(item.status) }}</el-tag>
                </span>
                <small>{{ item.phase || '-' }}<template v-if="taskTraceCode(item)"> · {{ taskTraceCode(item) }}</template></small>
                <em>{{ taskTimeValue(item) || '-' }}</em>
              </button>
            </div>
          </div>
          <el-empty v-if="!jobs.length" :description="hasTaskFilters ? '当前筛选没有任务' : '暂无历史任务'" />
        </aside>

        <section class="task-detail-panel">
          <div
            v-if="latestJob"
            class="task-progress-panel"
            :class="{
              'is-running': polling && !['done', 'error'].includes(latestJob.status),
              'is-complete': latestJob.status === 'done',
              'is-error': latestJob.status === 'error',
            }"
          >
            <div class="task-progress-head">
              <div class="task-progress-copy">
                <strong>{{ taskLabel(latestJob) }}</strong>
                <span>
                  {{ latestJob.phase || '-' }}
                  <template v-if="taskTraceCode(latestJob)"> · {{ taskTraceCode(latestJob) }}</template>
                  <template v-if="latestJob.error"> · {{ latestJob.error }}</template>
                  <template v-else-if="polling"> · 正在持续刷新</template>
                </span>
              </div>
              <div class="task-progress-meta">
                <div class="task-progress-status">
                  {{ jobStatusText(latestJob.status) }}
                </div>
                <em>{{ progressPercent }}% · {{ progressProcessed }} / {{ progressTotal }}</em>
                <el-button v-if="canTerminateLatestJob" type="danger" plain size="small" @click="terminateLatestJob">终止任务</el-button>
              </div>
            </div>

            <div class="task-progress-bar">
              <el-progress :percentage="progressPercent" :stroke-width="8" :show-text="false" />
            </div>

            <div class="task-progress-stats-inline">
              <div
                v-for="item in taskStatPills"
                :key="item.key"
                class="task-progress-pill"
                :class="[`is-${item.tone}`, { 'is-clickable': item.clickable, 'is-active': item.active }]"
                @click="toggleDetailFilter(item.key)"
              >
                <span>{{ item.label }}</span>
                <strong>{{ item.value }}</strong>
              </div>
            </div>

            <div class="task-time-strip">
              <span>创建：{{ latestJob.created_at || '-' }}</span>
              <span>开始：{{ latestJob.started_at || '-' }}</span>
              <span>完成：{{ latestJob.completed_at || '-' }}</span>
              <span v-if="showOperationTime">{{ operationTimeLabel }}：{{ latestJob.operation_time || latestJob.completed_at || latestJob.updated_at || '-' }}</span>
            </div>

            <div v-if="latestJob.kind === 'file_download' && latestJob.download_ready" class="task-download-ready">
              <div>
                <strong>下载包已生成</strong>
                <span>{{ latestJob.download_filename || 'files.zip' }}</span>
              </div>
              <el-button type="primary" @click="downloadJobFile">下载文件包</el-button>
            </div>
          </div>

          <el-table :data="pagedDetailRows" :row-class-name="reauthAccountRowClass" class="main-table task-detail-table">
            <el-table-column v-if="latestJob?.kind === 'query_reauth'" type="expand" width="44">
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
            <el-table-column v-if="latestJob?.kind === 'upload'" prop="batch_no" label="批次号" min-width="180" show-overflow-tooltip />
            <el-table-column prop="email" label="邮箱名称" min-width="180" show-overflow-tooltip />
            <template v-if="latestJob?.kind === 'query_reauth'">
              <el-table-column label="测活" width="110">
                <template #default="{ row }">
                  <div class="reauth-live-cell">
                    <el-tag :type="row.live_status === '正常' ? 'success' : (row.live_status === '跳过' ? 'info' : 'danger')" effect="plain">
                      {{ row.live_status }}
                    </el-tag>
                    <small>HTTP {{ row.http_status }}</small>
                  </div>
                </template>
              </el-table-column>
              <el-table-column label="授权状态" width="110">
                <template #default="{ row }">
                  <el-tag :type="reauthStatusTagType(row.reauth_status)" effect="plain">{{ row.reauth_status }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="当前日志" min-width="340">
                <template #default="{ row }">
                  <div class="reauth-account-progress-cell">
                    <span>{{ row.progress_log }}</span>
                    <time>{{ row.progress_time }}</time>
                  </div>
                </template>
              </el-table-column>
              <el-table-column prop="quota" label="额度" width="90" />
              <el-table-column prop="quota_period" label="额度周期" width="105" />
              <el-table-column prop="plan_type" label="套餐" width="100" />
            </template>
            <template v-else-if="isOutcomeTask">
              <el-table-column prop="operation_time" :label="operationTimeLabel" min-width="180" show-overflow-tooltip />
              <el-table-column prop="result" label="结果" min-width="100" show-overflow-tooltip />
              <el-table-column prop="reason" label="明细" min-width="280" show-overflow-tooltip />
            </template>
            <template v-else>
              <el-table-column prop="registered_at" label="注册时间" min-width="180" show-overflow-tooltip />
              <el-table-column prop="live_checked_at" label="测活时间" min-width="180" show-overflow-tooltip />
              <el-table-column prop="quota" label="额度" min-width="150" show-overflow-tooltip />
              <el-table-column prop="quota_period" label="额度周期" min-width="120" show-overflow-tooltip />
              <el-table-column prop="plan_type" label="套餐类型" min-width="120" show-overflow-tooltip />
              <el-table-column prop="http_status" label="状态码" min-width="110" show-overflow-tooltip />
            </template>
          </el-table>

          <div class="pager-line" v-if="filteredDetailRows.length">
            <el-pagination
              v-model:current-page="detailPage"
              v-model:page-size="detailPageSize"
              layout="total, sizes, prev, pager, next"
              :total="filteredDetailRows.length"
              :page-sizes="[10, 20, 50, 100]"
            />
          </div>

          <el-empty v-if="!filteredDetailRows.length" :description="detailFilter === 'failure' ? '当前没有异常记录' : '当前任务没有结构化明细可展示'" />
        </section>
      </div>
    </el-card>
  </div>
</template>
