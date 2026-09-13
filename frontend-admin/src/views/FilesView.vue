<script setup>
import { reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Delete, Download, FolderAdd, Refresh, VideoPlay } from '@element-plus/icons-vue'
import { deleteFiles, downloadFiles, fetchFiles, importTwoFactor, liveCheckFiles, recoverFiles, uploadFiles } from '../api/admin'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

const sessionStore = useSessionStore()
const router = useRouter()
const loading = ref(false)
const selection = ref([])
const fileInput = ref(null)
const jsonFileInput = ref(null)
const twoFactorDialog = ref(false)
const twoFactorText = ref('')
const twoFactorImporting = ref(false)

async function readTwoFactorFile(event) {
  const file = event.target.files?.[0]
  if (file) twoFactorText.value = await file.text()
  event.target.value = ''
}

async function submitTwoFactor() {
  twoFactorImporting.value = true
  try {
    const data = await importTwoFactor({ ...scope, text: twoFactorText.value })
    ElMessage.success(data.message)
    twoFactorText.value = ''
    twoFactorDialog.value = false
    await loadData()
  } catch (error) {
    showRequestError(error)
  } finally {
    twoFactorImporting.value = false
  }
}

const scope = reactive({
  owner_id: sessionStore.session?.pool?.owner_id ?? null,
  business_type: sessionStore.session?.pool?.business_type || 'free',
  group_tag: sessionStore.session?.pool?.group_tag || 'default',
})

const filters = reactive({
  filename: '',
  cdkey_code: '',
  extraction_no: '',
  extract_status: '',
  live_status: '',
  date: '',
  page: 1,
  per_page: 20,
})

const dataState = ref({
  items: [],
  pagination: { page: 1, pages: 1, total: 0, per_page: 20 },
  pool_summary: {},
  deletable_total: 0,
  filtered_checking_total: 0,
})

function openTaskProgress(jobId) {
  router.push({
    name: 'tasks',
    query: {
      ...(jobId ? { job_id: String(jobId) } : {}),
    },
  })
}

async function loadData() {
  loading.value = true
  try {
    const data = await fetchFiles({ ...scope, ...filters })
    dataState.value = data
    sessionStore.patchPool(data.pool)
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.filename = ''
  filters.cdkey_code = ''
  filters.extraction_no = ''
  filters.extract_status = ''
  filters.live_status = ''
  filters.date = ''
  filters.page = 1
  loadData()
}

function handleSelectionChange(rows) {
  selection.value = rows
}

function openDetail(row) {
  router.push({
    name: 'file-detail',
    params: { fileId: row.id },
    query: {
      ...(scope.owner_id !== null ? { owner_id: String(scope.owner_id) } : {}),
      business_type: scope.business_type,
      group_tag: scope.group_tag,
    },
  })
}

function openUploadDialog() {
  fileInput.value?.click()
}

async function onUploadChange(event) {
  const files = Array.from(event.target.files || [])
  if (!files.length) return
  const formData = new FormData()
  files.forEach((file) => formData.append('files', file, file.webkitRelativePath || file.name))
  if (scope.owner_id !== null) {
    formData.append('owner_id', String(scope.owner_id))
  }
  formData.append('business_type', scope.business_type)
  formData.append('group_tag', scope.group_tag)
  try {
    const data = await uploadFiles(formData)
    ElMessage.success('上传任务已开始')
    openTaskProgress(data.job_id)
  } catch (error) {
    showRequestError(error)
  } finally {
    event.target.value = ''
  }
}

async function runDelete() {
  if (!selection.value.length) {
    ElMessage.warning('请先勾选文件')
    return
  }
  await ElMessageBox.confirm('确认删除已选文件？已提取文件删除后将不再出现在历史提取结果中。', '删除文件', { type: 'warning' })
  try {
    const data = await deleteFiles({
      ...scope,
      selected_ids: selection.value.map((item) => item.id),
    })
    ElMessage.success('删除任务已开始')
    openTaskProgress(data.job_id)
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  }
}

async function runDeleteFiltered() {
  if (!dataState.value.pagination.total) {
    ElMessage.warning('当前筛选结果为空')
    return
  }
  try {
    const preview = await deleteFiles({
      ...scope,
      ...filters,
      mode: 'filtered',
      preview: true,
    })
    if (!preview.file_count) {
      ElMessage.warning('当前筛选结果为空')
      return
    }
    const confirmText = preview.confirm_text || '确认删除'
    const { value } = await ElMessageBox.prompt(
      `当前筛选将删除 ${preview.file_count} 个文件，影响 ${preview.cdkey_count || 0} 张卡密，其中已提取文件 ${preview.bound_file_count || 0} 个。删除后相关历史提取结果将不可用。请输入“${confirmText}”继续。`,
      '二次确认删除筛选结果',
      {
        type: 'warning',
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        inputPlaceholder: confirmText,
      },
    )
    const data = await deleteFiles({
      ...scope,
      ...filters,
      mode: 'filtered',
      confirm_text: value,
    })
    ElMessage.success('删除任务已开始')
    openTaskProgress(data.job_id)
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  }
}

async function runDownload() {
  if (!selection.value.length) {
    ElMessage.warning('请先勾选文件')
    return
  }
  try {
    const data = await downloadFiles({
      ...scope,
      selected_ids: selection.value.map((item) => item.id),
    })
    ElMessage.success('下载打包任务已开始')
    openTaskProgress(data.job_id)
  } catch (error) {
    showRequestError(error)
  }
}

async function runDownloadFiltered() {
  if (!dataState.value.pagination.total) {
    ElMessage.warning('当前筛选结果为空')
    return
  }
  try {
    const data = await downloadFiles({
      ...scope,
      ...filters,
      mode: 'filtered',
    })
    ElMessage.success('下载打包任务已开始')
    openTaskProgress(data.job_id)
  } catch (error) {
    showRequestError(error)
  }
}

async function runLiveCheck() {
  if (!selection.value.length) {
    ElMessage.warning('请先勾选文件')
    return
  }
  try {
    const data = await liveCheckFiles({
      ...scope,
      selected_ids: selection.value.map((item) => item.id),
    })
    ElMessage.success('测活任务已开始')
    openTaskProgress(data.job_id)
  } catch (error) {
    showRequestError(error)
  }
}

async function runLiveCheckFiltered() {
  if (!dataState.value.pagination.total) {
    ElMessage.warning('当前筛选结果为空')
    return
  }
  try {
    const data = await liveCheckFiles({
      ...scope,
      ...filters,
      mode: 'filtered',
    })
    ElMessage.success('测活任务已开始')
    openTaskProgress(data.job_id)
  } catch (error) {
    showRequestError(error)
  }
}

async function runRecover() {
  const checkingRows = selection.value.filter((item) => item.can_recover)
  if (!checkingRows.length) {
    ElMessage.warning('已选文件里没有提取测活中的文件')
    return
  }
  try {
    const data = await recoverFiles({
      ...scope,
      selected_ids: checkingRows.map((item) => item.id),
    })
    ElMessage.success(data.message || '恢复完成')
    await loadData()
  } catch (error) {
    showRequestError(error)
  }
}

async function runRecoverFiltered() {
  if (!dataState.value.filtered_checking_total) {
    ElMessage.warning('当前筛选结果里没有提取测活中的文件')
    return
  }
  try {
    const data = await recoverFiles({
      ...scope,
      ...filters,
      mode: 'filtered',
    })
    ElMessage.success(data.message || '恢复完成')
    await loadData()
  } catch (error) {
    showRequestError(error)
  }
}

watch(
  () => [scope.owner_id, scope.business_type, scope.group_tag],
  () => {
    filters.page = 1
    loadData()
  },
  { immediate: true },
)

watch(
  () => sessionStore.session?.pool,
  (pool) => {
    if (!pool) return
    scope.owner_id = pool.owner_id ?? null
    scope.business_type = pool.business_type || 'free'
    scope.group_tag = pool.group_tag || 'default'
  },
  { deep: true, immediate: true },
)
</script>

<template>
  <div class="page-stack">
    <el-card shadow="never" class="page-card page-card-tight">
      <div class="filter-line">
        <el-input v-model="filters.filename" placeholder="搜索文件名或邮箱" clearable />
        <el-input v-model="filters.cdkey_code" placeholder="绑定卡密" clearable />
        <el-input v-model="filters.extraction_no" placeholder="提取编号" clearable />
        <el-select v-model="filters.extract_status" placeholder="提取状态" clearable>
          <el-option label="未提取" value="AVAILABLE" />
          <el-option label="提取测活中" value="CHECKING" />
          <el-option label="已提取" value="BOUND" />
          <el-option label="不可出库" value="DEAD" />
        </el-select>
        <el-select v-model="filters.live_status" placeholder="测活状态" clearable>
          <el-option label="未测活" value="UNCHECKED" />
          <el-option label="正常" value="NORMAL" />
          <el-option label="异常" value="ERROR" />
        </el-select>
        <el-date-picker v-model="filters.date" type="date" value-format="YYYY-MM-DD" placeholder="上传日期" />
        <el-button type="primary" @click="filters.page = 1; loadData()">查询</el-button>
        <el-button @click="resetFilters">清空</el-button>
        <div class="filter-line-upload">
          <el-button type="primary" :icon="FolderAdd" @click="jsonFileInput?.click()">上传 JSON / sub2api</el-button>
          <el-button :icon="FolderAdd" @click="openUploadDialog">上传文件目录</el-button>
        <el-button :icon="FolderAdd" @click="twoFactorDialog = true">导入 2FA 库</el-button>
          <input ref="fileInput" hidden type="file" webkitdirectory directory multiple @change="onUploadChange" />
          <input ref="jsonFileInput" hidden type="file" accept=".json,application/json" multiple @change="onUploadChange" />
        </div>
      </div>
    </el-card>

    <div class="stats-grid stats-grid-compact">
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">当前显示</div>
        <div class="metric-value">{{ dataState.pagination.total }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">可出库</div>
        <div class="metric-value">{{ dataState.pool_summary.available_files || 0 }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">测活异常</div>
        <div class="metric-value">{{ dataState.pool_summary.live_error_files || 0 }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">测活中</div>
        <div class="metric-value">{{ dataState.filtered_checking_total || 0 }}</div>
      </el-card>
    </div>

    <el-card shadow="never" class="page-card list-card">
      <div class="card-heading">
        <div>
          <h2>文件列表</h2>
          <p>把操作收口到一条动作带，主空间留给列表。</p>
        </div>
        <div class="action-strip">
          <el-button :icon="Download" @click="runDownload">下载已选</el-button>
          <el-button plain :icon="Download" @click="runDownloadFiltered">下载筛选结果</el-button>
          <el-button :icon="VideoPlay" @click="runLiveCheck">测活已选</el-button>
          <el-button plain :icon="VideoPlay" @click="runLiveCheckFiltered">测活筛选结果</el-button>
          <el-button :icon="Refresh" @click="runRecover">恢复测活中</el-button>
          <el-button plain :icon="Refresh" @click="runRecoverFiltered">恢复筛选结果</el-button>
          <el-button type="danger" plain :icon="Delete" @click="runDelete">删除已选</el-button>
          <el-button type="danger" plain :icon="Delete" @click="runDeleteFiltered">删除筛选结果</el-button>
        </div>
      </div>

      <el-table
        v-loading="loading"
        :data="dataState.items"
        class="main-table"
        @selection-change="handleSelectionChange"
      >
        <el-table-column type="selection" width="48" />
        <el-table-column prop="email_name" label="文件" min-width="220">
          <template #default="{ row }">
            <div class="cell-primary">{{ row.email_name }}</div>
            <div class="cell-secondary">{{ row.original_filename }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="status_text" label="状态" width="120" />
        <el-table-column prop="live_status_text" label="测活" width="100" />
        <el-table-column label="2FA" width="100">
          <template #default="{ row }"><el-tag :type="row.has_2fa ? 'success' : 'danger'" effect="plain">{{ row.two_factor_status || '未导入' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="测活代码" width="110">
          <template #default="{ row }">
            {{ row.live_http_status || '-' }}
          </template>
        </el-table-column>
        <el-table-column prop="live_quota" label="额度" width="140" />
        <el-table-column prop="bound_cdkey_code" label="绑定卡密" width="220" />
        <el-table-column prop="extraction_no" label="提取编号" width="190" />
        <el-table-column prop="upload_time" label="上传时间" width="170" />
        <el-table-column prop="live_checked_at" label="最近测活" width="170" />
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pager-line">
        <el-pagination
          v-model:current-page="filters.page"
          v-model:page-size="filters.per_page"
          layout="total, prev, pager, next"
          :total="dataState.pagination.total"
          @current-change="loadData"
        />
      </div>
    </el-card>
  </div>
  <el-dialog v-model="twoFactorDialog" title="导入 2FA 库" width="min(640px, 94vw)" :close-on-click-modal="!twoFactorImporting">
    <p>按邮箱自动匹配当前文件池已有账号，每行：邮箱--密码--2FA密钥。支持已绑定卡密的账号。</p>
    <input type="file" accept=".txt,text/plain" :disabled="twoFactorImporting" @change="readTwoFactorFile" />
    <el-input v-model="twoFactorText" type="textarea" :rows="10" :disabled="twoFactorImporting" placeholder="user@example.com--账号密码--Base32密钥" />
    <template #footer>
      <el-button :disabled="twoFactorImporting" @click="twoFactorDialog = false">取消</el-button>
      <el-button type="primary" :loading="twoFactorImporting" :disabled="!twoFactorText.trim()" @click="submitTwoFactor">导入并匹配</el-button>
    </template>
  </el-dialog>

</template>
