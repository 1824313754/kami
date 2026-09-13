<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, Delete, Download, Plus, Setting, Upload } from '@element-plus/icons-vue'
import { createCdkeys, deleteCdkeys, deleteCdkeysByCodes, exportCdkeysUrl, fetchCdkeys, importCdkeys, updateOverIssue } from '../api/admin'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

const sessionStore = useSessionStore()
const router = useRouter()
const loading = ref(false)
const selection = ref([])
const createDialogVisible = ref(false)
const importDialogVisible = ref(false)
const overIssueDialogVisible = ref(false)
const generatedCodes = ref([])

const scope = reactive({
  owner_id: sessionStore.session?.pool?.owner_id ?? null,
  business_type: sessionStore.session?.pool?.business_type || 'free',
  group_tag: sessionStore.session?.pool?.group_tag || 'default',
})

const filters = reactive({
  status: '',
  batch_no: '',
  code: '',
  extraction_no: '',
  date: '',
  page: 1,
  per_page: 20,
})

const createForm = reactive({
  total_count: 10,
  files_per_key: 1,
  remark: '',
})

const importForm = reactive({
  codes: '',
  remark: '导入卡密',
})

const overIssueForm = reactive({
  over_issue_files: 0,
})

const codeDeleteForm = reactive({
  codes: '',
})

const dataState = ref({
  items: [],
  pagination: { page: 1, pages: 1, total: 0, per_page: 20 },
  pool_summary: {},
  capacity: null,
})

const generatedCodesText = computed(() => generatedCodes.value.join('\n'))
const exportUrl = computed(() => exportCdkeysUrl({ ...scope, ...filters }))
const selectedCodesText = computed(() => selection.value.map((item) => item.code).filter(Boolean).join('\n'))

async function loadData() {
  loading.value = true
  try {
    const data = await fetchCdkeys({ ...scope, ...filters })
    dataState.value = data
    overIssueForm.over_issue_files = data.capacity?.configured_over_issue_files || 0
    sessionStore.patchPool(data.pool)
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function handleSelectionChange(rows) {
  selection.value = rows
}

function openDetail(row) {
  router.push({
    name: 'cdkey-detail',
    params: { cdkeyId: row.id },
    query: {
      ...(scope.owner_id !== null ? { owner_id: String(scope.owner_id) } : {}),
      business_type: scope.business_type,
      group_tag: scope.group_tag,
    },
  })
}

async function submitCreate() {
  try {
    const data = await createCdkeys({ ...scope, ...createForm })
    generatedCodes.value = data.codes || []
    dataState.value.capacity = data.capacity || dataState.value.capacity
    createDialogVisible.value = false
    ElMessage.success(data.message || '已生成卡密')
    await copyGeneratedCodes()
    await loadData()
  } catch (error) {
    showRequestError(error)
  }
}

async function submitImport() {
  if (!importForm.codes.trim()) {
    ElMessage.warning('请输入要导入的卡密')
    return
  }
  try {
    const data = await importCdkeys({
      owner_id: scope.owner_id,
      codes: importForm.codes,
      remark: importForm.remark,
    })
    ElMessage.success(data.message || '导入成功')
    importDialogVisible.value = false
    importForm.codes = ''
    await loadData()
  } catch (error) {
    showRequestError(error)
  }
}

async function copyGeneratedCodes() {
  if (!generatedCodesText.value) return
  await navigator.clipboard.writeText(generatedCodesText.value)
  ElMessage.success('新生成卡密已复制')
}

function saveTextFile(text, filename) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

function exportSelectedCodes() {
  if (!selection.value.length) {
    ElMessage.warning('请先勾选卡密')
    return
  }
  if (!selectedCodesText.value) {
    ElMessage.warning('已选卡密为空')
    return
  }
  saveTextFile(selectedCodesText.value, 'cdkeys-selected.txt')
  ElMessage.success(`已导出 ${selection.value.length} 张卡密`)
}

async function submitOverIssue() {
  try {
    const data = await updateOverIssue({
      ...scope,
      over_issue_files: overIssueForm.over_issue_files,
    })
    ElMessage.success(data.message || '已更新')
    dataState.value.capacity = data.capacity
    overIssueDialogVisible.value = false
  } catch (error) {
    showRequestError(error)
  }
}

async function removeSelected() {
  if (!selection.value.length) {
    ElMessage.warning('请先勾选卡密')
    return
  }
  await ElMessageBox.confirm('确认删除已选卡密？如果已提取，会同时清理绑定文件。', '删除卡密', { type: 'warning' })
  try {
    const data = await deleteCdkeys({
      ...scope,
      selected_ids: selection.value.map((item) => item.id),
    })
    ElMessage.success(data.message || '删除成功')
    await loadData()
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  }
}

async function removeFiltered() {
  if (!dataState.value.pagination.total) {
    ElMessage.warning('当前筛选结果为空')
    return
  }
  try {
    const preview = await deleteCdkeys({
      ...scope,
      ...filters,
      mode: 'filtered',
      preview: true,
    })
    if (!preview.cdkey_count) {
      ElMessage.warning('当前筛选结果为空')
      return
    }
    const confirmText = preview.confirm_text || '确认删除'
    const { value } = await ElMessageBox.prompt(
      `当前筛选将删除 ${preview.cdkey_count} 张卡密，并清理绑定文件 ${preview.bound_file_count || 0} 个。请输入“${confirmText}”继续。`,
      '二次确认删除筛选结果',
      {
        type: 'warning',
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        inputPlaceholder: confirmText,
      },
    )
    const data = await deleteCdkeys({
      ...scope,
      ...filters,
      mode: 'filtered',
      confirm_text: value,
    })
    ElMessage.success(data.message || '删除成功')
    await loadData()
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  }
}

async function removeByCodes() {
  if (!codeDeleteForm.codes.trim()) {
    ElMessage.warning('请输入卡密')
    return
  }
  await ElMessageBox.confirm('确认按文本删除这批卡密？如果已提取，会同时清理绑定文件。', '文本删除', { type: 'warning' })
  try {
    const data = await deleteCdkeysByCodes({
      ...scope,
      codes: codeDeleteForm.codes,
    })
    ElMessage.success(data.message || '删除成功')
    codeDeleteForm.codes = ''
    await loadData()
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
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
      <div class="toolbar-head toolbar-head-between">
        <div class="filter-line filter-line-inline">
          <el-select v-model="filters.status" placeholder="状态" clearable>
            <el-option label="待提取" value="PENDING" />
            <el-option label="提取中" value="CHECKING" />
            <el-option label="已提取" value="EXTRACTED" />
          </el-select>
          <el-input v-model="filters.batch_no" placeholder="批次号" clearable />
          <el-input v-model="filters.code" placeholder="卡密" clearable />
          <el-input v-model="filters.extraction_no" placeholder="提取编号" clearable />
          <el-date-picker v-model="filters.date" type="date" value-format="YYYY-MM-DD" placeholder="创建日期" />
          <el-button type="primary" @click="filters.page = 1; loadData()">查询</el-button>
          <el-button @click="filters.status='';filters.batch_no='';filters.code='';filters.extraction_no='';filters.date='';filters.page=1;loadData()">清空</el-button>
        </div>
        <div class="action-strip">
          <el-button type="primary" :icon="Plus" @click="createDialogVisible = true">卡密生成</el-button>
          <el-button :icon="Upload" @click="importDialogVisible = true">导入卡密</el-button>
          <el-button :icon="Setting" @click="overIssueDialogVisible = true">超发</el-button>
        </div>
      </div>
    </el-card>

    <div class="stats-grid stats-grid-compact">
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">当前显示</div>
        <div class="metric-value">{{ dataState.pagination.total }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">2FA 可生成文件数</div>
        <div class="metric-value">{{ dataState.capacity?.total_bindable_files || 0 }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">超发剩余</div>
        <div class="metric-value">{{ dataState.capacity?.remaining_over_issue_files || 0 }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card mini">
        <div class="metric-label">待提取文件数</div>
        <div class="metric-value">{{ dataState.pool_summary.pending_cdkey_files || 0 }}</div>
      </el-card>
    </div>

    <el-card shadow="never" class="page-card list-card">
      <div class="card-heading">
        <div>
          <h2>卡密列表</h2>
          <p>只保留生成、超发、删除和详情这几个高频动作。</p>
        </div>
        <div class="action-strip">
          <el-button v-if="generatedCodes.length" :icon="CopyDocument" @click="copyGeneratedCodes">复制最近生成</el-button>
          <el-button :icon="Download" @click="exportSelectedCodes">导出已选 TXT</el-button>
          <el-button :icon="Download" :href="exportUrl" tag="a">导出筛选结果</el-button>
          <el-button type="danger" plain :icon="Delete" @click="removeSelected">删除已选</el-button>
          <el-button type="danger" plain :icon="Delete" @click="removeFiltered">删除筛选结果</el-button>
        </div>
      </div>

      <el-table
        v-loading="loading"
        :data="dataState.items"
        class="main-table"
        @selection-change="handleSelectionChange"
      >
        <el-table-column type="selection" width="48" />
        <el-table-column prop="code" label="卡密" min-width="260" />
        <el-table-column prop="extract_status_text" label="状态" width="100" />
        <el-table-column prop="batch_no" label="批次号" min-width="220" />
        <el-table-column prop="extraction_no" label="提取编号" width="190" />
        <el-table-column prop="files_per_key" label="文件数" width="90" />
        <el-table-column prop="created_at" label="创建时间" width="170" />
        <el-table-column prop="extracted_at" label="提取时间" width="170" />
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="list-bottom-tools">
        <el-input
          v-model="codeDeleteForm.codes"
          type="textarea"
          :rows="3"
          placeholder="按文本删除卡密，每行一张"
        />
        <div class="action-strip">
          <el-button type="danger" plain @click="removeByCodes">删除输入卡密</el-button>
        </div>
      </div>

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

    <el-dialog v-model="createDialogVisible" title="卡密生成" width="520px">
      <p>仅使用已导入有效 2FA 的库存，扣除待提取卡密占用；超发额度不增加可生成数量。</p>
      <el-form label-position="top">
        <el-form-item label="生成数量">
          <el-input-number v-model="createForm.total_count" :min="1" :max="10000" />
        </el-form-item>
        <el-form-item label="每张文件数">
          <el-input-number v-model="createForm.files_per_key" :min="1" :max="1000" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="createForm.remark" type="textarea" :rows="3" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="action-strip">
          <el-button @click="createDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="submitCreate">生成并复制</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="importDialogVisible" title="导入卡密" width="560px">
      <el-form label-position="top">
        <el-form-item label="卡密">
          <el-input
            v-model="importForm.codes"
            type="textarea"
            :rows="8"
            placeholder="每行一张卡密；只导入未提取卡密"
          />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="importForm.remark" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="action-strip">
          <el-button @click="importDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="submitImport">导入</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="overIssueDialogVisible" title="超发额度" width="420px">
      <el-form label-position="top">
        <el-form-item label="超发文件数">
          <el-input-number v-model="overIssueForm.over_issue_files" :min="0" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="action-strip">
          <el-button @click="overIssueDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="submitOverIssue">保存</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>
