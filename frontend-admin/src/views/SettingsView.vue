<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Delete, Plus } from '@element-plus/icons-vue'
import { fetchSettings, saveSettings } from '../api/admin'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

const loading = ref(false)
const sessionStore = useSessionStore()
const httpStatusOptions = Array.from({ length: 500 }, (_, index) => index + 100)
const form = reactive({
  live_check_timeout: '10',
  live_check_user_agent: '',
  unshippable_http_statuses: [401],
  task_workers: '50',
  query_totp_enabled: true,
  business_type_options: [],
})

function normalizeBusinessOptions(items) {
  return (Array.isArray(items) ? items : []).map((item) => ({
    key: item?.key || codeToKey(item?.code || item?.label),
    label: item?.label || item?.code || '',
    code: item?.code || item?.label || '',
    enabled: item?.enabled !== false,
    show_in_query: item?.show_in_query !== false,
    locked: item?.locked === true,
  }))
}

function codeToKey(value) {
  const text = String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '')
  if (!text) return ''
  return /^[a-z]/.test(text) ? text : `b${text}`
}

function applySettings(settings) {
  Object.assign(form, settings)
  const statusValues = settings?.unshippable_http_statuses ?? settings?.unshippable_http_status ?? [401]
  form.unshippable_http_statuses = [...new Set((Array.isArray(statusValues) ? statusValues : [statusValues])
    .map(Number)
    .filter((value) => Number.isInteger(value) && value >= 100 && value <= 599))]
  form.business_type_options = normalizeBusinessOptions(settings?.business_type_options)
}

async function loadData() {
  loading.value = true
  try {
    const data = await fetchSettings()
    applySettings(data.settings)
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

async function handleSave() {
  loading.value = true
  try {
    const data = await saveSettings({
      ...form,
      business_type_options: normalizeBusinessOptions(form.business_type_options),
    })
    applySettings(data.settings)
    if (data.session) {
      sessionStore.applySession(data.session)
    }
    ElMessage.success(data.message || '已保存')
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function nextBusinessOption() {
  const existing = new Set(form.business_type_options.map((item) => item.key))
  let index = form.business_type_options.length + 1
  let key = `custom${index}`
  while (existing.has(key)) {
    index += 1
    key = `custom${index}`
  }
  return {
    key,
    label: `自定义${index}`,
    code: `CUSTOM${index}`,
    enabled: true,
    show_in_query: true,
    locked: false,
  }
}

function applyBusinessCode(row, value) {
  const code = String(value || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '')
  row.code = code
  if (!row.label) {
    row.label = code
  }
  if (!row.locked) {
    row.key = codeToKey(code)
  }
}

function addBusinessType() {
  form.business_type_options.push(nextBusinessOption())
}

function removeBusinessType(index) {
  if (form.business_type_options.length <= 1) {
    ElMessage.warning('至少保留一个业务类型')
    return
  }
  form.business_type_options.splice(index, 1)
}

onMounted(loadData)
</script>

<template>
  <div class="page-stack">
    <el-card shadow="never" class="page-card settings-card" v-loading="loading">
      <div class="card-heading">
        <div>
          <h2>系统设置</h2>
          <p>保留当前真实可调的并发和测活参数，不增加虚假的配置项。</p>
        </div>
      </div>

      <el-form label-position="top" class="settings-form">
        <el-form-item label="测活超时（秒）">
          <el-input v-model="form.live_check_timeout" />
        </el-form-item>
        <el-form-item label="任务并发数">
          <el-input v-model="form.task_workers" />
        </el-form-item>
        <el-form-item label="2FA 验证码">
          <el-switch v-model="form.query_totp_enabled" active-text="启用" inactive-text="关闭" />
        </el-form-item>
        <el-form-item label="测活 User-Agent">
          <el-input v-model="form.live_check_user_agent" type="textarea" :rows="4" />
        </el-form-item>
        <el-form-item label="不可出库状态码">
          <el-select
            v-model="form.unshippable_http_statuses"
            multiple
            filterable
            collapse-tags
            :max-collapse-tags="6"
            style="width: 100%"
          >
            <el-option v-for="status in httpStatusOptions" :key="status" :label="String(status)" :value="status" />
          </el-select>
        </el-form-item>
        <div class="settings-section-head">
          <div>
            <h3>业务类型</h3>
            <p>业务编码作为卡密前缀，创建保存后不能修改；显示名称可用于页面展示。</p>
          </div>
          <el-button :icon="Plus" @click="addBusinessType">新增类型</el-button>
        </div>
        <el-table :data="form.business_type_options" class="settings-business-table">
          <el-table-column label="业务编码" min-width="180">
            <template #default="{ row }">
              <el-input
                :model-value="row.code"
                :disabled="row.locked"
                placeholder="PLUS"
                @update:model-value="(value) => applyBusinessCode(row, value)"
              />
            </template>
          </el-table-column>
          <el-table-column label="显示名称" min-width="180">
            <template #default="{ row }">
              <el-input v-model="row.label" placeholder="Plus 套餐" maxlength="64" />
            </template>
          </el-table-column>
          <el-table-column label="启用" width="110" align="center">
            <template #default="{ row }">
              <el-switch v-model="row.enabled" />
            </template>
          </el-table-column>
          <el-table-column label="前台显示" width="120" align="center">
            <template #default="{ row }">
              <el-switch v-model="row.show_in_query" :disabled="!row.enabled" />
            </template>
          </el-table-column>
          <el-table-column width="80" align="center">
            <template #default="{ $index }">
              <el-tooltip content="删除">
                <el-button :icon="Delete" circle text type="danger" @click="removeBusinessType($index)" />
              </el-tooltip>
            </template>
          </el-table-column>
        </el-table>
        <el-button type="primary" @click="handleSave">保存设置</el-button>
      </el-form>
    </el-card>
  </div>
</template>
