<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { fetchFileDetail } from '../api/admin'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

const route = useRoute()
const router = useRouter()
const sessionStore = useSessionStore()
const loading = ref(false)
const file = ref(null)

const scope = reactive({
  owner_id: route.query.owner_id ? Number(route.query.owner_id) : sessionStore.session?.pool?.owner_id ?? null,
  business_type: route.query.business_type || sessionStore.session?.pool?.business_type || 'free',
  group_tag: route.query.group_tag || sessionStore.session?.pool?.group_tag || 'default',
})

const summaryRows = computed(() => {
  if (!file.value) return []
  return [
    { label: '文件邮箱', value: file.value.email_name || '-' },
    { label: '原始文件名', value: file.value.original_filename || '-' },
    { label: '文件大小', value: file.value.file_size_text || '-' },
    { label: '状态', value: file.value.status_text || '-' },
    { label: '测活状态', value: file.value.live_status_text || '-' },
    { label: '额度信息', value: file.value.live_quota || '-' },
    { label: '提取编号', value: file.value.extraction_no || '-' },
    { label: '上传时间', value: file.value.upload_time || '-' },
    { label: '最近测活', value: file.value.live_checked_at || '-' },
    { label: '归属用户', value: file.value.owner?.username || '-' },
    { label: '绑定时间', value: file.value.bound_at || '-' },
  ]
})

const payloadRows = computed(() => {
  const payload = file.value?.payload
  if (!payload?.available) return []
  return [
    { label: '账号邮箱', value: payload.email || '-' },
    { label: '账号类型', value: payload.type || '-' },
    { label: '账号 ID', value: payload.account_id || '-' },
    { label: '过期时间', value: payload.expired_at || '-' },
    { label: '最近刷新', value: payload.last_refresh || '-' },
    { label: '含 Access Token', value: payload.has_access_token ? '是' : '否' },
    { label: '含 Refresh Token', value: payload.has_refresh_token ? '是' : '否' },
    { label: '含 ID Token', value: payload.has_id_token ? '是' : '否' },
  ]
})

async function loadData() {
  loading.value = true
  try {
    const data = await fetchFileDetail(route.params.fileId, scope)
    file.value = data.file
    sessionStore.patchPool(data.pool)
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function goBack() {
  router.push({
    name: 'files',
    query: {
      ...(scope.owner_id !== null ? { owner_id: String(scope.owner_id) } : {}),
      business_type: scope.business_type,
      group_tag: scope.group_tag,
    },
  })
}

function openCdkeyDetail() {
  if (!file.value?.bound_cdkey?.id) return
  router.push({
    name: 'cdkey-detail',
    params: { cdkeyId: file.value.bound_cdkey.id },
    query: {
      ...(scope.owner_id !== null ? { owner_id: String(scope.owner_id) } : {}),
      business_type: scope.business_type,
      group_tag: scope.group_tag,
    },
  })
}

watch(() => route.params.fileId, loadData)
onMounted(loadData)
</script>

<template>
  <div class="page-stack" v-loading="loading">
    <el-card shadow="never" class="page-card page-card-tight">
      <div class="detail-topbar">
        <div>
          <div class="detail-kicker">文件详情</div>
          <h2 class="detail-title">{{ file?.email_name || `文件 #${route.params.fileId}` }}</h2>
        </div>
        <div class="action-strip">
          <el-button @click="goBack">返回列表</el-button>
          <el-button
            v-if="file?.bound_cdkey?.id"
            type="primary"
            plain
            @click="openCdkeyDetail"
          >
            查看绑定卡密
          </el-button>
          <el-button
            v-if="file?.download_url"
            type="primary"
            :href="file.download_url"
            tag="a"
          >
            下载文件
          </el-button>
        </div>
      </div>
    </el-card>

    <div class="detail-grid">
      <el-card shadow="never" class="page-card detail-card">
        <div class="card-heading">
          <div>
            <h2>基础信息</h2>
            <p>聚合运营排查最常看的字段，避免来回切列表。</p>
          </div>
        </div>
        <div class="detail-list">
          <div v-for="item in summaryRows" :key="item.label" class="detail-row">
            <span>{{ item.label }}</span>
            <strong>{{ item.value }}</strong>
          </div>
        </div>
      </el-card>

      <el-card shadow="never" class="page-card detail-card">
        <div class="card-heading">
          <div>
            <h2>载荷摘要</h2>
            <p>仅展示是否存在和排查所需摘要，不直接暴露敏感凭据原文。</p>
          </div>
        </div>
        <div v-if="payloadRows.length" class="detail-list">
          <div v-for="item in payloadRows" :key="item.label" class="detail-row">
            <span>{{ item.label }}</span>
            <strong>{{ item.value }}</strong>
          </div>
        </div>
        <el-empty v-else description="当前文件没有可读取的本地载荷摘要" />
      </el-card>
    </div>

    <el-card v-if="file?.bound_cdkey" shadow="never" class="page-card detail-card">
      <div class="card-heading">
        <div>
          <h2>绑定卡密</h2>
          <p>提取链路只保留一跳，点进即可继续查看文件归属。</p>
        </div>
      </div>
      <div class="inline-summary">
        <span>{{ file.bound_cdkey.code }}</span>
        <span>{{ file.bound_cdkey.extract_status_text }}</span>
        <span>{{ file.bound_cdkey.extraction_no || '无提取编号' }}</span>
        <span>{{ file.bound_cdkey.batch_no || '无批次号' }}</span>
      </div>
    </el-card>
  </div>
</template>
