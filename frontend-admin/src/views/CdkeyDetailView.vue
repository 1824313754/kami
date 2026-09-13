<script setup>
import { onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { fetchCdkeyDetail } from '../api/admin'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

const route = useRoute()
const router = useRouter()
const sessionStore = useSessionStore()
const loading = ref(false)
const cdkey = ref(null)

const scope = reactive({
  owner_id: route.query.owner_id ? Number(route.query.owner_id) : sessionStore.session?.pool?.owner_id ?? null,
  business_type: route.query.business_type || sessionStore.session?.pool?.business_type || 'free',
  group_tag: route.query.group_tag || sessionStore.session?.pool?.group_tag || 'default',
})

async function loadData() {
  loading.value = true
  try {
    const data = await fetchCdkeyDetail(route.params.cdkeyId, scope)
    cdkey.value = data.cdkey
    sessionStore.patchPool(data.pool)
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function goBack() {
  router.push({
    name: 'cdkeys',
    query: {
      ...(scope.owner_id !== null ? { owner_id: String(scope.owner_id) } : {}),
      business_type: scope.business_type,
      group_tag: scope.group_tag,
    },
  })
}

function openFile(row) {
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

watch(() => route.params.cdkeyId, loadData)
onMounted(loadData)
</script>

<template>
  <div class="page-stack" v-loading="loading">
    <el-card shadow="never" class="page-card page-card-tight">
      <div class="detail-topbar">
        <div>
          <div class="detail-kicker">卡密详情</div>
          <h2 class="detail-title">{{ cdkey?.code || `卡密 #${route.params.cdkeyId}` }}</h2>
        </div>
        <div class="action-strip">
          <el-button @click="goBack">返回列表</el-button>
          <el-button
            v-if="cdkey?.download_url"
            type="primary"
            :href="cdkey.download_url"
            tag="a"
          >
            下载已绑定文件
          </el-button>
        </div>
      </div>
    </el-card>

    <div class="detail-grid">
      <el-card shadow="never" class="page-card detail-card">
        <div class="card-heading">
          <div>
            <h2>卡密信息</h2>
            <p>聚合提取状态、批次信息和下载入口。</p>
          </div>
        </div>
        <div class="detail-list" v-if="cdkey">
          <div class="detail-row"><span>卡密</span><strong>{{ cdkey.code }}</strong></div>
          <div class="detail-row"><span>状态</span><strong>{{ cdkey.extract_status_text }}</strong></div>
          <div class="detail-row"><span>提取编号</span><strong>{{ cdkey.extraction_no || '-' }}</strong></div>
          <div class="detail-row"><span>文件数</span><strong>{{ cdkey.files_per_key }}</strong></div>
          <div class="detail-row"><span>创建时间</span><strong>{{ cdkey.created_at }}</strong></div>
          <div class="detail-row"><span>提取时间</span><strong>{{ cdkey.extracted_at }}</strong></div>
          <div class="detail-row"><span>首次提取 IP</span><strong>{{ cdkey.first_extract_ip || '-' }}</strong></div>
          <div class="detail-row"><span>绑定文件数</span><strong>{{ cdkey.bound_files_count || 0 }}</strong></div>
        </div>
      </el-card>

      <el-card shadow="never" class="page-card detail-card">
        <div class="card-heading">
          <div>
            <h2>批次信息</h2>
            <p>保留最有用的批次上下文，方便回溯发放来源。</p>
          </div>
        </div>
        <div class="detail-list" v-if="cdkey?.batch">
          <div class="detail-row"><span>批次号</span><strong>{{ cdkey.batch.batch_no }}</strong></div>
          <div class="detail-row"><span>所属用户</span><strong>{{ cdkey.batch.owner_username || '-' }}</strong></div>
          <div class="detail-row"><span>生成前缀</span><strong>{{ cdkey.batch.prefix || '-' }}</strong></div>
          <div class="detail-row"><span>批次总量</span><strong>{{ cdkey.batch.total_count }}</strong></div>
          <div class="detail-row"><span>每张文件数</span><strong>{{ cdkey.batch.files_per_key }}</strong></div>
          <div class="detail-row"><span>创建时间</span><strong>{{ cdkey.batch.created_at }}</strong></div>
          <div class="detail-row"><span>备注</span><strong>{{ cdkey.batch.remark || '-' }}</strong></div>
        </div>
        <el-empty v-else description="未找到批次信息" />
      </el-card>
    </div>

    <el-card shadow="never" class="page-card detail-card">
      <div class="card-heading">
        <div>
          <h2>绑定文件</h2>
          <p>按提取结果展示当前卡密已关联的文件。</p>
        </div>
      </div>
      <el-table :data="cdkey?.files || []" class="main-table">
        <el-table-column prop="email_name" label="文件邮箱" min-width="220" />
        <el-table-column prop="original_filename" label="原始文件名" min-width="220" />
        <el-table-column prop="status_text" label="状态" width="120" />
        <el-table-column prop="live_status_text" label="测活" width="100" />
        <el-table-column prop="live_quota" label="额度" width="140" />
        <el-table-column prop="extraction_no" label="提取编号" width="190" />
        <el-table-column prop="upload_time" label="上传时间" width="170" />
        <el-table-column label="操作" width="90" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openFile(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>
