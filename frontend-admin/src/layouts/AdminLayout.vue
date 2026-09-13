<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { CopyDocument, DataAnalysis, Document, Files, Key, Setting, User } from '@element-plus/icons-vue'
import { useSessionStore } from '../stores/session'
import ScopeBar from '../components/ScopeBar.vue'

const route = useRoute()
const router = useRouter()
const sessionStore = useSessionStore()
let jobTimer = null

const currentUser = computed(() => sessionStore.session?.user)

const scope = reactive({
  owner_id: currentUser.value?.id ?? null,
  business_type: sessionStore.session?.pool?.business_type || 'free',
})

const menuItems = computed(() => {
  const items = [
    { name: 'dashboard', label: '今日总览', icon: Document },
    { name: 'files', label: '文件池', icon: Files },
    { name: 'cdkeys', label: '卡密', icon: Key },
  ]
  items.push({ name: 'tasks', label: '任务进度', icon: CopyDocument })
  if (sessionStore.session?.user?.is_admin) {
    items.push({ name: 'audit', label: '审计日志', icon: DataAnalysis })
    items.push({ name: 'users', label: '用户管理', icon: User })
    items.push({ name: 'settings', label: '系统设置', icon: Setting })
  }
  return items
})

const pageTitle = computed(() => route.meta.title || '后台')
const activeJobs = computed(() => (sessionStore.jobs || []).filter((item) => !['done', 'error'].includes(item.status)))
const enabledBusinessTypeKeys = computed(() => (sessionStore.session?.business_type_options || []).map((item) => item.key))
const fallbackBusinessType = computed(() => enabledBusinessTypeKeys.value[0] || 'free')

function syncScopeFromSession() {
  scope.owner_id = currentUser.value?.id ?? null
  const sessionBusinessType = sessionStore.session?.pool?.business_type || fallbackBusinessType.value
  scope.business_type = enabledBusinessTypeKeys.value.includes(sessionBusinessType) ? sessionBusinessType : fallbackBusinessType.value
}

function applyScopeChange(nextScope) {
  scope.owner_id = currentUser.value?.id ?? null
  const nextBusinessType = nextScope?.business_type || fallbackBusinessType.value
  scope.business_type = enabledBusinessTypeKeys.value.includes(nextBusinessType) ? nextBusinessType : fallbackBusinessType.value
}

function scheduleJobsRefresh() {
  if (jobTimer) {
    clearInterval(jobTimer)
    jobTimer = null
  }
  jobTimer = setInterval(() => {
    if (sessionStore.isAuthenticated) {
      sessionStore.refreshJobs().catch(() => {})
    }
  }, 1500)
}

async function handleLogout() {
  await sessionStore.signOut()
  router.push({ name: 'login' })
}

watch(
  () => [sessionStore.session?.pool, enabledBusinessTypeKeys.value.join('|')],
  () => {
    syncScopeFromSession()
  },
  { deep: true, immediate: true },
)

watch(
  () => [scope.owner_id, scope.business_type],
  () => {
    sessionStore.patchPool({
      ...sessionStore.session?.pool,
      owner_id: scope.owner_id,
      business_type: scope.business_type,
      group_tag: 'default',
      owner_label: currentUser.value?.username || '-',
      scope: {
        owner_id: scope.owner_id,
        business_type: scope.business_type,
        group_tag: 'default',
      },
    })
    sessionStore.refreshJobs().catch(() => {})
  },
  { deep: true, immediate: true },
)

onMounted(() => {
  sessionStore.refreshJobs().catch(() => {})
  scheduleJobsRefresh()
})

onBeforeUnmount(() => {
  if (jobTimer) {
    clearInterval(jobTimer)
    jobTimer = null
  }
})
</script>

<template>
  <div class="admin-shell">
    <aside class="admin-sidebar">
      <div class="brand-block">
        <div class="brand-mark">PF</div>
        <div>
          <div class="brand-title">Pyfaka Admin</div>
          <div class="brand-subtitle">Vue + Element Plus</div>
        </div>
      </div>
      <el-menu
        :default-active="route.name"
        class="sidebar-menu"
        @select="(name) => router.push({ name })"
      >
        <el-menu-item
          v-for="item in menuItems"
          :key="item.name"
          :index="item.name"
        >
          <el-icon><component :is="item.icon" /></el-icon>
          <span>{{ item.label }}</span>
        </el-menu-item>
      </el-menu>
    </aside>

    <main class="admin-main">
      <header class="admin-topbar">
        <div>
          <div class="topbar-kicker">后台工作台</div>
          <h1>{{ pageTitle }}</h1>
        </div>
        <div class="topbar-actions">
          <ScopeBar :model-value="scope" inline @change="applyScopeChange" />
          <el-badge :value="activeJobs.length" :hidden="!activeJobs.length" class="topbar-task-badge">
            <el-button plain @click="router.push({ name: 'tasks' })">任务进度</el-button>
          </el-badge>
          <el-dropdown trigger="click">
            <div class="user-chip">
              <span>{{ currentUser?.username }}</span>
              <small>{{ currentUser?.is_admin ? '管理员' : '子账号' }}</small>
            </div>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="router.push({ name: 'settings' })" v-if="currentUser?.is_admin">系统设置</el-dropdown-item>
                <el-dropdown-item divided @click="handleLogout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <section class="admin-content">
        <router-view />
      </section>
    </main>
  </div>
</template>
