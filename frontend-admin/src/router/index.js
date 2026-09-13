import { createRouter, createWebHistory } from 'vue-router'
import { useSessionStore } from '../stores/session'

const routes = [
  {
    path: '/query',
    name: 'query',
    component: () => import('../views/QueryView.vue'),
    meta: { public: true, title: '卡密提取' },
  },
  {
    path: '/query/progress/:jobId',
    name: 'query-progress',
    component: () => import('../views/QueryProgressView.vue'),
    meta: { public: true, title: '提取进度' },
  },
  {
    path: '/query/result',
    name: 'query-result',
    component: () => import('../views/QueryResultView.vue'),
    meta: { public: true, title: '提取结果' },
  },
  {
    path: '/admin/login',
    name: 'login',
    component: () => import('../views/LoginView.vue'),
    meta: { public: true },
  },
  {
    path: '/admin/password',
    name: 'password',
    component: () => import('../views/PasswordView.vue'),
    meta: { requiresAuth: true, title: '修改密码' },
  },
  {
    path: '/admin',
    component: () => import('../layouts/AdminLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        redirect: { name: 'dashboard' },
      },
      {
        path: 'dashboard',
        name: 'dashboard',
        component: () => import('../views/DashboardView.vue'),
        meta: { title: '今日总览' },
      },
      {
        path: 'files',
        name: 'files',
        component: () => import('../views/FilesView.vue'),
        meta: { title: '文件池' },
      },
      {
        path: 'files/:fileId',
        name: 'file-detail',
        component: () => import('../views/FileDetailView.vue'),
        meta: { title: '文件详情' },
      },
      {
        path: 'cdkeys',
        name: 'cdkeys',
        component: () => import('../views/CdkeysView.vue'),
        meta: { title: '卡密' },
      },
      {
        path: 'tasks',
        name: 'tasks',
        component: () => import('../views/TasksView.vue'),
        meta: { title: '任务进度' },
      },
      {
        path: 'cdkeys/:cdkeyId',
        name: 'cdkey-detail',
        component: () => import('../views/CdkeyDetailView.vue'),
        meta: { title: '卡密详情' },
      },
      {
        path: 'audit',
        name: 'audit',
        component: () => import('../views/AuditView.vue'),
        meta: { title: '审计日志', adminOnly: true },
      },
      {
        path: 'users',
        name: 'users',
        component: () => import('../views/UsersView.vue'),
        meta: { title: '用户管理', adminOnly: true },
      },
      {
        path: 'settings',
        name: 'settings',
        component: () => import('../views/SettingsView.vue'),
        meta: { title: '系统设置', adminOnly: true },
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const sessionStore = useSessionStore()

  if (!sessionStore.initialized) {
    await sessionStore.bootstrap()
  }

  if (to.meta.public) {
    if (to.name === 'login' && sessionStore.isAuthenticated) {
      if (sessionStore.session?.must_change_password) {
        return { name: 'password' }
      }
      return { name: 'dashboard' }
    }
    return true
  }

  if (to.meta.requiresAuth && !sessionStore.isAuthenticated) {
    return { name: 'login' }
  }

  if (sessionStore.session?.must_change_password && to.name !== 'password') {
    return { name: 'password' }
  }

  if (!sessionStore.session?.must_change_password && to.name === 'password') {
    return { name: 'dashboard' }
  }

  if (to.meta.adminOnly && !sessionStore.session?.user?.is_admin) {
    return { name: 'dashboard' }
  }

  return true
})

export default router
