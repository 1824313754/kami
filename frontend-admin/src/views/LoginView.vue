<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

const router = useRouter()
const sessionStore = useSessionStore()

const loading = ref(false)
const form = reactive({
  username: '',
  password: '',
})
const rememberUsername = ref(false)
const rememberPassword = ref(false)
const rememberKey = 'pyfaka_admin_login_remember'

function loadRememberedLogin() {
  try {
    const saved = JSON.parse(localStorage.getItem(rememberKey) || '{}')
    form.username = saved.username || ''
    form.password = saved.rememberPassword ? saved.password || '' : ''
    rememberUsername.value = Boolean(saved.rememberUsername || saved.rememberPassword)
    rememberPassword.value = Boolean(saved.rememberPassword)
  } catch {
    localStorage.removeItem(rememberKey)
  }
}

function saveRememberedLogin() {
  if (!rememberUsername.value && !rememberPassword.value) {
    localStorage.removeItem(rememberKey)
    return
  }
  localStorage.setItem(rememberKey, JSON.stringify({
    rememberUsername: rememberUsername.value || rememberPassword.value,
    rememberPassword: rememberPassword.value,
    username: form.username,
    password: rememberPassword.value ? form.password : '',
  }))
}

async function handleSubmit() {
  loading.value = true
  try {
    await sessionStore.signIn(form)
    saveRememberedLogin()
    ElMessage.success('登录成功')
    if (sessionStore.session?.must_change_password) {
      router.push({ name: 'password' })
      return
    }
    router.push({ name: 'dashboard' })
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

onMounted(loadRememberedLogin)
</script>

<template>
  <div class="auth-shell">
    <div class="auth-panel">
      <div class="auth-copy">
        <div class="topbar-kicker">重做后台</div>
        <h1>更干净的后台工作台</h1>
        <p>保留现有业务规则，用 Vue + Element Plus 重建管理体验。</p>
      </div>
      <el-card shadow="never" class="auth-card">
        <el-form label-position="top" @submit.prevent="handleSubmit">
          <el-form-item label="用户名">
            <el-input v-model="form.username" placeholder="请输入用户名" />
          </el-form-item>
          <el-form-item label="密码">
            <el-input v-model="form.password" type="password" show-password placeholder="请输入密码" />
          </el-form-item>
          <div class="login-options">
            <el-checkbox v-model="rememberUsername">记住用户名</el-checkbox>
            <el-checkbox v-model="rememberPassword">记住密码</el-checkbox>
          </div>
          <div v-if="rememberPassword" class="login-safety-note">
            密码会保存在当前浏览器本地，仅建议在自用设备开启。
          </div>
          <el-button type="primary" :loading="loading" class="full-width" @click="handleSubmit">
            登录后台
          </el-button>
        </el-form>
      </el-card>
    </div>
  </div>
</template>
