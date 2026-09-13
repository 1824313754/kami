<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { changeOwnPassword } from '../api/admin'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

const router = useRouter()
const sessionStore = useSessionStore()

const loading = ref(false)
const form = reactive({
  password: '',
  confirm_password: '',
})

async function handleSubmit() {
  loading.value = true
  try {
    const data = await changeOwnPassword(form)
    ElMessage.success(data.message || '密码已更新')
    sessionStore.applySession(null)
    router.push({ name: 'login' })
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="auth-shell">
    <el-card shadow="never" class="auth-card auth-card-narrow">
      <div class="card-heading">
        <h2>首次登录先修改密码</h2>
        <p>新密码至少 10 位，并包含字母和数字，更新后重新登录。</p>
      </div>
      <el-form label-position="top" @submit.prevent="handleSubmit">
        <el-form-item label="新密码">
          <el-input v-model="form.password" type="password" show-password placeholder="至少 10 位，包含字母和数字" />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input v-model="form.confirm_password" type="password" show-password />
        </el-form-item>
        <el-button type="primary" :loading="loading" class="full-width" @click="handleSubmit">
          保存并重新登录
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>
