<script setup>
import { reactive, ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { createUser, deleteUser, fetchUsers, toggleUser, updateUserPassword, updateUsername } from '../api/admin'
import { showRequestError } from '../utils/message'

const loading = ref(false)
const users = ref([])
const createForm = reactive({
  username: '',
  password: '',
  cdkey_prefix: '',
})

async function loadData() {
  loading.value = true
  try {
    const data = await fetchUsers()
    users.value = data.items
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

async function submitCreate() {
  try {
    const data = await createUser(createForm)
    ElMessage.success(data.message || '创建成功')
    createForm.username = ''
    createForm.password = ''
    createForm.cdkey_prefix = ''
    await loadData()
  } catch (error) {
    showRequestError(error)
  }
}

async function handleToggle(row) {
  try {
    const data = await toggleUser(row.id)
    ElMessage.success(data.message || '状态已更新')
    await loadData()
  } catch (error) {
    showRequestError(error)
  }
}

async function handleResetPassword(row) {
  const { value } = await ElMessageBox.prompt(`为 ${row.username} 设置新密码`, '重置密码', {
    confirmButtonText: '保存',
    cancelButtonText: '取消',
    inputType: 'password',
    inputPlaceholder: '至少 10 位，包含字母和数字',
  })
  try {
    const data = await updateUserPassword(row.id, { password: value })
    ElMessage.success(data.message || '密码已更新')
    await loadData()
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  }
}

async function handleRename(row) {
  const { value } = await ElMessageBox.prompt(`修改 ${row.username} 的用户名`, '修改用户名', {
    confirmButtonText: '保存',
    cancelButtonText: '取消',
    inputValue: row.username,
  })
  try {
    const data = await updateUsername(row.id, { username: value })
    ElMessage.success(data.message || '用户名已更新')
    await loadData()
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  }
}

async function handleDelete(row) {
  await ElMessageBox.confirm(`确认删除用户 ${row.username}？仅支持删除空账号。`, '删除用户', { type: 'warning' })
  try {
    const data = await deleteUser(row.id)
    ElMessage.success(data.message || '删除成功')
    await loadData()
  } catch (error) {
    if (error !== 'cancel') showRequestError(error)
  }
}

onMounted(loadData)
</script>

<template>
  <div class="page-stack">
    <div class="split-grid split-grid-narrow">
      <el-card shadow="never" class="page-card side-card">
        <div class="card-heading">
          <div>
            <h2>新建用户</h2>
            <p>密码至少 10 位，并包含字母和数字。</p>
          </div>
        </div>
        <el-form label-position="top">
          <el-form-item label="用户名">
            <el-input v-model="createForm.username" />
          </el-form-item>
          <el-form-item label="登录密码">
            <el-input v-model="createForm.password" type="password" show-password placeholder="至少 10 位，包含字母和数字" />
          </el-form-item>
          <el-form-item label="卡密前缀">
            <el-input v-model="createForm.cdkey_prefix" />
          </el-form-item>
          <el-button type="primary" class="full-width" @click="submitCreate">创建用户</el-button>
        </el-form>
      </el-card>

      <el-card shadow="never" class="page-card list-card">
        <div class="card-heading">
          <div>
            <h2>用户列表</h2>
            <p>支持启停、改名、重置密码和删除空账号。</p>
          </div>
        </div>

        <el-table v-loading="loading" :data="users" class="main-table">
          <el-table-column prop="username" label="用户名" min-width="140" />
          <el-table-column prop="cdkey_prefix" label="前缀" width="100" />
          <el-table-column prop="is_admin" label="角色" width="90">
            <template #default="{ row }">
              {{ row.is_admin ? '管理员' : '子账号' }}
            </template>
          </el-table-column>
          <el-table-column prop="enabled" label="状态" width="90">
            <template #default="{ row }">
              {{ row.enabled ? '启用' : '停用' }}
            </template>
          </el-table-column>
          <el-table-column prop="last_login_at" label="最近登录" width="170" />
          <el-table-column label="操作" min-width="280">
            <template #default="{ row }">
              <div class="row-action-group">
                <el-button link @click="handleRename(row)">改名</el-button>
                <el-button link @click="handleResetPassword(row)">改密</el-button>
                <el-button link @click="handleToggle(row)">{{ row.enabled ? '停用' : '启用' }}</el-button>
                <el-button link type="danger" @click="handleDelete(row)">删除</el-button>
              </div>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>
  </div>
</template>
