<script setup>
import { onMounted, reactive, ref } from 'vue'
import { fetchAudit } from '../api/admin'
import { showRequestError } from '../utils/message'

const loading = ref(false)

const filters = reactive({
  user_id: '',
  action: '',
  target_type: '',
  date: '',
  page: 1,
  per_page: 20,
})

const dataState = ref({
  items: [],
  pagination: { page: 1, pages: 1, total: 0, per_page: 20 },
  options: { actions: [], target_types: [] },
})

async function loadData() {
  loading.value = true
  try {
    const data = await fetchAudit({
      user_id: filters.user_id || undefined,
      action: filters.action || undefined,
      target_type: filters.target_type || undefined,
      date: filters.date || undefined,
      page: filters.page,
      per_page: filters.per_page,
    })
    dataState.value = data
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.user_id = ''
  filters.action = ''
  filters.target_type = ''
  filters.date = ''
  filters.page = 1
  loadData()
}

onMounted(loadData)
</script>

<template>
  <div class="page-stack">
    <el-card shadow="never" class="page-card page-card-tight">
      <div class="filter-line">
        <el-input v-model="filters.user_id" placeholder="用户 ID" clearable />
        <el-select v-model="filters.action" placeholder="动作" clearable>
          <el-option
            v-for="item in dataState.options.actions"
            :key="item"
            :label="item"
            :value="item"
          />
        </el-select>
        <el-select v-model="filters.target_type" placeholder="目标类型" clearable>
          <el-option
            v-for="item in dataState.options.target_types"
            :key="item"
            :label="item"
            :value="item"
          />
        </el-select>
        <el-date-picker v-model="filters.date" type="date" value-format="YYYY-MM-DD" placeholder="日期" />
        <el-button type="primary" @click="filters.page = 1; loadData()">查询</el-button>
        <el-button @click="resetFilters">清空</el-button>
      </div>
    </el-card>

    <el-card shadow="never" class="page-card list-card">
      <div class="card-heading">
        <div>
          <h2>审计日志</h2>
          <p>统一查看关键管理动作，便于追溯用户、目标和操作时间。</p>
        </div>
      </div>

      <el-table v-loading="loading" :data="dataState.items" class="main-table">
        <el-table-column prop="created_at" label="时间" width="170" />
        <el-table-column prop="username" label="操作人" width="120" />
        <el-table-column prop="action" label="动作" min-width="180" />
        <el-table-column prop="target_type" label="目标类型" width="120" />
        <el-table-column prop="target_text" label="目标" min-width="220" />
        <el-table-column prop="detail" label="详情" min-width="320" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="140" />
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
</template>
