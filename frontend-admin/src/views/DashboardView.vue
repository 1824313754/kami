<script setup>
import { nextTick, onMounted, reactive, ref, watch } from 'vue'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { init, use, graphic } from 'echarts/core'
import { fetchDashboard } from '../api/admin'
import { useSessionStore } from '../stores/session'
import { showRequestError } from '../utils/message'

use([CanvasRenderer, LineChart, GridComponent, LegendComponent, TooltipComponent])

const sessionStore = useSessionStore()
const loading = ref(false)
const chartRef = ref(null)
let chart = null

const scope = reactive({
  owner_id: sessionStore.session?.pool?.owner_id ?? null,
  business_type: sessionStore.session?.pool?.business_type || 'free',
  group_tag: sessionStore.session?.pool?.group_tag || 'default',
})

const summary = ref(null)

async function loadData() {
  loading.value = true
  try {
    const data = await fetchDashboard(scope)
    summary.value = data.summary
    sessionStore.patchPool(data.pool)
    await nextTick()
    renderChart()
  } catch (error) {
    showRequestError(error)
  } finally {
    loading.value = false
  }
}

function renderChart() {
  if (!chartRef.value || !summary.value) return
  if (!chart) {
    chart = init(chartRef.value)
  }
  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: 24, right: 24, top: 32, bottom: 24, containLabel: true },
    legend: { top: 0, icon: 'roundRect' },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: summary.value.trend_points.map((item) => item.label),
    },
    yAxis: { type: 'value', splitLine: { lineStyle: { color: '#e5e7eb' } } },
    series: [
      {
        name: '上传文件数',
        type: 'line',
        smooth: true,
        symbolSize: 8,
        data: summary.value.trend_points.map((item) => item.uploaded_count),
        lineStyle: { width: 3, color: '#0f766e' },
        itemStyle: { color: '#0f766e' },
        areaStyle: {
          color: new graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(15, 118, 110, 0.24)' },
            { offset: 1, color: 'rgba(15, 118, 110, 0.02)' },
          ]),
        },
      },
      {
        name: '提取文件数',
        type: 'line',
        smooth: true,
        symbolSize: 8,
        data: summary.value.trend_points.map((item) => item.extracted_files_count),
        lineStyle: { width: 3, color: '#ea580c' },
        itemStyle: { color: '#ea580c' },
        areaStyle: {
          color: new graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(234, 88, 12, 0.22)' },
            { offset: 1, color: 'rgba(234, 88, 12, 0.02)' },
          ]),
        },
      },
    ],
  })
}

watch(
  () => [scope.owner_id, scope.business_type, scope.group_tag],
  () => {
    loadData()
  },
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

onMounted(loadData)
</script>

<template>
  <div class="page-stack" v-loading="loading">
    <div class="stats-grid" v-if="summary">
      <el-card shadow="never" class="metric-card">
        <div class="metric-label">今日上传文件</div>
        <div class="metric-value">{{ summary.uploaded_today }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card">
        <div class="metric-label">今日提取卡密</div>
        <div class="metric-value">{{ summary.extracted_today }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card">
        <div class="metric-label">今日提取文件数</div>
        <div class="metric-value">{{ summary.extracted_files_today }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card">
        <div class="metric-label">当前可用文件数</div>
        <div class="metric-value">{{ summary.available_files }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card">
        <div class="metric-label">全历史上传文件</div>
        <div class="metric-value">{{ summary.uploaded_total }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card">
        <div class="metric-label">全历史提取卡密</div>
        <div class="metric-value">{{ summary.extracted_total }}</div>
      </el-card>
      <el-card shadow="never" class="metric-card">
        <div class="metric-label">全历史提取文件数</div>
        <div class="metric-value">{{ summary.extracted_files_total }}</div>
      </el-card>
    </div>

    <el-card shadow="never" class="page-card chart-card">
      <div class="card-heading">
        <div>
          <h2>最近 7 天上传 / 提取趋势</h2>
          <p>按当前用户范围统计，帮助快速判断库存补充和提取节奏。</p>
        </div>
        <div class="chart-hint">{{ summary?.date_label }}</div>
      </div>
      <div ref="chartRef" class="trend-chart"></div>
    </el-card>
  </div>
</template>
