<script setup>
import { onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()

onMounted(() => {
  const jobId = String(route.query.job_id || '').trim()
  if (jobId) {
    router.replace({ name: 'query', query: { job_id: jobId, token: route.query.token } })
    return
  }
  router.replace({ name: 'query' })
})
</script>

<template>
  <div />
</template>
