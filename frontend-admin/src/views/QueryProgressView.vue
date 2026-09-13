<script setup>
import { onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()
onMounted(() => {
  router.replace({ name: 'query', query: { job_id: route.params.jobId, token: route.query.token } })
})
</script>

<template>
  <div />
</template>
