import { onBeforeUnmount, ref } from 'vue'
import { fetchJob, fetchQueryJob } from '../api/admin'

export function useJobPoller(kind = 'admin') {
  const job = ref(null)
  const polling = ref(false)
  let timer = null

  function stop() {
    polling.value = false
    if (timer) {
      clearTimeout(timer)
      timer = null
    }
  }

  async function start(jobId, onDone) {
    stop()
    polling.value = true

    const tick = async () => {
      if (!polling.value) return
      try {
        const data = kind === 'query' ? await fetchQueryJob(jobId) : await fetchJob(jobId)
        job.value = data.job
        if (['done', 'error'].includes(data.job?.status)) {
          polling.value = false
          onDone?.(data.job)
          return
        }
      } finally {
        if (polling.value) {
          timer = setTimeout(tick, 1200)
        }
      }
    }

    await tick()
  }

  onBeforeUnmount(stop)

  return {
    job,
    polling,
    start,
    stop,
  }
}
