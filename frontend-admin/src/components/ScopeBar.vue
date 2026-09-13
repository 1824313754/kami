<script setup>
import { computed, reactive, watch } from 'vue'
import { useSessionStore } from '../stores/session'

const props = defineProps({
  modelValue: {
    type: Object,
    required: true,
  },
  inline: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['update:modelValue', 'change'])

const sessionStore = useSessionStore()

const form = reactive({
  business_type: 'free',
})

watch(
  () => props.modelValue,
  (value) => {
    form.business_type = value?.business_type || 'free'
  },
  { immediate: true, deep: true },
)

const businessTypes = computed(() => sessionStore.session?.business_type_options || [])
const businessTypeOptions = computed(() =>
  businessTypes.value.map((item) => ({
    label: item.label || item.key,
    value: item.key,
  })),
)
const fallbackBusinessType = computed(() => businessTypeOptions.value[0]?.value || 'free')

function emitChange() {
  const nextValue = {
    owner_id: props.modelValue?.owner_id ?? null,
    business_type: form.business_type,
  }
  emit('update:modelValue', nextValue)
  emit('change', nextValue)
}

watch(
  businessTypeOptions,
  () => {
    if (!businessTypeOptions.value.length) return
    if (!businessTypeOptions.value.some((item) => item.value === form.business_type)) {
      form.business_type = fallbackBusinessType.value
      emitChange()
    }
  },
  { immediate: true },
)
</script>

<template>
  <div :class="['scope-bar', { 'scope-bar-inline': inline }]">
    <div class="scope-row scope-row-types">
      <el-segmented
        v-model="form.business_type"
        :options="businessTypeOptions"
        @change="emitChange"
      />
    </div>
  </div>
</template>
