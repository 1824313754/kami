import { ElMessage } from 'element-plus'

export function extractErrorMessage(error) {
  return (
    error?.response?.data?.error ||
    error?.message ||
    '请求失败，请稍后重试'
  )
}

export function showRequestError(error) {
  ElMessage.error(extractErrorMessage(error))
}
