import axios from 'axios'

const apiClient = axios.create({
  baseURL: '/api/admin',
  withCredentials: true,
  timeout: 1200000,
})

apiClient.interceptors.request.use((config) => {
  const token = window.__PYFAKA_CSRF_TOKEN__
  if (token) {
    config.headers['X-CSRF-Token'] = token
  }
  return config
})

export default apiClient
