import axios from 'axios'
import { ElMessage } from 'element-plus'

const api = axios.create({
  baseURL: '/api',
  timeout: 5000
})

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = token
  }
  return config
})

api.interceptors.response.use(response => {
  const res = response.data
  // Handle backend custom code structure if needed
  // Assuming backend returns { code: 0, data: ... } or { code: 401, msg: ... }
  if (res.code !== 0 && res.code !== 200) { // Check code
      // If code is defined and not 0 (success), treat as error
      if (res.code === 401) {
          localStorage.removeItem('token')
          window.location.href = '/login'
      }
      ElMessage.error(res.msg || 'Error')
      return Promise.reject(new Error(res.msg || 'Error'))
  }
  return res
}, error => {
  ElMessage.error(error.message || 'Request failed')
  return Promise.reject(error)
})

export const login = (data: any) => api.post('/login', data)
export const getAgents = () => api.get('/agents')
export const getAgent = (id: string) => api.get(`/agent/${id}`)
export const getAlerts = () => api.get('/alerts')
export const getDashboardStats = () => api.get('/dashboard/stats')

// Asset APIs
export const getAssetPorts = (agentId: string) => api.get('/assets/ports', { params: { agent_id: agentId } })
export const getAssetUsers = (agentId: string) => api.get('/assets/users', { params: { agent_id: agentId } })
export const getAssetChanges = (agentId: string) => api.get('/assets/changes', { params: { agent_id: agentId } })

// Timeline APIs
export const getProcessEvents = (agentId: string) => api.get('/events/process', { params: { agent_id: agentId } })
export const getNetworkEvents = (agentId: string) => api.get('/events/network', { params: { agent_id: agentId } })
export const getFileEvents = (agentId: string) => api.get('/events/file', { params: { agent_id: agentId } })

// Config APIs
export const getThreatBookConfig = () => api.get('/config/threatbook')
export const setThreatBookConfig = (enabled: boolean) => api.post('/config/threatbook', { enabled })

export default api
