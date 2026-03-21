<template>
  <div>
    <el-card>
      <template #header>
        <div class="card-header">
          <span>安全告警</span>
          <div>
            <el-button @click="exportEvents">导出事件</el-button>
            <el-button @click="exportAlerts">导出告警</el-button>
            <el-button type="primary" @click="fetchData">刷新</el-button>
          </div>
        </div>
      </template>
      <el-table :data="tableData" style="width: 100%" v-loading="loading">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="timestamp" label="时间" width="180" />
        <el-table-column prop="agent_id" label="主机ID" width="180" />
        <el-table-column prop="type" label="类型" />
        <el-table-column prop="message" label="消息" />
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="scope">
            <el-tag :type="getSeverityType(scope.row.severity)">{{ scope.row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getAlerts } from '../api'

const tableData = ref([])
const loading = ref(false)

const fetchData = async () => {
  loading.value = true
  try {
    const res: any = await getAlerts()
    if (res.code === 0) {
      tableData.value = res.data
    }
  } catch (error) {
    console.error(error)
  } finally {
    loading.value = false
  }
}

const getSeverityType = (severity: string) => {
  if (severity === 'CRITICAL') return 'danger'
  if (severity === 'HIGH') return 'danger'
  if (severity === 'WARN') return 'warning'
  return 'info'
}

const exportEvents = () => {
  window.open('/api/export/events', '_blank')
}

const exportAlerts = () => {
  window.open('/api/export/alerts', '_blank')
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: #fff;
}
:deep(.el-card) {
  background-color: #1d1e1f;
  border: 1px solid #303133;
  color: #fff;
}
:deep(.el-card__header) {
  border-bottom: 1px solid #303133;
}
:deep(.el-table) {
  background-color: transparent !important;
  color: #fff;
  --el-table-tr-bg-color: transparent;
  --el-table-header-bg-color: #2b2d30;
  --el-table-border-color: #303133;
  --el-table-row-hover-bg-color: #2b2d30;
}
:deep(.el-table th), :deep(.el-table tr) {
  background-color: transparent !important;
}
:deep(.el-table td.el-table__cell), :deep(.el-table th.el-table__cell.is-leaf) {
  border-bottom: 1px solid #303133;
}
</style>
