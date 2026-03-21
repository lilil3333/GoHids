<template>
  <div class="home-container">
    <!-- Top Stats Cards -->
    <el-row :gutter="20" class="mb-4">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon bg-blue">
              <el-icon><Monitor /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-title">在线主机</div>
              <div class="stat-value text-blue">{{ stats.online_agents || 0 }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon bg-gray">
              <el-icon><SwitchButton /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-title">离线主机</div>
              <div class="stat-value text-gray">{{ stats.offline_agents || 0 }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon bg-red">
              <el-icon><Warning /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-title">总告警数</div>
              <div class="stat-value text-red">{{ stats.total_alerts || 0 }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon bg-purple">
              <el-icon><Aim /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-title">威胁情报检测 (ThreatBook)</div>
              <div style="margin-top: 5px;">
                 <el-switch v-model="tbEnabled" @change="toggleTB" :loading="tbLoading" inline-prompt active-text="ON" inactive-text="OFF" />
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Asset Inventory Charts -->
    <el-row :gutter="20" class="mb-4">
      <el-col :span="12">
         <el-card shadow="hover" class="chart-card">
          <template #header>
            <div class="card-header">
              <span>全网资产分布 (OS Distribution)</span>
            </div>
          </template>
          <div id="osChart" style="height: 300px;"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover" class="chart-card">
          <template #header>
            <div class="card-header">
              <span>Top 5 软件/服务 (Software Stats)</span>
            </div>
          </template>
          <div id="softwareChart" style="height: 300px;"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Main Charts Area -->
    <el-row :gutter="20" class="mb-4">
      <el-col :span="16">
        <el-card shadow="hover" class="chart-card">
          <template #header>
            <div class="card-header">
              <span>告警趋势分析 (Alert Trend)</span>
            </div>
          </template>
          <div id="trendChart" style="height: 350px;"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="hover" class="chart-card">
          <template #header>
            <div class="card-header">
              <span>Top 5 活跃进程 (Active Processes)</span>
            </div>
          </template>
          <div id="processChart" style="height: 350px;"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Bottom Lists -->
    <el-row :gutter="20">
      <el-col :span="24">
        <el-card shadow="hover" class="list-card">
          <template #header>
            <div class="card-header">
              <span>最新告警 (Recent Alerts)</span>
              <el-button link type="primary" @click="$router.push('/alerts')">查看全部</el-button>
            </div>
          </template>
          <el-table :data="stats.recent_alerts || []" style="width: 100%" size="small">
            <el-table-column width="50">
               <template #default="scope">
                 <el-icon v-if="scope.row.severity === 'CRITICAL' || scope.row.severity === 'HIGH'" color="#F56C6C"><WarningFilled /></el-icon>
                 <el-icon v-else color="#E6A23C"><InfoFilled /></el-icon>
               </template>
            </el-table-column>
            <el-table-column prop="message" label="消息" show-overflow-tooltip />
            <el-table-column prop="type" label="类型" width="180" />
            <el-table-column prop="agent_id" label="主机ID" width="150" show-overflow-tooltip />
            <el-table-column prop="timestamp" label="时间" width="180" align="right">
                <template #default="scope">{{ formatTime(scope.row.timestamp) }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import * as echarts from 'echarts'
import { getDashboardStats, getThreatBookConfig, setThreatBookConfig } from '../api'
import { ElMessage } from 'element-plus'

const stats = ref<any>({})
const tbEnabled = ref(false)
const tbLoading = ref(false)

const formatTime = (ts: string) => {
    return new Date(ts).toLocaleString()
}

const fetchTBConfig = async () => {
    try {
        const res: any = await getThreatBookConfig()
        if (res.code === 0) {
            tbEnabled.value = res.enabled
        }
    } catch (e) {
        console.error(e)
    }
}

const toggleTB = async (val: boolean) => {
    tbLoading.value = true
    try {
        await setThreatBookConfig(val)
        ElMessage.success('配置已更新')
    } catch (e) {
        tbEnabled.value = !val // Revert on error
        ElMessage.error('更新失败')
    } finally {
        tbLoading.value = false
    }
}

const initCharts = () => {
  // 1. OS Distribution (Pie)
  const osChart = echarts.init(document.getElementById('osChart'))
  const osData = Object.entries(stats.value.os_distribution || {}).map(([name, value]) => ({ name, value }))
  
  osChart.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item' },
    legend: { bottom: '0%', textStyle: { color: '#909399' } },
    series: [
      {
        name: 'OS Distribution',
        type: 'pie',
        radius: ['40%', '70%'],
        itemStyle: {
          borderRadius: 10,
          borderColor: '#1d1e1f',
          borderWidth: 2
        },
        label: { show: true, color: '#fff' },
        data: osData.length ? osData : [{name: 'No Data', value: 0}]
      }
    ]
  })

  // 2. Software Stats (Bar)
  const softwareChart = echarts.init(document.getElementById('softwareChart'))
  // Take Top 5 Software
  const softData = Object.entries(stats.value.software_stats || {})
    .sort((a: any, b: any) => b[1] - a[1])
    .slice(0, 5)
    
  softwareChart.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
        type: 'value',
        axisLine: { lineStyle: { color: '#909399' } },
        splitLine: { lineStyle: { color: '#303133' } }
    },
    yAxis: {
        type: 'category',
        data: softData.map(d => d[0]),
        axisLabel: { color: '#909399', width: 100, overflow: 'truncate' },
        axisLine: { lineStyle: { color: '#909399' } }
    },
    series: [
        {
            name: 'Count',
            type: 'bar',
            data: softData.map(d => d[1]),
            itemStyle: { color: '#409EFF' }
        }
    ]
  })

  // 3. Alert Trend (Line)
  const trendChart = echarts.init(document.getElementById('trendChart'))
  const trendData = stats.value.alert_trend || []
  // Sort by date just in case
  trendData.sort((a: any, b: any) => new Date(a.time).getTime() - new Date(b.time).getTime())
  
  trendChart.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: trendData.map((d: any) => d.time),
      axisLine: { lineStyle: { color: '#909399' } }
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#909399' } },
      splitLine: { lineStyle: { color: '#303133' } }
    },
    series: [
      {
        name: 'Alerts',
        type: 'line',
        smooth: true,
        areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: 'rgba(245, 108, 108, 0.5)' },
                { offset: 1, color: 'rgba(245, 108, 108, 0.1)' }
            ])
        },
        itemStyle: { color: '#F56C6C' },
        data: trendData.map((d: any) => d.count)
      }
    ]
  })

  // 4. Top Processes (Bar - Vertical)
  const processChart = echarts.init(document.getElementById('processChart'))
  const procData = (stats.value.top_processes || []).slice(0, 5)

  processChart.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item' },
    legend: { show: false },
    xAxis: {
        type: 'category',
        data: procData.map((d: any) => d.name),
        axisLabel: { color: '#909399', interval: 0, rotate: 30 },
        axisLine: { lineStyle: { color: '#909399' } }
    },
    yAxis: {
        type: 'value',
        axisLine: { lineStyle: { color: '#909399' } },
        splitLine: { lineStyle: { color: '#303133' } }
    },
    series: [
      {
        name: 'Instances',
        type: 'bar',
        data: procData.map((d: any) => d.count),
        itemStyle: { color: '#E6A23C' }
      }
    ]
  })

  window.addEventListener('resize', () => {
    osChart.resize()
    softwareChart.resize()
    trendChart.resize()
    processChart.resize()
  })
}

const fetchData = async () => {
    try {
        const res: any = await getDashboardStats()
        if (res.code === 0) {
            stats.value = res.data
        }
    } catch (e) {
        console.error(e)
    }
}

onMounted(async () => {
  await fetchData()
  await fetchTBConfig()
  initCharts()
})
</script>

<style scoped>
.home-container {
  padding: 20px;
}
.mb-4 {
  margin-bottom: 20px;
}
.stat-card {
  background-color: #1d1e1f;
  border: 1px solid #303133;
  color: #fff;
}
.stat-content {
  display: flex;
  align-items: center;
}
.stat-icon {
  width: 60px;
  height: 60px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 30px;
  color: #fff;
  margin-right: 15px;
}
.bg-blue { background: linear-gradient(135deg, #409EFF, #337ecc); }
.bg-red { background: linear-gradient(135deg, #F56C6C, #c45656); }
.bg-gray { background: linear-gradient(135deg, #909399, #606266); }
.bg-green { background: linear-gradient(135deg, #67C23A, #529b2e); }
.bg-purple { background: linear-gradient(135deg, #9b59b6, #8e44ad); }

.stat-info { flex: 1; }
.stat-title { font-size: 14px; color: #909399; }
.stat-value { font-size: 24px; font-weight: bold; margin-top: 5px; }

.text-blue { color: #409EFF; }
.text-red { color: #F56C6C; }
.text-gray { color: #909399; }
.text-green { color: #67C23A; }

.chart-card, .list-card {
  background-color: #1d1e1f;
  border: 1px solid #303133;
  color: #fff;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: #fff;
  font-weight: bold;
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