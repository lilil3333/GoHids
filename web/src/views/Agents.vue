<template>
  <div class="agents-container">
    <el-card shadow="hover" class="mb-4">
      <template #header>
        <div class="card-header">
          <span>主机列表</span>
          <el-button type="primary" size="small" @click="fetchAgents">刷新</el-button>
        </div>
      </template>
      <el-table :data="agents" style="width: 100%">
        <el-table-column prop="hostname" label="主机名" />
        <el-table-column prop="intranet_ipv4" label="IP地址">
             <template #default="scope">
                {{ scope.row.intranet_ipv4 ? scope.row.intranet_ipv4.join(', ') : '' }}
             </template>
        </el-table-column>
        <el-table-column prop="product" label="系统/产品" />
        <el-table-column prop="version" label="Agent版本" />
        <el-table-column prop="last_seen" label="最后心跳">
             <template #default="scope">
                {{ new Date(scope.row.last_seen).toLocaleString() }}
             </template>
        </el-table-column>
        <el-table-column label="状态">
             <template #default="scope">
                <el-tag :type="isOnline(scope.row.last_seen) ? 'success' : 'danger'">
                    {{ isOnline(scope.row.last_seen) ? 'Online' : 'Offline' }}
                </el-tag>
             </template>
        </el-table-column>
        <el-table-column label="操作">
            <template #default="scope">
                <el-button link type="primary" size="small" @click="viewDetails(scope.row)">主机详情</el-button>
            </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Full Detail Dialog -->
    <el-dialog v-model="dialogVisible" title="主机全景视图" width="90%" top="5vh">
        <template #header>
            <div class="dialog-header">
                <span class="text-lg font-bold">主机详情: {{ currentAgent?.hostname }} ({{ currentAgent?.intranet_ipv4?.join(', ') }})</span>
                <el-tag size="small" class="ml-2">{{ currentAgent?.product }}</el-tag>
            </div>
        </template>
        
        <el-tabs v-model="activeTab">
            <!-- 1. 概览与变更 -->
            <el-tab-pane label="概览 & 变更 (Overview)" name="overview">
                <el-row :gutter="20">
                    <el-col :span="16">
                        <div class="section-title">变更历史 (Change Log)</div>
                        <el-timeline>
                            <el-timeline-item
                              v-for="(activity, index) in assetChanges"
                              :key="index"
                              :type="activity.action === 'ADD' ? 'danger' : 'info'"
                              :timestamp="new Date(activity.timestamp).toLocaleString()">
                              {{ activity.action === 'ADD' ? '新增' : '删除' }} {{ activity.asset_type }}: {{ activity.detail }}
                            </el-timeline-item>
                            <el-timeline-item v-if="assetChanges.length === 0" timestamp="近期无变更" placement="top">
                                <el-empty description="暂无资产变更记录" :image-size="60"></el-empty>
                            </el-timeline-item>
                        </el-timeline>
                    </el-col>
                    <el-col :span="8">
                        <div class="section-title">基础信息</div>
                        <el-descriptions :column="1" border size="small">
                            <el-descriptions-item label="Agent ID">{{ currentAgent?.agent_id }}</el-descriptions-item>
                            <el-descriptions-item label="主机名">{{ currentAgent?.hostname }}</el-descriptions-item>
                            <el-descriptions-item label="操作系统">{{ currentAgent?.product }}</el-descriptions-item>
                            <el-descriptions-item label="内核版本">{{ currentAgentData?.kernel || 'Unknown' }}</el-descriptions-item>
                            <el-descriptions-item label="IP地址">
                                <div v-for="ip in currentAgent?.intranet_ipv4" :key="ip">{{ ip }}</div>
                            </el-descriptions-item>
                            <el-descriptions-item label="Agent版本">{{ currentAgent?.version }}</el-descriptions-item>
                            <el-descriptions-item label="最后在线">{{ new Date(currentAgent?.last_seen).toLocaleString() }}</el-descriptions-item>
                        </el-descriptions>
                    </el-col>
                </el-row>
            </el-tab-pane>

            <!-- 2. 实时进程 (新版 Cyber UI) -->
            <el-tab-pane label="实时进程 (Processes)" name="processes">
                 <ProcessMonitor 
                    v-if="rawProcesses.length > 0"
                    :rawProcesses="rawProcesses"
                    :hostname="currentAgent?.hostname"
                    :osVersion="currentAgent?.product"
                    :ips="currentAgent?.intranet_ipv4"
                    style="height: 700px"
                 />
                 <el-empty v-else description="暂无进程数据" />
            </el-tab-pane>

            <!-- 3. 网络连接 (新版 Cyber UI) -->
            <el-tab-pane label="网络连接 (Connections)" name="network">
                 <Connections 
                    v-if="connections.length > 0"
                    :connections="connections" 
                    style="height: 700px"
                 />
                 <el-empty v-else description="暂无网络连接数据" />
            </el-tab-pane>

            <!-- 4. 开放端口 (新版 Cyber UI) -->
            <el-tab-pane label="开放端口 (Listening)" name="ports">
                <ListeningPorts 
                    v-if="assetPorts.length > 0"
                    :ports="assetPorts" 
                    style="height: 700px"
                />
                <el-empty v-else description="暂无开放端口数据" />
            </el-tab-pane>

            <!-- 5. 系统账号 (新版 Cyber UI) -->
            <el-tab-pane label="系统账号 (Users)" name="users">
                <SystemUsers 
                    v-if="assetUsers.length > 0"
                    :users="assetUsers" 
                    style="height: 700px"
                />
                <el-empty v-else description="暂无用户数据" />
            </el-tab-pane>
            
            <!-- 6. 服务列表 (新版 Cyber UI) -->
            <el-tab-pane label="服务列表 (Services)" name="services">
                <ServiceList 
                    v-if="services.length > 0"
                    :services="services" 
                    style="height: 700px"
                />
                <el-empty v-else description="暂无服务数据" />
            </el-tab-pane>

             <!-- 7. 注册表 (新版 Cyber UI) -->
            <el-tab-pane label="注册表监控 (Registry)" name="registry">
                <RegistryMonitor 
                    :registryData="registryData" 
                    style="height: 700px"
                />
            </el-tab-pane>
        </el-tabs>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getAgents, getAgent, getAssetPorts, getAssetUsers, getAssetChanges } from '../api'
import ProcessMonitor from '../components/ProcessMonitor.vue'
import Connections from '../components/Connections.vue'
import ListeningPorts from '../components/ListeningPorts.vue'
import SystemUsers from '../components/SystemUsers.vue'
import ServiceList from '../components/ServiceList.vue'
import RegistryMonitor from '../components/RegistryMonitor.vue'

const agents = ref([])
const dialogVisible = ref(false)
const activeTab = ref('overview')
const currentAgent = ref<any>(null)
const currentAgentData = ref<any>({}) // Extra data like kernel

// Asset Data
const assetPorts = ref([])
const assetUsers = ref([])
const assetChanges = ref<any[]>([])

// Realtime Data (From AgentInfo)
const processes = ref([]) // Tree structure (Legacy)
const rawProcesses = ref<any[]>([]) // Flat list for ProcessMonitor
const connections = ref([])
const services = ref([])
const registryData = ref({})

const fetchAgents = async () => {
    try {
        const res: any = await getAgents()
        if (res.code === 0) {
            agents.value = res.data
        }
    } catch (e) {}
}

const isOnline = (lastSeen: string) => {
    const diff = new Date().getTime() - new Date(lastSeen).getTime()
    return diff < 5 * 60 * 1000 // 5 minutes
}

const viewDetails = async (row: any) => {
    currentAgent.value = row
    dialogVisible.value = true
    activeTab.value = 'overview'
    
    const agentId = row.agent_id
    
    // 1. Get Detailed Agent Info (Realtime Data)
    try {
        const detailRes: any = await getAgent(agentId)
        if (detailRes.code === 0 && detailRes.data) {
            const data = detailRes.data.data || {}
            currentAgentData.value = data
            
            // Safe parse if data is raw interface{}
            const rawProcs = data.processes || []
            rawProcesses.value = rawProcs // Store flat list for ProcessMonitor
            
            // Build Process Tree (Legacy support if needed)
            processes.value = buildProcessTree(rawProcs)

            connections.value = data.network || []
            services.value = data.services || []
            registryData.value = data.registry || {}
        }
    } catch (e) {
        console.error("Failed to load agent details", e)
    }

    // 2. Load Asset Data (DB Snapshots)
    const pRes: any = await getAssetPorts(agentId)
    if(pRes.code === 0) assetPorts.value = pRes.data
    
    const uRes: any = await getAssetUsers(agentId)
    if(uRes.code === 0) assetUsers.value = uRes.data

    const cRes: any = await getAssetChanges(agentId)
    if(cRes.code === 0) assetChanges.value = cRes.data
}

// Helper to build tree from flat list
const buildProcessTree = (flatList: any[]) => {
    const map = new Map<number, any>()
    const roots: any[] = []

    // 1. Initialize map
    flatList.forEach(p => {
        // Ensure children array exists
        p.children = []
        map.set(p.pid, p)
    })

    // 2. Build tree
    flatList.forEach(p => {
        if (p.ppid && map.has(p.ppid)) {
            const parent = map.get(p.ppid)
            parent.children.push(p)
        } else {
            roots.push(p)
        }
    })

    return roots
}

onMounted(() => {
    fetchAgents()
})
</script>

<style scoped>
.agents-container {
    padding: 20px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.section-title {
    font-size: 16px;
    font-weight: bold;
    margin-bottom: 15px;
    border-left: 4px solid #409EFF;
    padding-left: 10px;
}
.ml-2 {
    margin-left: 8px;
}
</style>