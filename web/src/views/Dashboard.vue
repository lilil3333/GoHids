<template>
  <el-container class="layout-container">
    <el-aside width="240px" class="aside">
      <div class="logo">
        <el-icon class="logo-icon"><Shield /></el-icon>
        <span>GoHIDS 安全平台</span>
      </div>
      <el-menu
        router
        :default-active="$route.path"
        background-color="#1d1e1f"
        text-color="#bfcbd9"
        active-text-color="#409EFF"
        class="el-menu-vertical"
      >
        <el-menu-item index="/dashboard">
          <el-icon><Odometer /></el-icon>
          <span>总览 (Dashboard)</span>
        </el-menu-item>
        <el-menu-item index="/agents">
          <el-icon><Monitor /></el-icon>
          <span>主机监控</span>
        </el-menu-item>
        <el-menu-item index="/alerts">
          <el-icon><Warning /></el-icon>
          <span>行为告警</span>
        </el-menu-item>
        <el-menu-item index="/logs" disabled>
          <el-icon><Document /></el-icon>
          <span>日志分析</span>
        </el-menu-item>
        <el-menu-item index="/rules" disabled>
          <el-icon><Operation /></el-icon>
          <span>规则管理</span>
        </el-menu-item>
        <el-menu-item index="/settings" disabled>
          <el-icon><Setting /></el-icon>
          <span>系统设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="header-left">
          <span class="system-time">{{ currentTime }}</span>
          <el-divider direction="vertical" />
          <span class="status-badge"><span class="dot green"></span> 系统运行正常</span>
        </div>
        <div class="header-right">
          <el-dropdown @command="handleCommand">
            <span class="el-dropdown-link">
              <el-avatar :size="32" src="https://cube.elemecdn.com/0/88/03b0d39583f48206768a7534e55bcpng.png" />
              <span class="username">管理员</span>
              <el-icon class="el-icon--right"><arrow-down /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const currentTime = ref('')
let timer: any = null

const updateTime = () => {
  const now = new Date()
  currentTime.value = now.toLocaleString()
}

const handleCommand = (command: string) => {
  if (command === 'logout') {
    localStorage.removeItem('token')
    router.push('/login')
  }
}

onMounted(() => {
  updateTime()
  timer = setInterval(updateTime, 1000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.layout-container {
  height: 100vh;
  background-color: #141414;
}
.aside {
  background-color: #1d1e1f;
  color: white;
  border-right: 1px solid #303133;
}
.logo {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  font-weight: bold;
  background-color: #1d1e1f;
  border-bottom: 1px solid #303133;
  color: #409EFF;
}
.logo-icon {
  margin-right: 10px;
  font-size: 24px;
}
.el-menu-vertical {
  border-right: none;
}
.header {
  background-color: #1d1e1f;
  border-bottom: 1px solid #303133;
  display: flex;
  align-items: center;
  justify-content: space-between;
  color: #fff;
  height: 60px;
}
.header-left {
  display: flex;
  align-items: center;
  font-size: 14px;
  color: #909399;
}
.system-time {
  margin-right: 15px;
}
.status-badge {
  display: flex;
  align-items: center;
  margin-left: 15px;
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 5px;
}
.dot.green { background-color: #67C23A; }

.el-dropdown-link {
  cursor: pointer;
  display: flex;
  align-items: center;
  color: #fff;
}
.username {
  margin-left: 10px;
}
.main-content {
  background-color: #141414; /* Dark background for content area */
  padding: 20px;
}
</style>
