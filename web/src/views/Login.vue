<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <div class="login-header">
          <h2>GoHIDS 安全管理系统</h2>
        </div>
      </template>
      <el-form :model="form" label-width="0px">
        <el-form-item>
          <el-input v-model="form.username" placeholder="用户名" prefix-icon="User" />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" placeholder="密码" prefix-icon="Lock" show-password />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" style="width: 100%" @click="handleLogin" :loading="loading">登录</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { login } from '../api'
import { ElMessage } from 'element-plus'

const router = useRouter()
const form = ref({
  username: '',
  password: ''
})
const loading = ref(false)

const handleLogin = async () => {
  if (!form.value.username || !form.value.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    const res: any = await login(form.value)
    // api interceptor handles error codes, but let's double check
    if (res.code === 0) {
        localStorage.setItem('token', res.token)
        ElMessage.success('登录成功')
        router.push('/')
    }
  } catch (error) {
    console.error(error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background-color: #141414;
}
.login-card {
  width: 400px;
  background-color: #1d1e1f;
  border: 1px solid #303133;
  color: #fff;
}
:deep(.el-card__header) {
  border-bottom: 1px solid #303133;
}
.login-header {
  text-align: center;
}
:deep(.el-input__wrapper) {
  background-color: #2b2d30;
  box-shadow: 0 0 0 1px #303133 inset;
}
:deep(.el-input__inner) {
  color: #fff;
}
</style>
