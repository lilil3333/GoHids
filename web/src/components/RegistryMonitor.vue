<template>
  <div class="cyber-table-container">
    <div class="overflow-x-auto flex-1 w-full">
      <div class="min-w-[800px]">
        <!-- Header -->
        <div class="cyber-table-header">
          <div class="text-center">ACT</div>
          <div class="pl-2">ROOT</div>
          <div class="pl-2">KEY PATH</div>
          <div class="pl-2">VALUE NAME</div>
          <div class="text-center">TIMESTAMP</div>
        </div>

        <!-- Body -->
        <div class="cyber-table-body">
            <!-- Mock Data since actual registry data structure might vary -->
            <el-empty v-if="!registryData || Object.keys(registryData).length === 0" description="暂无注册表变更数据" />
            <div v-else class="p-4 text-secondary font-mono text-sm">
                 <pre>{{ JSON.stringify(registryData, null, 2) }}</pre>
            </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const props = defineProps<{
  registryData: any;
}>();
</script>

<style scoped>
/* Layout & Grid - CRITICAL FIX */
.cyber-table-header {
  display: grid !important;
  grid-template-columns: 60px 100px minmax(300px,1fr) minmax(150px,1fr) 130px !important;
  gap: 8px;
  align-items: center;
  width: 100%;
}

.cyber-table-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
  background-color: #0D1117;
}

.cyber-table-header {
  background-color: #161B22;
  border-bottom: 1px solid #30363D;
  padding: 8px 0;
  font-size: 11px;
  font-weight: 600;
  color: #8B949E;
  text-transform: uppercase;
  position: sticky;
  top: 0;
  z-index: 10;
}

/* Utilities */
.text-center { text-align: center; }
.pl-2 { padding-left: 0.5rem; }
.overflow-x-auto { overflow-x: auto; }
.min-w-\[800px\] { min-width: 800px; }
.flex-1 { flex: 1; }
.w-full { width: 100%; }
.p-4 { padding: 1rem; }
.text-secondary { color: #8B949E; }
.font-mono { font-family: 'JetBrains Mono', 'Consolas', monospace; }
.text-sm { font-size: 0.875rem; }
</style>