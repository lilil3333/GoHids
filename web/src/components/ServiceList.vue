<template>
  <div class="cyber-table-container">
    <div class="overflow-x-auto flex-1 w-full">
      <div class="min-w-[800px]">
        <!-- Header -->
        <div class="cyber-table-header">
          <div class="text-center">STATUS</div>
          <div class="pl-2">SERVICE NAME</div>
          <div class="pl-2">DISPLAY NAME</div>
          <div class="pl-2">RUN AS</div>
          <div class="text-center">RISK</div>
        </div>

        <!-- Body -->
        <div class="cyber-table-body">
          <div 
            v-for="(svc, index) in services" 
            :key="index"
            class="cyber-row group"
          >
            <!-- Selection/Status Strip -->
            <div 
              class="absolute left-0 top-0 bottom-0 w-[3px]"
              :class="{
                'bg-cyber-accent-green': svc.status === 'Running',
                'bg-cyber-text-muted': svc.status !== 'Running'
              }"
            ></div>

            <!-- Status Icon -->
            <div class="flex justify-center items-center text-xs">
               <div class="w-2 h-2 rounded-full" :class="{
                 'bg-cyber-accent-green': svc.status === 'Running',
                 'bg-cyber-text-muted': svc.status !== 'Running'
               }"></div>
            </div>

            <!-- Service Name -->
            <div class="pl-2 font-sans font-medium text-cyber-text-primary overflow-hidden">
                <div class="truncate" :title="svc.name">{{ svc.name }}</div>
            </div>

            <!-- Display Name -->
            <div class="pl-2 font-sans text-sm text-cyber-text-secondary overflow-hidden">
                <div class="truncate" :title="svc.display_name">{{ svc.display_name }}</div>
            </div>

            <!-- Run As -->
            <div class="pl-2 font-mono text-xs text-cyber-accent-blue overflow-hidden">
              <div class="truncate" :title="svc.user">{{ svc.user }}</div>
            </div>

            <!-- Risk -->
            <div class="text-center">
               <span class="risk-badge justify-center w-full" :class="getRiskClass(svc)">
                  <span class="dot"></span>
                  {{ getRiskLevel(svc) }}
                </span>
            </div>
          </div>
           <el-empty v-if="services.length === 0" description="暂无服务数据" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Service {
  name: string;
  display_name: string;
  status: string;
  user: string;
}

const props = defineProps<{
  services: Service[];
}>();

const getRiskLevel = (svc: Service) => {
  // Simple mock logic
  if (svc.status === 'Running' && (svc.name.toLowerCase().includes('remote') || svc.name.toLowerCase().includes('telnet'))) return 'WARNING';
  return 'NORMAL';
};

const getRiskClass = (svc: Service) => {
  const level = getRiskLevel(svc);
  if (level === 'WARNING') return 'badge-warning';
  return 'badge-normal';
};
</script>

<style scoped>
/* Layout & Grid */
.cyber-table-header, .cyber-row {
  display: grid;
  grid-template-columns: 60px minmax(200px, 1fr) minmax(200px, 1fr) 150px 80px;
  gap: 8px;
  align-items: center;
}

/* Base Container */
.cyber-table-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
  background-color: #0D1117; /* Fallback bg */
}

/* Header Styles */
.cyber-table-header {
  background-color: #161B22;
  border-bottom: 1px solid #30363D;
  padding: 8px 0;
  font-size: 11px;
  font-weight: 600;
  color: #8B949E;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  position: sticky;
  top: 0;
  z-index: 10;
}

/* Row Styles */
.cyber-row {
  padding: 8px 0;
  border-bottom: 1px solid #21262D;
  cursor: pointer;
  position: relative;
  transition: background-color 0.1s;
  font-size: 13px;
  min-height: 48px; /* Consistent height */
}

.cyber-row:hover {
  background-color: #161B22;
}

/* Utilities */
.text-center { text-align: center; }
.pl-2 { padding-left: 0.5rem; }
.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.overflow-hidden { overflow: hidden; }
.overflow-x-auto { overflow-x: auto; }
.min-w-\[800px\] { min-width: 800px; }
.w-full { width: 100%; }
.flex-1 { flex: 1 1 0%; }
.absolute { position: absolute; }
.top-0 { top: 0; }
.bottom-0 { bottom: 0; }
.left-0 { left: 0; }
.w-\[3px\] { width: 3px; }
.flex { display: flex; }
.justify-center { justify-content: center; }
.items-center { align-items: center; }

/* Colors (extracted from tailwind config/process monitor) */
.bg-cyber-accent-green { background-color: #39D353; }
.bg-cyber-text-muted { background-color: #6E7681; }
.text-cyber-text-primary { color: #C9D1D9; }
.text-cyber-text-secondary { color: #8B949E; }
.text-cyber-accent-blue { color: #58A6FF; }

/* Badge Styles */
.risk-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
}
.badge-warning { color: #FAAD14; background: rgba(250, 173, 20, 0.1); border: 1px solid rgba(250, 173, 20, 0.2); }
.badge-normal { color: #39D353; background: rgba(57, 211, 83, 0.1); border: 1px solid rgba(57, 211, 83, 0.2); }

.dot {
  width: 4px;
  height: 4px;
  border-radius: 50%;
  margin-right: 4px;
  background-color: currentColor;
}
</style>