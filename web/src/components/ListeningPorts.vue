<template>
  <div class="cyber-table-container">
    <div class="overflow-x-auto flex-1 w-full">
      <div class="min-w-[900px]">
        <!-- Header -->
        <div class="cyber-table-header">
          <div class="text-center">STATUS</div>
          <div class="text-center">PROTO</div>
          <div class="pl-2">LISTENING ADDRESS</div>
          <div class="pl-2">PORT</div>
          <div class="pl-2">PROCESS</div>
          <div class="text-center">RISK</div>
          <div class="text-center">SEEN</div>
        </div>

        <!-- Body -->
        <div class="cyber-table-body">
          <div 
            v-for="(port, index) in ports" 
            :key="index"
            class="cyber-row group"
          >
            <!-- Selection/Status Strip -->
            <div 
              class="absolute left-0 top-0 bottom-0 w-[3px]"
              :class="{
                'bg-accent-blue': port.state === 'LISTEN',
                'bg-accent-green': port.state === 'ESTABLISHED',
                'bg-text-muted': port.state === 'CLOSED'
              }"
            ></div>

            <!-- Status Icon -->
            <div class="flex justify-center items-center text-muted text-xs">
               <div class="w-2 h-2 rounded-full" :class="{
                 'bg-accent-blue': port.state === 'LISTEN',
                 'bg-accent-green': port.state === 'ESTABLISHED',
                 'bg-text-muted': port.state === 'CLOSED'
               }"></div>
            </div>

            <!-- Protocol -->
            <div class="text-center">
              <span class="px-1.5 py-0.5 rounded text-[10px] font-bold inline-block" :class="{
                'bg-accent-blue-soft': port.protocol === 'TCP',
                'bg-accent-green-soft': port.protocol === 'UDP'
              }">{{ port.protocol }}</span>
            </div>

            <!-- Address -->
            <div class="pl-2 font-mono text-sm flex items-center gap-2 overflow-hidden">
                <span v-if="port.bind_ip === '0.0.0.0' || port.bind_ip === '::'" class="text-accent-orange flex-shrink-0" title="Exposed to all interfaces">🌐</span>
                <span v-else-if="port.bind_ip === '127.0.0.1'" class="text-accent-green flex-shrink-0" title="Localhost only">🔒</span>
                <span v-else class="text-accent-blue flex-shrink-0">🏠</span>
                <span class="truncate" :class="{
                    'text-accent-orange': port.bind_ip === '0.0.0.0' || port.bind_ip === '::',
                    'text-accent-green': port.bind_ip === '127.0.0.1',
                    'text-primary': !['0.0.0.0', '::', '127.0.0.1'].includes(port.bind_ip)
                }">{{ port.bind_ip || '0.0.0.0' }}</span>
            </div>

            <!-- Port -->
            <div class="pl-2 font-mono text-lg font-bold text-accent-blue overflow-hidden flex items-center">
              <span>{{ port.port }}</span>
              <span v-if="getServiceName(port.port)" class="ml-1 px-1 rounded bg-elevated text-secondary text-[10px] font-sans font-normal border border-border truncate">{{ getServiceName(port.port) }}</span>
            </div>

            <!-- Process -->
            <div class="pl-2 flex items-center gap-2 truncate">
              <span class="text-secondary flex-shrink-0">⚙️</span>
              <span class="text-primary text-sm font-sans truncate">PID: {{ port.pid }}</span>
            </div>

            <!-- Risk -->
            <div class="text-center">
               <span class="risk-badge justify-center w-full" :class="getRiskClass(port)">
                  <span class="dot"></span>
                  {{ getRiskLevel(port) }}
                </span>
            </div>
            
            <!-- Time -->
            <div class="text-center text-xs text-muted">
                {{ new Date(port.updated_at).toLocaleTimeString() }}
            </div>
          </div>
           <el-empty v-if="ports.length === 0" description="暂无开放端口数据" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Port {
  port: number;
  protocol: string;
  state: string;
  pid: number;
  updated_at: string;
  bind_ip?: string;
}

const props = defineProps<{
  ports: Port[];
}>();

const getServiceName = (port: number) => {
    const map: Record<number, string> = { 21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 53: 'DNS' };
    return map[port];
}

const getRiskLevel = (port: Port) => {
  if ([21, 22, 23, 3389, 445].includes(port.port) && (!port.bind_ip || port.bind_ip === '0.0.0.0')) return 'WARNING';
  return 'NORMAL';
};

const getRiskClass = (port: Port) => {
  const level = getRiskLevel(port);
  if (level === 'WARNING') return 'badge-warning';
  return 'badge-normal';
};
</script>

<style scoped>
/* Layout & Grid - CRITICAL FIX */
.cyber-table-header, .cyber-row {
  display: grid !important;
  grid-template-columns: 60px 60px minmax(200px,1fr) 100px minmax(200px,1fr) 100px 130px !important;
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

.cyber-row {
  padding: 8px 0;
  border-bottom: 1px solid #21262D;
  cursor: pointer;
  position: relative;
  transition: background-color 0.1s;
  font-size: 13px;
  min-height: 48px;
}

.cyber-row:hover { background-color: #161B22; }

/* Utilities */
.text-center { text-align: center; }
.pl-2 { padding-left: 0.5rem; }
.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.overflow-x-auto { overflow-x: auto; }
.min-w-\[900px\] { min-width: 900px; }
.flex-1 { flex: 1; }
.absolute { position: absolute; }
.top-0 { top: 0; }
.bottom-0 { bottom: 0; }
.left-0 { left: 0; }
.w-\[3px\] { width: 3px; }
.flex { display: flex; }
.justify-center { justify-content: center; }
.items-center { align-items: center; }
.gap-2 { gap: 0.5rem; }
.flex-shrink-0 { flex-shrink: 0; }

/* Colors */
.bg-accent-blue { background-color: #58A6FF; }
.bg-accent-green { background-color: #39D353; }
.bg-text-muted { background-color: #6E7681; }
.bg-elevated { background-color: #21262D; }
.border-border { border-color: #30363D; }
.bg-accent-blue-soft { background: rgba(88, 166, 255, 0.1); color: #58A6FF; border: 1px solid rgba(88, 166, 255, 0.2); }
.bg-accent-green-soft { background: rgba(57, 211, 83, 0.1); color: #39D353; border: 1px solid rgba(57, 211, 83, 0.2); }
.text-accent-blue { color: #58A6FF; }
.text-accent-green { color: #39D353; }
.text-accent-orange { color: #FAAD14; }
.text-primary { color: #C9D1D9; }
.text-secondary { color: #8B949E; }
.text-muted { color: #6E7681; }

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