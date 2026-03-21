<template>
  <div class="cyber-table-container">
    <div class="overflow-x-auto flex-1 w-full">
      <div class="min-w-[900px]">
        <!-- Header -->
        <div class="cyber-table-header">
          <div class="text-center">STATUS</div>
          <div class="pl-2">ACTION</div>
          <div class="text-center">PROTO</div>
          <div class="pl-2">SOURCE</div>
          <div class="text-center">DIR</div>
          <div class="pl-2">DESTINATION</div>
          <div class="pl-2">PROCESS</div>
          <div class="text-center">RISK</div>
        </div>

        <!-- Body -->
        <div class="cyber-table-body">
          <div 
            v-for="(conn, index) in connections" 
            :key="index"
            class="cyber-row group"
            :class="{ 'is-external': isExternal(conn.dst_ip) }"
          >
            <!-- Selection/Status Strip -->
            <div 
              class="absolute left-0 top-0 bottom-0 w-[3px]"
              :class="{
                'bg-accent-green': conn.status === 'ESTABLISHED',
                'bg-accent-orange': conn.status === 'CLOSE_WAIT',
                'bg-accent-blue': conn.status === 'SYN_SENT',
                'bg-text-muted': !['ESTABLISHED', 'CLOSE_WAIT', 'SYN_SENT'].includes(conn.status)
              }"
            ></div>

            <!-- Status Icon -->
            <div class="flex justify-center items-center text-xs">
               <div class="w-2 h-2 rounded-full" :class="{
                 'bg-accent-green': conn.status === 'ESTABLISHED',
                 'bg-accent-orange': conn.status === 'CLOSE_WAIT',
                 'bg-accent-blue': conn.status === 'SYN_SENT',
                 'bg-text-muted': !['ESTABLISHED', 'CLOSE_WAIT', 'SYN_SENT'].includes(conn.status)
               }"></div>
            </div>

            <!-- Action -->
            <div class="pl-2 flex items-center gap-1 text-xs font-medium overflow-hidden">
              <svg v-if="conn.action === 'CONNECT'" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-accent-green flex-shrink-0"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
              <svg v-else-if="conn.action === 'DISCONNECT'" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-accent-red flex-shrink-0"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
              <svg v-else xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-accent-blue flex-shrink-0"><path d="M2 12h20"></path></svg>
              
              <span class="truncate" :class="{
                'text-accent-green': conn.action === 'CONNECT',
                'text-accent-red': conn.action === 'DISCONNECT',
                'text-accent-blue': conn.action === 'LISTEN'
              }">{{ conn.action }}</span>
            </div>

            <!-- Protocol -->
            <div class="text-center">
              <span class="px-1.5 py-0.5 rounded text-[10px] font-bold inline-block" :class="{
                'bg-accent-blue-soft': conn.protocol === 'TCP',
                'bg-accent-green-soft': conn.protocol === 'UDP'
              }">{{ conn.protocol }}</span>
            </div>

            <!-- Source -->
            <div class="pl-2 font-mono text-sm text-accent-blue truncate">
              {{ conn.src_ip }}<span class="text-secondary text-xs">:{{ conn.src_port }}</span>
            </div>

            <!-- Direction -->
            <div class="text-center text-muted">→</div>

            <!-- Destination -->
            <div class="pl-2 font-mono text-sm truncate flex items-center gap-1">
              <svg v-if="isExternal(conn.dst_ip)" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-accent-orange flex-shrink-0"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
              <span v-else class="text-accent-blue flex-shrink-0">🏠</span>
              <span class="truncate" :class="isExternal(conn.dst_ip) ? 'text-accent-orange' : 'text-accent-blue'">
                {{ conn.dst_ip }}
              </span>
              <span class="text-secondary text-xs">:{{ conn.dst_port }}</span>
            </div>

            <!-- Process -->
            <div class="pl-2 flex items-center gap-2 truncate">
              <span class="text-secondary flex-shrink-0">👤</span>
              <span class="text-primary text-sm font-sans truncate">{{ conn.process_name }}</span>
              <span class="text-muted text-xs font-mono group-hover:inline hidden">({{ conn.pid }})</span>
            </div>

            <!-- Risk -->
            <div class="text-center">
               <span class="risk-badge justify-center w-full" :class="getRiskClass(conn)">
                  <span class="dot"></span>
                  {{ getRiskLevel(conn) }}
                </span>
            </div>
          </div>
           <el-empty v-if="connections.length === 0" description="暂无网络连接数据" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Connection {
  action: string;
  protocol: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  process_name: string;
  pid: number;
  status: string;
}

const props = defineProps<{
  connections: Connection[];
}>();

const isExternal = (ip: string) => {
  if (!ip) return false;
  return !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.16.') && ip !== '127.0.0.1' && ip !== '::1';
};

const getRiskLevel = (conn: Connection) => {
  if (isExternal(conn.dst_ip) && ![80, 443].includes(conn.dst_port)) return 'WARNING';
  return 'NORMAL';
};

const getRiskClass = (conn: Connection) => {
  const level = getRiskLevel(conn);
  if (level === 'WARNING') return 'badge-warning';
  return 'badge-normal';
};
</script>

<style scoped>
/* Layout & Grid - CRITICAL FIX */
.cyber-table-header, .cyber-row {
  display: grid !important;
  grid-template-columns: 60px 80px 60px minmax(140px, 1fr) 40px minmax(160px, 1fr) minmax(120px, 1fr) 80px !important;
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
.is-external { background-color: rgba(255, 77, 79, 0.05); }

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
.gap-1 { gap: 0.25rem; }
.flex-shrink-0 { flex-shrink: 0; }

/* Colors */
.bg-accent-green { background-color: #39D353; }
.bg-accent-orange { background-color: #FAAD14; }
.bg-accent-blue { background-color: #58A6FF; }
.bg-text-muted { background-color: #6E7681; }
.bg-accent-blue-soft { background: rgba(88, 166, 255, 0.1); color: #58A6FF; border: 1px solid rgba(88, 166, 255, 0.2); }
.bg-accent-green-soft { background: rgba(57, 211, 83, 0.1); color: #39D353; border: 1px solid rgba(57, 211, 83, 0.2); }
.text-accent-green { color: #39D353; }
.text-accent-red { color: #FF4D4F; }
.text-accent-blue { color: #58A6FF; }
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