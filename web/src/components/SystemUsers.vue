<template>
  <div class="cyber-table-container">
    <div class="overflow-x-auto flex-1 w-full">
      <div class="min-w-[800px]">
        <!-- Header -->
        <div class="cyber-table-header">
          <div class="text-center">TYPE</div>
          <div class="pl-2">USERNAME</div>
          <div class="text-center">UID/GID</div>
          <div class="pl-2">SHELL</div>
          <div class="pl-2">HOME DIR</div>
          <div class="text-center">RISK</div>
        </div>

        <!-- Body -->
        <div class="cyber-table-body">
          <div 
            v-for="(user, index) in users" 
            :key="index"
            class="cyber-row group"
          >
            <!-- Selection/Status Strip -->
            <div 
              class="absolute left-0 top-0 bottom-0 w-[3px]"
              :class="{
                'bg-accent-purple': isAdmin(user),
                'bg-accent-blue': !isAdmin(user)
              }"
            ></div>

            <!-- Type Icon -->
            <div class="flex justify-center items-center text-lg">
               <span v-if="isAdmin(user)">🔧</span>
               <span v-else-if="isSystem(user)">⚙️</span>
               <span v-else>👤</span>
            </div>

            <!-- Username -->
            <div class="pl-2 font-sans font-medium text-primary flex items-center gap-2 overflow-hidden">
                <span class="truncate">{{ user.username }}</span>
                <span v-if="isAdmin(user)" class="px-1.5 py-0.5 rounded text-[10px] bg-accent-purple-soft text-accent-purple border border-accent-purple flex-shrink-0">Admin</span>
            </div>

            <!-- UID/GID -->
            <div class="text-center font-mono text-xs text-secondary">
              {{ user.uid }}/{{ user.gid }}
            </div>

            <!-- Shell -->
            <div class="pl-2 font-mono text-xs text-secondary truncate" :title="user.shell">
              {{ user.shell }}
            </div>

            <!-- Home Dir -->
            <div class="pl-2 font-mono text-xs text-muted truncate" :title="user.home_dir">
              {{ user.home_dir }}
            </div>

            <!-- Risk -->
            <div class="text-center">
               <span class="risk-badge justify-center w-full" :class="getRiskClass(user)">
                  <span class="dot"></span>
                  {{ getRiskLevel(user) }}
                </span>
            </div>
          </div>
           <el-empty v-if="users.length === 0" description="暂无用户数据" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
interface User {
  username: string;
  uid: string;
  gid: string;
  shell: string;
  home_dir: string;
}

const props = defineProps<{
  users: User[];
}>();

const isAdmin = (user: User) => {
    return user.gid === '0' || user.username.toLowerCase() === 'root' || user.username.toLowerCase().includes('admin');
}

const isSystem = (user: User) => {
    const uid = parseInt(user.uid);
    return uid < 1000 && uid !== 0; // Typical linux logic, simplistic
}

const getRiskLevel = (user: User) => {
  if (user.username === 'Guest' || (!user.shell.endsWith('nologin') && !user.shell.endsWith('false') && isSystem(user))) return 'WARNING';
  return 'NORMAL';
};

const getRiskClass = (user: User) => {
  const level = getRiskLevel(user);
  if (level === 'WARNING') return 'badge-warning';
  return 'badge-normal';
};
</script>

<style scoped>
/* Layout & Grid - CRITICAL FIX */
.cyber-table-header, .cyber-row {
  display: grid !important;
  grid-template-columns: 60px minmax(150px,1fr) 100px 150px minmax(200px,1fr) 80px !important;
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
.min-w-\[800px\] { min-width: 800px; }
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
.bg-accent-purple { background-color: #A371F7; }
.bg-accent-blue { background-color: #58A6FF; }
.bg-accent-purple-soft { background: rgba(163, 113, 247, 0.1); }
.text-accent-purple { color: #A371F7; }
.border-accent-purple { border-color: rgba(163, 113, 247, 0.2); }
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