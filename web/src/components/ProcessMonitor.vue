<template>
  <div class="cyber-container">
    <!-- Header / Status Bar -->
    <div class="cyber-header">
      <div class="flex items-center gap-4">
        <div class="cyber-badge bg-elevated text-info">
          <span class="w-2 h-2 rounded-full bg-processing animate-pulse mr-2"></span>
          Host: {{ hostname }}
        </div>
        <div class="cyber-badge bg-elevated text-secondary">
          {{ osVersion }}
        </div>
        <div class="cyber-badge bg-elevated text-secondary font-mono">
          {{ ips.join(', ') }}
        </div>
      </div>
      
      <div class="flex items-center gap-2">
        <div class="cyber-search">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-muted"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <input 
            v-model="searchQuery" 
            type="text" 
            placeholder="输入要搜索的pid,进程名或命令行" 
            class="bg-transparent border-none focus:outline-none text-primary ml-2 w-48 text-sm"
          />
        </div>
      </div>
    </div>

    <!-- Main Content: Process Tree -->
    <div class="cyber-table-container">
      <div class="cyber-table-header">
        <div class="col-name">PROCESS NAME</div>
        <div class="col-pid">PID</div>
        <div class="col-user">USER</div>
        <div class="col-cmd">COMMAND LINE</div>
        <div class="col-risk">RISK</div>
      </div>
      
      <div class="cyber-table-body">
        <div 
          v-for="proc in flattenedTree" 
          :key="proc.pid"
          class="cyber-row"
          :class="{ 
            'row-critical': proc.riskLevel === 'critical',
            'row-warning': proc.riskLevel === 'warning',
            'row-selected': selectedPid === proc.pid
          }"
          @click="toggleExpand(proc)"
          @mouseenter="hoverPid = proc.pid"
          @mouseleave="hoverPid = null"
        >
          <!-- Risk Indicator Strip -->
          <div class="risk-strip" :class="`risk-${proc.riskLevel}`"></div>

          <!-- Name Column -->
          <div class="col-name flex items-center" :style="{ paddingLeft: `${proc.depth * 20 + 12}px` }">
            <!-- Expand Icon -->
            <div 
              class="expand-icon mr-2"
              :style="{ visibility: (proc.children && proc.children.length > 0) ? 'visible' : 'hidden' }"
              :class="{ 'is-expanded': proc.expanded }"
              @click.stop="toggleExpand(proc)"
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            </div>
            
            <!-- Process Icon -->
            <span class="mr-2">
              <span v-if="proc.isSystem" class="text-info" title="System Process">🔒</span>
              <span v-else class="text-secondary" title="User Process">👤</span>
            </span>
            
            <span class="font-mono text-sm" :class="proc.riskLevel === 'critical' ? 'text-critical' : 'text-primary'">
              {{ proc.name }}
            </span>
            
            <span v-if="proc.children && proc.children.length" class="text-muted text-xs ml-2">({{ proc.children.length }})</span>
          </div>

          <!-- PID Column -->
          <div class="col-pid font-mono text-secondary">
            {{ proc.pid }} <span class="text-muted text-xs">/{{ proc.ppid }}</span>
          </div>

          <!-- User Column -->
          <div class="col-user">
             <span 
               class="user-tag" 
               :class="isSystemUser(proc.user) ? 'text-warning' : 'text-secondary'"
             >
               {{ proc.user }}
             </span>
          </div>

          <!-- Cmdline Column -->
          <div class="col-cmd font-mono text-xs text-muted truncate relative group">
            {{ proc.cmdline }}
            <!-- Tooltip for full cmdline -->
            <div class="hidden group-hover:block absolute top-6 left-0 bg-elevated border border-border p-2 rounded shadow-xl z-50 whitespace-normal break-all max-w-lg text-primary">
              {{ proc.cmdline }}
            </div>
          </div>

          <!-- Risk Badge Column -->
          <div class="col-risk">
            <span class="risk-badge" :class="`badge-${proc.riskLevel}`">
              <span class="dot"></span>
              {{ proc.riskLevel.toUpperCase() }}
            </span>
          </div>

          <!-- Hover Actions -->
          <div class="row-actions" v-if="hoverPid === proc.pid || selectedPid === proc.pid">
            <button class="action-btn text-info">Detail</button>
            <button class="action-btn text-critical">Kill</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';

// --- Types ---
interface RawProcess {
  pid: number;
  ppid: number;
  name: string;
  user: string;
  cmdline: string;
}

interface ProcessNode extends RawProcess {
  children: ProcessNode[];
  depth: number;
  expanded: boolean;
  isSystem: boolean;
  riskLevel: 'critical' | 'warning' | 'normal' | 'system';
}

// --- Props ---
const props = defineProps<{
  rawProcesses: RawProcess[];
  hostname?: string;
  osVersion?: string;
  ips?: string[];
}>();

// --- State ---
const searchQuery = ref('');
const selectedPid = ref<number | null>(null);
const hoverPid = ref<number | null>(null);
const expandedPids = ref<Set<number>>(new Set());

// --- Constants ---
const SYSTEM_USERS = ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'root'];
const CRITICAL_PROCESSES = ['nc.exe', 'ncat.exe', 'powershell.exe', 'cmd.exe', 'mimikatz.exe'];
const WARNING_PROCESSES = ['python.exe', 'java.exe', 'node.exe'];

// --- Logic ---

const isSystemUser = (user: string) => SYSTEM_USERS.includes(user);

const getRiskLevel = (proc: RawProcess): 'critical' | 'warning' | 'normal' | 'system' => {
  if (CRITICAL_PROCESSES.includes(proc.name)) return 'critical';
  if (WARNING_PROCESSES.includes(proc.name)) return 'warning';
  if (isSystemUser(proc.user)) return 'system';
  return 'normal';
};

// Build Tree
const processTree = computed(() => {
  const map = new Map<number, ProcessNode>();
  const roots: ProcessNode[] = [];
  
  // 1. Init nodes
  props.rawProcesses.forEach(p => {
    map.set(p.pid, {
      ...p,
      children: [],
      depth: 0,
      expanded: expandedPids.value.has(p.pid), // Restore expanded state
      isSystem: isSystemUser(p.user),
      riskLevel: getRiskLevel(p)
    });
  });

  // 2. Build Hierarchy
  props.rawProcesses.forEach(p => {
    const node = map.get(p.pid)!;
    if (p.ppid && map.has(p.ppid)) {
      const parent = map.get(p.ppid)!;
      parent.children.push(node);
    } else {
      roots.push(node);
    }
  });

  // Sort by PID for stability
  const sortNodes = (nodes: ProcessNode[]) => {
    nodes.sort((a, b) => a.pid - b.pid);
    nodes.forEach(n => sortNodes(n.children));
  };
  sortNodes(roots);

  return roots;
});

// Flatten Tree for Rendering (Virtual Scroll friendly structure)
const flattenedTree = computed(() => {
  const query = searchQuery.value.toLowerCase().trim();

  // 1. If no query, standard traversal respecting expanded state
  if (!query) {
    const result: ProcessNode[] = [];
    const traverse = (nodes: ProcessNode[], depth: number) => {
      for (const node of nodes) {
        node.depth = depth;
        result.push(node);
        if (node.expanded) {
          traverse(node.children, depth + 1);
        }
      }
    };
    traverse(processTree.value, 0);
    return result;
  }

  // 2. Search Mode: Filter and Flatten
  // Returns a list of nodes that match OR have matching children
  const filterAndFlatten = (nodes: ProcessNode[], depth: number): ProcessNode[] => {
    const list: ProcessNode[] = [];
    
    for (const node of nodes) {
      // Recursively filter children first
      const matchingChildren = filterAndFlatten(node.children, depth + 1);
      const hasMatchingChildren = matchingChildren.length > 0;
      
      // Check self match
      const selfMatch = node.name.toLowerCase().includes(query) || 
                        node.pid.toString().includes(query) ||
                        node.cmdline.toLowerCase().includes(query);

      // Include if self matches OR has matching children
      if (selfMatch || hasMatchingChildren) {
        node.depth = depth;
        
        // Auto-expand if children match so user can see them
        if (hasMatchingChildren) {
            node.expanded = true;
            // Optional: Update expandedPids to persist state
            expandedPids.value.add(node.pid);
        }

        list.push(node);
        
        // If children matched, include them (they are already flattened)
        if (hasMatchingChildren) {
          list.push(...matchingChildren);
        }
      }
    }
    return list;
  };

  return filterAndFlatten(processTree.value, 0);
});

// --- Actions ---
const toggleExpand = (proc: ProcessNode) => {
  proc.expanded = !proc.expanded;
  if (proc.expanded) {
    expandedPids.value.add(proc.pid);
  } else {
    expandedPids.value.delete(proc.pid);
  }
};

// Initial Expand All (Optional)
// watch(() => props.rawProcesses, () => {
//    // Logic to expand roots by default if needed
// }, { immediate: true });

</script>

<style scoped>
/* --- Design System: Dark Cyber --- */
.cyber-container {
  background-color: #0D1117;
  color: #C9D1D9;
  font-family: 'Inter', sans-serif;
  height: 100%;
  display: flex;
  flex-direction: column;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #30363D;
}

/* Header */
.cyber-header {
  background-color: #161B22;
  border-bottom: 1px solid #30363D;
  padding: 12px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.cyber-badge {
  padding: 4px 12px;
  border-radius: 9999px;
  font-size: 12px;
  font-weight: 500;
  display: flex;
  align-items: center;
}

.cyber-search {
  background-color: #0D1117;
  border: 1px solid #30363D;
  border-radius: 6px;
  padding: 6px 10px;
  display: flex;
  align-items: center;
  transition: border-color 0.2s;
}
.cyber-search:focus-within {
  border-color: #58A6FF;
}

/* Table */
.cyber-table-container {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.cyber-table-header {
  display: flex;
  padding: 10px 0;
  background-color: #161B22;
  border-bottom: 1px solid #30363D;
  font-size: 11px;
  font-weight: 600;
  color: #8B949E;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  position: sticky;
  top: 0;
  z-index: 10;
}

/* Table Header Columns */
.col-name { flex: 0 0 350px; padding-right: 10px; overflow: hidden; } /* Fixed width for name */
.col-pid { flex: 0 0 120px; text-align: right; padding-right: 20px; } /* Fixed width */
.col-user { flex: 0 0 140px; } /* Fixed width */
.col-cmd { flex: 1; padding-right: 10px; min-width: 200px; overflow: hidden; } /* Flexible width */
.col-risk { flex: 0 0 100px; text-align: center; } /* Fixed width */

/* Rows */
.cyber-row {
  display: flex;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid #21262D;
  cursor: pointer;
  position: relative;
  transition: background-color 0.1s;
  font-size: 13px;
  width: 100%; /* Ensure row takes full width */
}

.cyber-row:hover {
  background-color: #161B22;
}

.row-selected {
  background-color: #1F242C; /* elevated + blue hint */
}

/* Risk Strip */
.risk-strip {
  width: 3px;
  height: 100%;
  position: absolute;
  left: 0;
  top: 0;
}
.risk-critical { background-color: #FF4D4F; box-shadow: 0 0 8px rgba(255, 77, 79, 0.4); }
.risk-warning { background-color: #FAAD14; }
.risk-system { background-color: #58A6FF; opacity: 0.5; }
.risk-normal { background-color: transparent; }

/* Critical Row Effect */
.row-critical {
  background: linear-gradient(90deg, rgba(255,77,79,0.05) 0%, transparent 100%);
}

/* Icons */
.expand-icon {
  width: 16px;
  height: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #8B949E;
  transition: transform 0.2s;
}
.is-expanded {
  transform: rotate(90deg);
}

/* Text Colors */
.text-primary { color: #C9D1D9; }
.text-secondary { color: #8B949E; }
.text-muted { color: #6E7681; }
.text-info { color: #58A6FF; }
.text-warning { color: #FAAD14; }
.text-critical { color: #FF4D4F; }
.text-processing { color: #39D353; }

.font-mono { font-family: 'JetBrains Mono', 'Consolas', monospace; }

/* Badges */
.risk-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
}
.badge-critical { color: #FF4D4F; background: rgba(255, 77, 79, 0.1); border: 1px solid rgba(255, 77, 79, 0.2); }
.badge-warning { color: #FAAD14; background: rgba(250, 173, 20, 0.1); border: 1px solid rgba(250, 173, 20, 0.2); }
.badge-system { color: #58A6FF; background: rgba(88, 166, 255, 0.1); border: 1px solid rgba(88, 166, 255, 0.2); }
.badge-normal { color: #39D353; background: rgba(57, 211, 83, 0.1); border: 1px solid rgba(57, 211, 83, 0.2); }

.dot {
  width: 4px;
  height: 4px;
  border-radius: 50%;
  margin-right: 4px;
  background-color: currentColor;
}
.badge-critical .dot { animation: pulse 1s infinite; }

/* Actions */
.row-actions {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  display: flex;
  gap: 8px;
  background: #161B22;
  padding: 2px 8px;
  border-radius: 4px;
  box-shadow: -4px 0 8px rgba(0,0,0,0.2);
}
.action-btn {
  background: none;
  border: none;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
}
.action-btn:hover { text-decoration: underline; }

/* Utils */
.flex { display: flex; }
.items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.gap-2 { gap: 0.5rem; }
.gap-4 { gap: 1rem; }
.mr-2 { margin-right: 0.5rem; }
.ml-2 { margin-left: 0.5rem; }
.w-48 { width: 12rem; }
.bg-transparent { background-color: transparent; }
.border-none { border: none; }
.focus\:outline-none:focus { outline: none; }
.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hidden { display: none; }
.group-hover\:block:hover { display: block; }
.absolute { position: absolute; }
.z-50 { z-index: 50; }

@keyframes pulse {
  0% { opacity: 1; }
  50% { opacity: 0.5; }
  100% { opacity: 1; }
}

/* Scrollbar */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-track {
  background: #0D1117;
}
::-webkit-scrollbar-thumb {
  background: #30363D;
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
  background: #58A6FF;
}
</style>