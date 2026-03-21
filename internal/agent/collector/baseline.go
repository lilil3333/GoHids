package collector

import (
	"encoding/json"
	"fmt"
	"gohids/internal/common"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	pb "gohids/pkg/protocol"

	"github.com/shirou/gopsutil/v3/host"
	psnet "github.com/shirou/gopsutil/v3/net"
)

// --- 数据结构定义 ---

// PortDetail 端口详情 (用于基线对比)
type PortDetail struct {
	Port     uint32 `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	PID      int32  `json:"pid"`
}

// UserDetail 用户详情 (用于基线对比)
type UserDetail struct {
	Username string `json:"username"`
	UID      string `json:"uid"`
	GID      string `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}

// HostSnapshot 定义主机基础信息快照 (扩展 Port/User)
type HostSnapshot struct {
	Hostname  string                `json:"hostname"`
	OS        string                `json:"os"`
	Kernel    string                `json:"kernel"`
	IPs       []string              `json:"ips"`
	Ports     map[string]PortDetail `json:"ports"` // Key: "Port/Proto"
	Users     map[string]UserDetail `json:"users"` // Key: Username
	Timestamp int64                 `json:"timestamp"`
}

// AssetBaseline 定义本地基线存储结构
type AssetBaseline struct {
	LastUpdatedAt int64        `json:"last_updated_at"`
	HostInfo      HostSnapshot `json:"host_info"`
}

// AssetChangeEvent 定义变更事件结构 (对应 Protocol Buffer 逻辑)
type AssetChangeEvent struct {
	Timestamp int64  `json:"timestamp"`
	AssetType string `json:"asset_type"` // IP, HOSTNAME, OS, KERNEL, PORT, USER
	Action    string `json:"action"`     // ADD, DELETE, MODIFY
	Key       string `json:"key"`        // 变更主体标识
	OldValue  string `json:"old_value,omitempty"`
	NewValue  string `json:"new_value,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

const (
	AssetTypeIP       = "IP"
	AssetTypeHostname = "HOSTNAME"
	AssetTypeOS       = "OS"
	AssetTypeKernel   = "KERNEL"
	AssetTypePort     = "PORT"
	AssetTypeUser     = "USER"

	ActionAdd    = "ADD"
	ActionDelete = "DELETE"
	ActionModify = "MODIFY"

	BaselineFile = "baseline.json"
)

// --- Collector 定义 ---

type BaselineCollector struct {
	stopCh   chan struct{}
	filePath string
	mu       sync.Mutex
}

func NewBaselineCollector() *BaselineCollector {
	return &BaselineCollector{
		stopCh:   make(chan struct{}),
		filePath: BaselineFile,
	}
}

func (c *BaselineCollector) Name() string {
	return "Baseline"
}

func (c *BaselineCollector) Start(ch chan<- *pb.RawData) {
	// 启动时执行一次全量检测
	c.check(ch)

	// 之后每 30 秒检测一次 (开发调试模式)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.check(ch)
		}
	}
}

func (c *BaselineCollector) Stop() {
	close(c.stopCh)
}

func (c *BaselineCollector) check(ch chan<- *pb.RawData) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. 采集当前快照
	currentSnapshot, err := c.collectSnapshot()
	if err != nil {
		log.Printf("[Baseline] Failed to collect snapshot: %v", err)
		return
	}

	// 2. 加载本地基线
	baseline, err := c.loadBaseline()

	if err != nil || baseline == nil {
		// [场景 A: 首次运行]
		log.Println("[Baseline] First run detected (no baseline). Initializing baseline...")
		// 仅保存基线，不上报变更
		if err := c.saveBaseline(currentSnapshot); err != nil {
			log.Printf("[Baseline] Failed to save baseline: %v", err)
		}

		// 首次上报基线数据给 Server 存档 (DataTypeAssetSnapshot)
		c.reportSnapshot(ch, currentSnapshot)
		return
	}

	// [场景 B: 非首次运行]
	// 2.5. 检查基线版本兼容性 (处理旧基线缺少字段的情况)
	baselineUpdated := false
	if baseline.HostInfo.Ports == nil {
		log.Println("[Baseline] Detected old baseline (missing Ports). Initializing Ports baseline...")
		baseline.HostInfo.Ports = currentSnapshot.Ports
		baselineUpdated = true
	}
	// 防止 Users 字段为 nil 导致后续启用 Diff 时误报
	if baseline.HostInfo.Users == nil {
		baseline.HostInfo.Users = currentSnapshot.Users
		baselineUpdated = true
	}

	if baselineUpdated {
		if err := c.saveBaseline(&baseline.HostInfo); err != nil {
			log.Printf("[Baseline] Failed to update baseline: %v", err)
		}
	}

	// 3. 执行比对
	changes := c.diff(baseline.HostInfo, *currentSnapshot)

	// Debug Log
	if len(changes) == 0 {
		// log.Printf("[Baseline] No changes detected. Monitoring %d ports.", len(currentSnapshot.Ports))
	} else {
		log.Printf("[Baseline] Diff found %d changes!", len(changes))
		for _, ch := range changes {
			log.Printf("   >> %s %s: %s", ch.Action, ch.AssetType, ch.Key)
		}
	}

	// 4. 处理变更
	if len(changes) > 0 {
		log.Printf("[Baseline] Detected %d changes", len(changes))
		// 上报变更
		c.reportChanges(ch, changes)

		// 更新本地基线
		if err := c.saveBaseline(currentSnapshot); err != nil {
			log.Printf("[Baseline] Failed to update baseline: %v", err)
		}
	}

	// 无论是否有变更，定期上报全量快照以刷新 Server 端的“最后在线”和基础信息
	// 为了避免流量过大，可以降低频率，或者每次都报
	c.reportSnapshot(ch, currentSnapshot)
}

// --- 采集逻辑 ---

func (c *BaselineCollector) collectSnapshot() (*HostSnapshot, error) {
	// 1. Hostname
	hostname, _ := os.Hostname()

	// 2. OS & Kernel
	hostInfo, _ := host.Info()
	osStr := hostInfo.Platform + " " + hostInfo.PlatformVersion
	kernelStr := hostInfo.KernelVersion

	// 3. Network Interfaces (IPs)
	addrs, _ := net.InterfaceAddrs()
	var validIPs []string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				validIPs = append(validIPs, ipnet.IP.String())
			}
		}
	}
	sort.Strings(validIPs)

	// 4. Ports
	ports := make(map[string]PortDetail)
	connections, err := psnet.Connections("all")
	if err == nil {
		for _, conn := range connections {
			if conn.Status == "LISTEN" {
				protocol := "TCP"
				if conn.Type == 2 {
					protocol = "UDP"
				}
				key := fmt.Sprintf("%d/%s", conn.Laddr.Port, protocol)
				ports[key] = PortDetail{
					Port:     conn.Laddr.Port,
					Protocol: protocol,
					State:    conn.Status,
					PID:      conn.Pid,
				}
			}
		}
	}

	// 5. Users
	users := make(map[string]UserDetail)
	hostUsers, err := host.Users()
	if err == nil {
		for _, u := range hostUsers {
			users[u.User] = UserDetail{
				Username: u.User,
				// gopsutil host.Users() only gives basic info.
				// For full system users (like /etc/passwd), we need platform specific code.
				// For now, using logged in users or what gopsutil provides is a start.
				// In real HIDS, we should parse /etc/passwd or use syscalls.
			}
		}
	}

	return &HostSnapshot{
		Hostname:  hostname,
		OS:        osStr,
		Kernel:    kernelStr,
		IPs:       validIPs,
		Ports:     ports,
		Users:     users,
		Timestamp: time.Now().Unix(),
	}, nil
}

// --- 本地存储逻辑 ---

func (c *BaselineCollector) loadBaseline() (*AssetBaseline, error) {
	if _, err := os.Stat(c.filePath); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := ioutil.ReadFile(c.filePath)
	if err != nil {
		return nil, err
	}

	var baseline AssetBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}
	return &baseline, nil
}

func (c *BaselineCollector) saveBaseline(snapshot *HostSnapshot) error {
	baseline := AssetBaseline{
		LastUpdatedAt: time.Now().Unix(),
		HostInfo:      *snapshot,
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(c.filePath, data, 0644)
}

// --- Diff 逻辑 ---

func (c *BaselineCollector) diff(old, new HostSnapshot) []*AssetChangeEvent {
	var events []*AssetChangeEvent

	// 1. Hostname
	if old.Hostname != new.Hostname {
		events = append(events, &AssetChangeEvent{
			Timestamp: time.Now().Unix(),
			AssetType: AssetTypeHostname,
			Action:    ActionModify,
			Key:       "Hostname",
			OldValue:  old.Hostname,
			NewValue:  new.Hostname,
			Reason:    "Hostname changed",
		})
	}

	// 2. OS
	if old.OS != new.OS {
		events = append(events, &AssetChangeEvent{
			Timestamp: time.Now().Unix(),
			AssetType: AssetTypeOS,
			Action:    ActionModify,
			Key:       "OS",
			OldValue:  old.OS,
			NewValue:  new.OS,
			Reason:    "OS version changed",
		})
	}

	// 3. Kernel
	if old.Kernel != new.Kernel {
		events = append(events, &AssetChangeEvent{
			Timestamp: time.Now().Unix(),
			AssetType: AssetTypeKernel,
			Action:    ActionModify,
			Key:       "Kernel",
			OldValue:  old.Kernel,
			NewValue:  new.Kernel,
			Reason:    "Kernel version changed",
		})
	}

	// 4. IPs (Set Diff)
	oldIPs := make(map[string]bool)
	newIPs := make(map[string]bool)
	for _, ip := range old.IPs {
		oldIPs[ip] = true
	}
	for _, ip := range new.IPs {
		newIPs[ip] = true
	}

	for ip := range oldIPs {
		if !newIPs[ip] {
			events = append(events, &AssetChangeEvent{
				Timestamp: time.Now().Unix(),
				AssetType: AssetTypeIP,
				Action:    ActionDelete,
				Key:       ip,
				OldValue:  ip,
				Reason:    "IP address removed",
			})
		}
	}
	for ip := range newIPs {
		if !oldIPs[ip] {
			events = append(events, &AssetChangeEvent{
				Timestamp: time.Now().Unix(),
				AssetType: AssetTypeIP,
				Action:    ActionAdd,
				Key:       ip,
				NewValue:  ip,
				Reason:    "New IP address detected",
			})
		}
	}

	// 5. Ports (Map Diff)
	for key, oldP := range old.Ports {
		if _, exists := new.Ports[key]; !exists {
			events = append(events, &AssetChangeEvent{
				Timestamp: time.Now().Unix(),
				AssetType: AssetTypePort,
				Action:    ActionDelete,
				Key:       fmt.Sprintf("Port %d/%s", oldP.Port, oldP.Protocol),
				Reason:    "Port closed",
			})
		}
	}
	for key, newP := range new.Ports {
		if _, exists := old.Ports[key]; !exists {
			events = append(events, &AssetChangeEvent{
				Timestamp: time.Now().Unix(),
				AssetType: AssetTypePort,
				Action:    ActionAdd,
				Key:       fmt.Sprintf("Port %d/%s", newP.Port, newP.Protocol),
				NewValue:  fmt.Sprintf("PID: %d", newP.PID),
				Reason:    "New port opened",
			})
		}
	}

	// 6. Users (Map Diff)
	// Disabled to prevent spam from login sessions (gopsutil returns login users, not system users)
	/*
		for user := range old.Users {
			if _, exists := new.Users[user]; !exists {
				events = append(events, &AssetChangeEvent{
					Timestamp: time.Now().Unix(),
					AssetType: AssetTypeUser,
					Action:    ActionDelete,
					Key:       user,
					Reason:    "User removed",
				})
			}
		}
		for user := range new.Users {
			if _, exists := old.Users[user]; !exists {
				events = append(events, &AssetChangeEvent{
					Timestamp: time.Now().Unix(),
					AssetType: AssetTypeUser,
					Action:    ActionAdd,
					Key:       user,
					Reason:    "New user created",
				})
			}
		}
	*/

	return events
}

// --- 上报逻辑 ---

func (c *BaselineCollector) reportChanges(ch chan<- *pb.RawData, changes []*AssetChangeEvent) {
	dataBytes, _ := json.Marshal(changes)
	data := createRawData(common.DataTypeAssetChange, map[string]string{
		"data": string(dataBytes),
	})
	data.Data[0].Timestamp = time.Now().Unix()
	ch <- data
}

func (c *BaselineCollector) reportSnapshot(ch chan<- *pb.RawData, snapshot *HostSnapshot) {
	dataBytes, _ := json.Marshal(snapshot)
	data := createRawData(common.DataTypeAssetSnapshot, map[string]string{
		"data": string(dataBytes),
	})
	data.Data[0].Timestamp = time.Now().Unix()
	ch <- data
}
