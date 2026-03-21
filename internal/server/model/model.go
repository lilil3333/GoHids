package model

import (
	"time"
)

type Agent struct {
	ID           string    `gorm:"primaryKey" json:"agent_id"`
	Hostname     string    `json:"hostname"`
	Product      string    `json:"product"`
	Version      string    `json:"version"`
	IntranetIPv4 string    `json:"intranet_ipv4"` // Stored as comma-separated string
	LastSeen     time.Time `json:"last_seen"`
	Status       string    `json:"status"`
}

type PerformanceLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentID   string    `gorm:"index" json:"agent_id"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	CPU       float64   `json:"cpu"`
	Memory    float64   `json:"memory"` // Usage percentage
	Disk      string    `json:"disk"`   // JSON string of disk usage
}

type SecurityEvent struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentID   string    `gorm:"index" json:"agent_id"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	EventType string    `json:"event_type"` // e.g., "LOGIN", "PROCESS", "FILE", "REGISTRY"
	Details   string    `json:"details"`    // JSON string of details
	Severity  string    `json:"severity"`   // "INFO", "WARN", "CRITICAL"
}

type Alert struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentID   string    `gorm:"index" json:"agent_id"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	Type      string    `json:"type"`     // e.g., "RDP_BRUTE_FORCE", "FILE_TAMPERING"
	Message   string    `json:"message"`  // e.g., "Failed RDP login from 192.168.1.5 user: admin"
	Severity  string    `json:"severity"` // "HIGH", "CRITICAL"
	Status    string    `json:"status"`   // "OPEN", "RESOLVED"
}

// User represents a system user for login
type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Username     string     `gorm:"type:varchar(191);uniqueIndex;not null" json:"username"`
	PasswordHash string     `gorm:"type:varchar(255);not null" json:"-"` // Store hash only, never return password
	Role         string     `gorm:"type:varchar(50)" json:"role"`        // e.g., "admin", "viewer"
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login"`
}

// AgentInfo is a transient struct for Dashboard (in-memory)
type AgentInfo struct {
	AgentID      string                 `json:"agent_id"`
	Hostname     string                 `json:"hostname"`
	Product      string                 `json:"product"`
	Version      string                 `json:"version"`
	IntranetIPv4 []string               `json:"intranet_ipv4"`
	LastSeen     string                 `json:"last_seen"`
	Data         map[string]interface{} `json:"data"` // Latest monitoring data
}

type ProcessEvent struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentID   string    `gorm:"index" json:"agent_id"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	Action    string    `json:"action"` // START, EXIT, SNAPSHOT
	PID       int32     `json:"pid"`
	PPID      int32     `json:"ppid"`
	Name      string    `json:"name"`
	Cmdline   string    `json:"cmdline"`
	Path      string    `json:"path"`
	User      string    `json:"user"`
	Checksum  string    `json:"checksum"`
}

type NetworkEvent struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	AgentID     string    `gorm:"index" json:"agent_id"`
	Timestamp   time.Time `gorm:"index" json:"timestamp"`
	Action      string    `json:"action"` // CONNECT, DISCONNECT, SNAPSHOT
	Protocol    string    `json:"protocol"`
	SrcIP       string    `json:"src_ip"`
	SrcPort     uint32    `json:"src_port"`
	DstIP       string    `json:"dst_ip"`
	DstPort     uint32    `json:"dst_port"`
	ProcessName string    `json:"process_name"`
	PID         int32     `json:"pid"`
}

type FileEvent struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	AgentID     string    `gorm:"index" json:"agent_id"`
	Timestamp   time.Time `gorm:"index" json:"timestamp"`
	Action      string    `json:"action"` // CREATE, MODIFY, DELETE, RENAME
	FilePath    string    `json:"file_path"`
	OldFilePath string    `json:"old_file_path,omitempty"` // For RENAME
	Hash        string    `json:"hash"`
}

type AssetPort struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	AgentID     string    `gorm:"index" json:"agent_id"`
	Port        uint32    `json:"port"`
	Protocol    string    `json:"protocol"` // TCP/UDP
	State       string    `json:"state"`    // LISTEN
	ProcessName string    `json:"process_name"`
	PID         int32     `json:"pid"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AssetUser struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentID   string    `gorm:"index" json:"agent_id"`
	Username  string    `json:"username"`
	UID       string    `json:"uid"`
	GID       string    `json:"gid"`
	HomeDir   string    `json:"home_dir"`
	Shell     string    `json:"shell"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AssetChange struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentID   string    `gorm:"index" json:"agent_id"`
	AssetType string    `json:"asset_type"` // PORT, USER, PROCESS, CRON
	Action    string    `json:"action"`     // ADD, DELETE, MODIFY
	Detail    string    `json:"detail"`     // JSON string of the snapshot or change detail
	Timestamp time.Time `gorm:"index" json:"timestamp"`
}

type DashboardStats struct {
	OnlineAgents    int            `json:"online_agents"`
	OfflineAgents   int            `json:"offline_agents"`
	TotalAlerts     int64          `json:"total_alerts"`
	OSDistribution  map[string]int `json:"os_distribution"`
	TopProcesses    []TopStat      `json:"top_processes"`
	OpenPorts       map[string]int `json:"open_ports"`
	HighRiskSystems []string       `json:"high_risk_systems"` // IPs or Hostnames
	SoftwareStats   map[string]int `json:"software_stats"`
	RecentAlerts    []Alert        `json:"recent_alerts"`
	AlertTrend      []TimeStat     `json:"alert_trend"`
}

type TopStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type TimeStat struct {
	Time  string `json:"time"`
	Count int    `json:"count"`
}
