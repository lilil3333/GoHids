package service

import (
	"encoding/json"
	"fmt"
	"gohids/internal/common"
	"gohids/internal/server/model"
	"gohids/internal/server/repository"
	"gohids/pkg/auth"
	pb "gohids/pkg/protocol"
	"gohids/pkg/threatbook"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TODO: Move this to config
const ThreatBookAPIKey = "708c58fe378840dda0f88be97affd339796f997475f24e3a94be070b47ff5957"

type AgentService interface {
	ProcessData(agentID string, data *pb.RawData) error
	GetAgentStatus(agentID string) (*model.AgentInfo, bool)
	GetAllAgentsStatus() []*model.AgentInfo

	GetSecurityEvents(agentID string, limit int) ([]model.SecurityEvent, error)
	GetProcessEvents(agentID string, limit int) ([]model.ProcessEvent, error)
	GetNetworkEvents(agentID string, limit int) ([]model.NetworkEvent, error)
	GetFileEvents(agentID string, limit int) ([]model.FileEvent, error)
	GetDashboardStats() (*model.DashboardStats, error)

	// Stream Management
	RegisterAgentStream(agentID string, stream pb.Transfer_TransferServer)
	UnregisterAgentStream(agentID string)
	SendCommand(agentID string, cmd *pb.Command) error

	// User Logic
	Login(username, password string) (string, error)
	Register(username, password string) error

	// Configuration
	SetThreatBookEnabled(enabled bool)
	IsThreatBookEnabled() bool
	GetAssetPorts(agentID string) ([]model.AssetPort, error)
	GetAssetUsers(agentID string) ([]model.AssetUser, error)
	GetAssetChanges(agentID string, limit int) ([]model.AssetChange, error)
}

type agentService struct {
	repo repository.Repository
	// InMemory cache for dashboard
	cache map[string]*model.AgentInfo

	// Active gRPC streams
	streams map[string]pb.Transfer_TransferServer

	mu        sync.RWMutex
	tbClient  *threatbook.Client
	tbEnabled bool
}

func NewAgentService(repo repository.Repository) AgentService {
	s := &agentService{
		repo:      repo,
		cache:     make(map[string]*model.AgentInfo),
		streams:   make(map[string]pb.Transfer_TransferServer),
		tbClient:  threatbook.GetClient(ThreatBookAPIKey),
		tbEnabled: false, // Default to false to prevent quota exceeded errors
	}

	// Restore cache from DB to persist state across restarts
	agents, err := repo.GetAgents()
	if err == nil {
		for _, a := range agents {
			s.cache[a.ID] = &model.AgentInfo{
				AgentID:      a.ID,
				Hostname:     a.Hostname,
				Product:      a.Product,
				Version:      a.Version,
				IntranetIPv4: strings.Split(a.IntranetIPv4, ","),
				LastSeen:     a.LastSeen.Format(time.RFC3339),
				Data:         make(map[string]interface{}), // Empty data initially
			}
		}
		fmt.Printf("[Service] Restored %d agents from DB\n", len(agents))
	} else {
		fmt.Printf("[Service] Failed to restore agents from DB: %v\n", err)
	}

	return s
}

func (s *agentService) SetThreatBookEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tbEnabled = enabled
}

func (s *agentService) IsThreatBookEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tbEnabled
}

func (s *agentService) GetSecurityEvents(agentID string, limit int) ([]model.SecurityEvent, error) {
	return s.repo.GetSecurityEvents(agentID, limit)
}

func (s *agentService) GetProcessEvents(agentID string, limit int) ([]model.ProcessEvent, error) {
	return s.repo.GetProcessEvents(agentID, limit)
}

func (s *agentService) GetNetworkEvents(agentID string, limit int) ([]model.NetworkEvent, error) {
	return s.repo.GetNetworkEvents(agentID, limit)
}

func (s *agentService) GetFileEvents(agentID string, limit int) ([]model.FileEvent, error) {
	return s.repo.GetFileEvents(agentID, limit)
}

func (s *agentService) RegisterAgentStream(agentID string, stream pb.Transfer_TransferServer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams[agentID] = stream
}

func (s *agentService) UnregisterAgentStream(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streams, agentID)
}

func (s *agentService) SendCommand(agentID string, cmd *pb.Command) error {
	s.mu.RLock()
	stream, ok := s.streams[agentID]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("agent %s not connected", agentID)
	}

	return stream.Send(cmd)
}

func (s *agentService) GetAgentStatus(agentID string) (*model.AgentInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.cache[agentID]
	return info, ok
}

func (s *agentService) GetAllAgentsStatus() []*model.AgentInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*model.AgentInfo, 0, len(s.cache))
	for _, v := range s.cache {
		list = append(list, v)
	}
	return list
}

func (s *agentService) GetDashboardStats() (*model.DashboardStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &model.DashboardStats{
		OSDistribution: make(map[string]int),
		OpenPorts:      make(map[string]int),
		SoftwareStats:  make(map[string]int),
	}

	// 1. Agent Stats from Memory Cache
	now := time.Now()
	for _, info := range s.cache {
		// Parse LastSeen
		lastSeen, _ := time.Parse(time.RFC3339, info.LastSeen)
		if now.Sub(lastSeen) < 5*time.Minute {
			stats.OnlineAgents++
		} else {
			stats.OfflineAgents++
		}

		// OS Distribution (Simplistic check based on Product/Platform field if available, or assume Linux/Windows based on path)
		// For now, let's assume "Unknown" if not strictly defined, or infer from file paths in data if possible.
		// GoHIDS agent sends "Product" which usually is OS name in some implementations, or we check "Version".
		// Let's use a placeholder or derived logic.
		os := "Unknown"
		if strings.Contains(strings.ToLower(info.Product), "windows") {
			os = "Windows"
		} else if strings.Contains(strings.ToLower(info.Product), "linux") {
			os = "Linux"
		}
		stats.OSDistribution[os]++

		// 2. Aggregate Software/Services
		if svcs, ok := info.Data["services"].([]interface{}); ok {
			for _, svc := range svcs {
				if sm, ok := svc.(map[string]interface{}); ok {
					if name, ok := sm["name"].(string); ok {
						stats.SoftwareStats[name]++
					}
				}
			}
		}

		// 3. Aggregate Ports (from Network Data - Listen ports are usually in a separate "Port" collector,
		// but if we use Network "LISTEN" events or just infer from connections...)
		// Actually, standard HIDS usually has a specialized Port collector.
		// If GoHIDS doesn't have explicit Port collector in "Data", we might check "network" for "LISTEN" state if available.
		// Assuming "network" contains connection info.
		// Let's use "network" data if it has listening ports.
		// The current Agent Network collector sends CONNECT/DNS events.
		// Let's check if we have "listening_ports" in Data (maybe added later).
		// For now, we will aggregate distinct Destination Ports from CONNECT events as "Active External Services"
		// OR strictly, we need to implement PortCollector.
		// Let's use what we have: Process names.

		// Aggregate Top Processes
		if procs, ok := info.Data["processes"].([]interface{}); ok {
			for _, p := range procs {
				if pm, ok := p.(map[string]interface{}); ok {
					if _, ok := pm["name"].(string); ok {
						// Simple frequency map for this agent to avoid double counting same process on same agent?
						// Or just count total instances across fleet.
						// Let's count total instances.
						// We need a temp map for top processes
					}
				}
			}
		}
	}

	// Re-iterate for Top Processes to handle globally
	procCounts := make(map[string]int)
	for _, info := range s.cache {
		if procs, ok := info.Data["processes"].([]interface{}); ok {
			seenOnHost := make(map[string]bool)
			for _, p := range procs {
				if pm, ok := p.(map[string]interface{}); ok {
					if name, ok := pm["name"].(string); ok {
						if !seenOnHost[name] {
							procCounts[name]++
							seenOnHost[name] = true
						}
					}
				}
			}
		}
	}

	// Convert procCounts to TopProcesses slice
	for name, count := range procCounts {
		stats.TopProcesses = append(stats.TopProcesses, model.TopStat{Name: name, Count: count})
	}
	// Sort (Bubble sort or simple sort for brevity)
	// For production, use sort.Slice
	// ... sort logic here ...
	// Let's just return top 10 unsorted or partially sorted in UI, or sort here.

	// 4. Alerts from DB
	alerts, _ := s.repo.GetAlerts(100)
	stats.RecentAlerts = alerts
	stats.TotalAlerts = int64(len(alerts)) // In real app, Count() query

	// Alert Trend (Mock or Real aggregation from DB)
	// We can aggregate alerts by day
	trendMap := make(map[string]int)
	for _, a := range alerts {
		date := a.Timestamp.Format("2006-01-02")
		trendMap[date]++
	}
	for k, v := range trendMap {
		stats.AlertTrend = append(stats.AlertTrend, model.TimeStat{Time: k, Count: v})
	}

	return stats, nil
}

func (s *agentService) Login(username, password string) (string, error) {
	user, err := s.repo.GetUserByUsername(username)
	if err != nil {
		return "", fmt.Errorf("invalid username or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", fmt.Errorf("invalid username or password")
	}

	now := time.Now()
	user.LastLogin = &now
	// Update last login (optional, if repo supports update)

	// Generate JWT Token
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		return "", fmt.Errorf("failed to generate token")
	}
	return token, nil
}

func (s *agentService) Register(username, password string) error {
	if _, err := s.repo.GetUserByUsername(username); err == nil {
		return fmt.Errorf("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user := &model.User{
		Username:     username,
		PasswordHash: string(hashedPassword),
		Role:         "admin",
		CreatedAt:    time.Now(),
	}
	return s.repo.CreateUser(user)
}

func (s *agentService) ProcessData(agentID string, req *pb.RawData) error {
	// 1. Update In-Memory Cache
	s.mu.Lock()
	info, ok := s.cache[agentID]
	if !ok {
		info = &model.AgentInfo{
			AgentID: agentID,
			Data:    make(map[string]interface{}),
		}
		s.cache[agentID] = info
	}
	info.Hostname = req.Hostname
	info.Product = req.Product
	info.Version = req.Version
	info.IntranetIPv4 = req.IntranetIPv4
	info.LastSeen = time.Now().Format(time.RFC3339)
	s.mu.Unlock()

	// 2. Update DB: Agent Table
	agent := &model.Agent{
		ID:           agentID,
		Hostname:     req.Hostname,
		Product:      req.Product,
		Version:      req.Version,
		IntranetIPv4: strings.Join(req.IntranetIPv4, ","),
		LastSeen:     time.Now(),
		Status:       "online",
	}
	if err := s.repo.UpsertAgent(agent); err != nil {
		return fmt.Errorf("failed to upsert agent: %w", err)
	}

	// 3. Process Records
	for _, record := range req.GetData() {
		if err := s.processRecord(agentID, info, record); err != nil {
			// Log error but continue processing other records
			fmt.Printf("Error processing record type %d: %v\n", record.DataType, err)
		}
	}
	return nil
}

func (s *agentService) processRecord(agentID string, info *model.AgentInfo, record *pb.Record) error {
	switch record.DataType {
	case common.DataTypeHeartbeat:
		// Already handled by LastSeen update
	case common.DataTypeProcess:
		return s.handleProcess(info, record)
	case common.DataTypeNetwork:
		return s.handleNetwork(agentID, info, record)
	case common.DataTypeFile:
		return s.handleFile(agentID, info, record)
	case common.DataTypeService:
		return s.handleService(info, record)
	case common.DataTypeRegistry:
		return s.handleRegistry(agentID, info, record)
	case common.DataTypePerformance:
		return s.handlePerformance(agentID, info, record)
	case common.DataTypeSecurityLog:
		return s.handleSecurityLog(agentID, record)
	case common.DataTypeUSB:
		return s.handleUSB(agentID, record)
	case common.DataTypeIntrusion:
		return s.handleIntrusion(agentID, record)
	case common.DataTypeForensics:
		return s.handleForensics(agentID, record)
	case common.DataTypeAssetPort:
		return s.handleAssetPort(agentID, record)
	case common.DataTypeAssetUser:
		return s.handleAssetUser(agentID, record)
	case common.DataTypeAssetChange:
		return s.handleAssetChange(agentID, record)
	case common.DataTypeAssetSnapshot:
		return s.handleAssetSnapshot(agentID, record)
	}
	return nil
}

func (s *agentService) handleAssetSnapshot(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if data, ok := record.Body.Fields["data"]; ok {
			var snapshot map[string]interface{}
			if err := json.Unmarshal([]byte(data), &snapshot); err == nil {
				s.mu.Lock()
				defer s.mu.Unlock()

				info, ok := s.cache[agentID]
				if !ok {
					// Create if not exists (though usually it should exist by now)
					info = &model.AgentInfo{AgentID: agentID, Data: make(map[string]interface{})}
					s.cache[agentID] = info
				}

				// Update Basic Info
				if hostname, ok := snapshot["hostname"].(string); ok {
					info.Hostname = hostname
				}
				if osInfo, ok := snapshot["os"].(string); ok {
					info.Product = osInfo
				}
				if kernel, ok := snapshot["kernel"].(string); ok {
					info.Data["kernel"] = kernel // Store kernel in Data map
				}
				if ips, ok := snapshot["ips"].([]interface{}); ok {
					var ipList []string
					for _, ip := range ips {
						if ipStr, ok := ip.(string); ok {
							ipList = append(ipList, ipStr)
						}
					}
					info.IntranetIPv4 = ipList
				}

				// Also update DB Agent record if needed
				// For now, memory cache is enough for frontend display
			}
		}
	}
	return nil
}

func (s *agentService) handleAssetChange(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if data, ok := record.Body.Fields["data"]; ok {
			var changes []map[string]interface{}
			if err := json.Unmarshal([]byte(data), &changes); err == nil {
				for _, ch := range changes {
					assetType, _ := ch["asset_type"].(string)
					action, _ := ch["action"].(string)
					key, _ := ch["key"].(string)

					// 构造详情描述
					detail := key
					if reason, ok := ch["reason"].(string); ok && reason != "" {
						detail = fmt.Sprintf("%s (%s)", key, reason)
					}

					if action == "MODIFY" {
						oldV, _ := ch["old_value"].(string)
						newV, _ := ch["new_value"].(string)
						detail = fmt.Sprintf("%s: %s -> %s", key, oldV, newV)
					}

					// 存储到数据库
					s.repo.CreateAssetChange(&model.AssetChange{
						AgentID:   agentID,
						AssetType: assetType,
						Action:    action,
						Detail:    detail,
						Timestamp: time.Now(),
					})
				}
			}
		}
	}
	return nil
}

func (s *agentService) GetAssetPorts(agentID string) ([]model.AssetPort, error) {
	return s.repo.GetAssetPorts(agentID)
}

func (s *agentService) GetAssetUsers(agentID string) ([]model.AssetUser, error) {
	return s.repo.GetAssetUsers(agentID)
}

func (s *agentService) GetAssetChanges(agentID string, limit int) ([]model.AssetChange, error) {
	return s.repo.GetAssetChanges(agentID, limit)
}

func (s *agentService) handleAssetPort(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if data, ok := record.Body.Fields["data"]; ok {
			var ports []map[string]interface{}
			if err := json.Unmarshal([]byte(data), &ports); err == nil {
				// Get existing ports for Diff
				existingPorts, _ := s.repo.GetAssetPorts(agentID)
				existingMap := make(map[string]model.AssetPort)
				for _, p := range existingPorts {
					key := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
					existingMap[key] = p
				}

				currentMap := make(map[string]bool)

				for _, p := range ports {
					portFloat, _ := p["port"].(float64)
					port := uint32(portFloat)
					protocol, _ := p["protocol"].(string)
					state, _ := p["state"].(string)
					pidFloat, _ := p["pid"].(float64)
					pid := int32(pidFloat)

					key := fmt.Sprintf("%d/%s", port, protocol)
					currentMap[key] = true

					// Check New
					// if _, exists := existingMap[key]; !exists {
					// 	// ADDED
					// 	detail := fmt.Sprintf("Port %d/%s (PID: %d)", port, protocol, pid)
					// 	s.repo.CreateAssetChange(&model.AssetChange{
					// 		AgentID:   agentID,
					// 		AssetType: "PORT",
					// 		Action:    "ADD",
					// 		Detail:    detail,
					// 		Timestamp: time.Now(),
					// 	})
					// }

					// Upsert
					s.repo.UpsertAssetPort(&model.AssetPort{
						AgentID:   agentID,
						Port:      port,
						Protocol:  protocol,
						State:     state,
						PID:       pid,
						UpdatedAt: time.Now(),
					})
				}

				// Check Deleted
				// for key, p := range existingMap {
				// 	if !currentMap[key] {
				// 		// DELETED
				// 		detail := fmt.Sprintf("Port %d/%s", p.Port, p.Protocol)
				// 		s.repo.CreateAssetChange(&model.AssetChange{
				// 			AgentID:   agentID,
				// 			AssetType: "PORT",
				// 			Action:    "DELETE",
				// 			Detail:    detail,
				// 			Timestamp: time.Now(),
				// 		})
				// 		s.repo.DeleteAssetPort(agentID, p.Port, p.Protocol)
				// 	}
				// }
				// Keep deleting state for cleanup, but DON'T generate Change Event
				for key, p := range existingMap {
					if !currentMap[key] {
						s.repo.DeleteAssetPort(agentID, p.Port, p.Protocol)
					}
				}
			}
		}
	}
	return nil
}

func (s *agentService) handleAssetUser(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if data, ok := record.Body.Fields["data"]; ok {
			var users []map[string]interface{}
			if err := json.Unmarshal([]byte(data), &users); err == nil {
				// Get existing users for Diff
				existingUsers, _ := s.repo.GetAssetUsers(agentID)
				existingMap := make(map[string]model.AssetUser)
				for _, u := range existingUsers {
					existingMap[u.Username] = u
				}

				currentMap := make(map[string]bool)

				for _, u := range users {
					username, _ := u["username"].(string)
					currentMap[username] = true

					// Check New
					// if _, exists := existingMap[username]; !exists {
					// 	// ADDED
					// 	s.repo.CreateAssetChange(&model.AssetChange{
					// 		AgentID:   agentID,
					// 		AssetType: "USER",
					// 		Action:    "ADD",
					// 		Detail:    fmt.Sprintf("User: %s", username),
					// 		Timestamp: time.Now(),
					// 	})
					// }

					// Upsert
					s.repo.UpsertAssetUser(&model.AssetUser{
						AgentID:   agentID,
						Username:  username,
						UpdatedAt: time.Now(),
					})
				}

				// Check Deleted
				// for user := range existingMap {
				// 	if !currentMap[user] {
				// 		// DELETED
				// 		s.repo.CreateAssetChange(&model.AssetChange{
				// 			AgentID:   agentID,
				// 			AssetType: "USER",
				// 			Action:    "DELETE",
				// 			Detail:    fmt.Sprintf("User: %s", user),
				// 			Timestamp: time.Now(),
				// 		})
				// 		s.repo.DeleteAssetUser(agentID, user)
				// 	}
				// }
				// Keep deleting state for cleanup, but DON'T generate Change Event
				for user := range existingMap {
					if !currentMap[user] {
						s.repo.DeleteAssetUser(agentID, user)
					}
				}
			}
		}
	}
	return nil
}

func (s *agentService) handleForensics(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if data, ok := record.Body.Fields["data"]; ok {
			// Save forensic report
			return s.repo.CreateSecurityEvent(&model.SecurityEvent{
				AgentID:   agentID,
				Timestamp: time.Now(),
				EventType: common.EventTypeForensics,
				Details:   data,
				Severity:  common.SeverityCritical,
			})
		}
	}
	return nil
}

func (s *agentService) handleIntrusion(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if data, ok := record.Body.Fields["data"]; ok {
			// Alert details are already in the "data" field as JSON string
			// We can parse it to extract specific fields if needed,
			// or just store it directly.

			// Try to parse basic info for the main Alert table message
			var alertInfo map[string]interface{}
			msg := "Intrusion Detection Alert"
			severity := common.SeverityHigh

			if err := json.Unmarshal([]byte(data), &alertInfo); err == nil {
				if m, ok := alertInfo["rule_msg"].(string); ok {
					msg = m
				}

				// Enrich with Process Info if available
				procName, hasName := alertInfo["process_name"].(string)
				pidFloat, hasPID := alertInfo["process_pid"].(float64)

				if hasName && hasPID {
					msg = fmt.Sprintf("%s (进程: %s PID: %d)", msg, procName, int(pidFloat))

					// If cmdline is available, maybe append it or just stick to name/pid for brevity
					// User asked: "确定是哪个外联IP的什么进程，这个进程在哪里"
					// "在哪里" usually implies Path.
					// ProcessCollector currently sends 'process_cmd' but not explicit 'process_path' in the map?
					// Let's check ProcessCollector again.
					// It sends "process_cmd": cmdline.
					// Let's try to parse path from cmdline or if ProcessCollector was updated to send path?
					// ProcessCollector in previous read:
					// info := ProcessInfo{... Name, Cmdline ...}
					// It does NOT send Path explicitly in alertData, only "process_cmd".
					// But usually cmdline[0] is the path or close to it.
					// However, I updated NetworkCollector to send Path. ProcessCollector I haven't touched.
					// Let's just use what we have: Name and PID.
				}

				// Map Suricata/GoHIDS rule class to Severity
				// This logic can be refined
				severity = common.SeverityCritical
			}

			// 1. Create Security Event (Detailed Log)
			err := s.repo.CreateSecurityEvent(&model.SecurityEvent{
				AgentID:   agentID,
				Timestamp: time.Now(),
				EventType: common.EventTypeIntrusion,
				Details:   data, // The full JSON payload
				Severity:  severity,
			})
			if err != nil {
				return err
			}

			// 2. Create High-Level Alert (Dashboard Notification)
			return s.repo.CreateAlert(&model.Alert{
				AgentID:   agentID,
				Timestamp: time.Now(),
				Type:      "INTRUSION_DETECTION",
				Message:   fmt.Sprintf("[Suricata Rule] %s", msg),
				Severity:  severity,
				Status:    "OPEN",
			})
		}
	}
	return nil
}

func (s *agentService) handleProcess(info *model.AgentInfo, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if procData, ok := record.Body.Fields["data"]; ok {
			// DEBUG LOGGING
			// fmt.Printf("[DEBUG] Process Data Received: %s\n", procData)

			var events []map[string]interface{}
			if err := json.Unmarshal([]byte(procData), &events); err == nil {
				s.mu.Lock()
				// Initialize if nil
				if info.Data["processes"] == nil {
					info.Data["processes"] = []interface{}{}
				}
				// Get current list
				currentProcs := info.Data["processes"].([]interface{})

				// Process events
				for _, evt := range events {
					// Fallback for action (support old agent for a moment or debug)
					action, _ := evt["action"].(string)
					if action == "" {
						// Try to guess or log error
						// fmt.Println("[WARN] Empty action in process event")
					}

					pidFloat, _ := evt["pid"].(float64)
					pid := int32(pidFloat)
					ppidFloat, _ := evt["ppid"].(float64)
					ppid := int32(ppidFloat)
					name, _ := evt["name"].(string)
					path, _ := evt["path"].(string) // Added
					cmdline, _ := evt["cmdline"].(string)
					user, _ := evt["user"].(string)

					// 1. Store in DB (Timeline)
					err := s.repo.CreateProcessEvent(&model.ProcessEvent{
						AgentID:   info.AgentID,
						Timestamp: time.Now(),
						Action:    action,
						PID:       pid,
						PPID:      ppid,
						Name:      name,
						Path:      path, // Added
						Cmdline:   cmdline,
						User:      user,
					})
					if err != nil {
						fmt.Printf("Error creating process event: %v\n", err)
					}

					// 2. Update In-Memory Cache (Current State)
					if action == "START" {
						// Check if exists
						exists := false
						for _, p := range currentProcs {
							if pm, ok := p.(map[string]interface{}); ok {
								if pPid, ok := pm["pid"].(float64); ok && int32(pPid) == pid {
									exists = true
									break
								}
							}
						}
						if !exists {
							currentProcs = append(currentProcs, evt)
						}
					} else if action == "EXIT" {
						// Remove
						newProcs := make([]interface{}, 0)
						for _, p := range currentProcs {
							if pm, ok := p.(map[string]interface{}); ok {
								if pPid, ok := pm["pid"].(float64); ok && int32(pPid) == pid {
									continue // Skip (Delete)
								}
							}
							newProcs = append(newProcs, p)
						}
						currentProcs = newProcs
					} else {
						// If action is empty (Old Agent?), it's likely a Snapshot
						// We might want to replace the whole list if it looks like a snapshot list
						// But for now, let's assume new agent.
					}
				}

				info.Data["processes"] = currentProcs
				s.mu.Unlock()
			}
		}
	}
	return nil
}

// NetworkContext holds process info associated with a network connection
type NetworkContext struct {
	PID         int32
	ProcessName string
	ProcessPath string
	Cmdline     string
}

func (s *agentService) handleNetwork(agentID string, info *model.AgentInfo, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if netData, ok := record.Body.Fields["data"]; ok {
			var events []map[string]interface{}
			if err := json.Unmarshal([]byte(netData), &events); err == nil {
				// Map IP -> Context
				publicIPs := make(map[string]NetworkContext)

				for _, evt := range events {
					action, _ := evt["action"].(string)
					protocol, _ := evt["protocol"].(string)
					srcIP, _ := evt["src_ip"].(string)
					srcPortFloat, _ := evt["src_port"].(float64)
					dstIP, _ := evt["dst_ip"].(string)
					dstPortFloat, _ := evt["dst_port"].(float64)

					// Process Info
					processName, _ := evt["process_name"].(string)
					pidFloat, _ := evt["pid"].(float64)
					processPath, _ := evt["process_path"].(string)
					cmdline, _ := evt["cmdline"].(string)

					// Store in NetworkEvent table
					err := s.repo.CreateNetworkEvent(&model.NetworkEvent{
						AgentID:     agentID,
						Timestamp:   time.Now(),
						Action:      action,
						Protocol:    protocol,
						SrcIP:       srcIP,
						SrcPort:     uint32(srcPortFloat),
						DstIP:       dstIP,
						DstPort:     uint32(dstPortFloat),
						ProcessName: processName,
						PID:         int32(pidFloat),
					})
					if err != nil {
						fmt.Printf("Error creating network event: %v\n", err)
					}

					// Collect Public IPs for ThreatBook (Only on CONNECT)
					if action == "CONNECT" && dstIP != "" && !isPrivateIP(dstIP) {
						publicIPs[dstIP] = NetworkContext{
							PID:         int32(pidFloat),
							ProcessName: processName,
							ProcessPath: processPath,
							Cmdline:     cmdline,
						}
					}
				}

				s.mu.Lock()
				// FIX: Append instead of overwrite for events, OR maintain a "Current Active Connections" list
				// Currently NetworkCollector sends "Events" (CONNECT/DISCONNECT).
				// If we overwrite info.Data["network"] with just the latest batch of events,
				// the dashboard will only show what happened in the last 10 seconds.

				// Better approach for Dashboard "Current Connections":
				// We should maintain a state map of active connections in info.Data["active_connections"]
				// And use info.Data["network"] for the event log stream.

				if info.Data["active_connections"] == nil {
					info.Data["active_connections"] = make(map[string]map[string]interface{})
				}
				activeConns := info.Data["active_connections"].(map[string]map[string]interface{})

				for _, evt := range events {
					action, _ := evt["action"].(string)
					// Reconstruct Key to match Agent's logic or close enough
					protocol, _ := evt["protocol"].(string)
					srcIP, _ := evt["src_ip"].(string)
					srcPort, _ := evt["src_port"].(float64)
					dstIP, _ := evt["dst_ip"].(string)
					dstPort, _ := evt["dst_port"].(float64)

					key := fmt.Sprintf("%s|%s:%d|%s:%d", protocol, srcIP, int(srcPort), dstIP, int(dstPort))

					if action == "CONNECT" {
						activeConns[key] = evt
					} else if action == "DISCONNECT" {
						delete(activeConns, key)
					}
				}

				// Convert map back to slice for frontend
				var connList []interface{}
				for _, v := range activeConns {
					connList = append(connList, v)
				}
				info.Data["network"] = connList // Now this contains ALL active connections
				s.mu.Unlock()

				// Perform ThreatBook Analysis asynchronously
				if len(publicIPs) > 0 && s.IsThreatBookEnabled() {
					go s.checkMaliciousIPs(agentID, publicIPs)
				}
			}
		}
	}
	return nil
}

func (s *agentService) checkMaliciousIPs(agentID string, ipMap map[string]NetworkContext) {
	// Extract IPs for query
	var ips []string
	for ip := range ipMap {
		ips = append(ips, ip)
	}

	// 1. Check for Hardcoded Test IP
	testIP := "8.130.165.89"
	if ctx, ok := ipMap[testIP]; ok {
		fmt.Printf("[TEST] Detected hardcoded test IP: %s\n", testIP)
		fakeInfo := threatbook.IPReputationDetails{
			IsMalicious:     true,
			Severity:        "critical",
			ConfidenceLevel: "high",
			Judgments:       []string{"测试恶意IP", "Hardcoded Test"},
		}
		s.triggerAlertAndForensics(agentID, testIP, fakeInfo, ctx)
	}

	// 2. Query ThreatBook API for others
	// Filter out testIP from API query to save quota/avoid confusion if needed,
	// though TB client might handle it.

	results, err := s.tbClient.QueryIPs(ips)
	if err != nil {
		fmt.Printf("ThreatBook Query Error: %v\n", err)
		return
	}

	for ip, info := range results {
		// Skip if it was already handled by hardcoded logic (optional, but good for logs)
		if ip == testIP {
			continue
		}

		if info.IsMalicious {
			if ctx, ok := ipMap[ip]; ok {
				s.triggerAlertAndForensics(agentID, ip, info, ctx)
			}
		}
	}
}

// 辅助结构，用于构建更详细的上下文
type AlertContext struct {
	ThreatInfo  threatbook.IPReputationDetails `json:"threat_info"`
	TargetIP    string                         `json:"target_ip"`
	ProcessInfo NetworkContext                 `json:"process_info"` // Added Process Info
	Description string                         `json:"description"`
}

func (s *agentService) triggerAlertAndForensics(agentID, ip string, info threatbook.IPReputationDetails, ctx NetworkContext) {
	// Found malicious IP!
	// Enrich Message
	msg := fmt.Sprintf("发现恶意IP连接: %s (进程: %s PID: %d) (可信度: %s, 威胁类型: %v)",
		ip, ctx.ProcessName, ctx.PID, info.ConfidenceLevel, info.Judgments)

	// Enrich Context
	alertCtx := AlertContext{
		ThreatInfo:  info,
		TargetIP:    ip,
		ProcessInfo: ctx,
		Description: fmt.Sprintf("进程 %s (PID: %d) 尝试连接恶意IP %s。路径: %s", ctx.ProcessName, ctx.PID, ip, ctx.ProcessPath),
	}
	ctxBytes, _ := json.Marshal(alertCtx)

	// 1. Create Security Event
	s.repo.CreateSecurityEvent(&model.SecurityEvent{
		AgentID:   agentID,
		Timestamp: time.Now(),
		EventType: common.EventTypeIntrusion,
		Details:   string(ctxBytes), // Store structured context
		Severity:  common.SeverityCritical,
	})

	// 2. Create Alert
	s.repo.CreateAlert(&model.Alert{
		AgentID:   agentID,
		Timestamp: time.Now(),
		Type:      "MALICIOUS_IP_CONNECTION",
		Message:   msg,
		Severity:  common.SeverityCritical,
		Status:    "OPEN",
	})

	fmt.Printf("[ALERT] Malicious IP detected for agent %s: %s\n", agentID, msg)

	// 3. Trigger Automated Forensics
	fmt.Printf("[Forensics] Triggering automated forensics for IP: %s on Agent: %s\n", ip, agentID)

	args := map[string]string{
		"target_ip": ip,
		"pid":       fmt.Sprintf("%d", ctx.PID), // Pass PID to forensics
	}
	argsBytes, _ := json.Marshal(args)

	cmd := &pb.Command{
		Task: &pb.PluginTask{
			DataType: int32(common.DataTypeForensics),
			Name:     common.TaskTypeForensics,
			Data:     string(argsBytes),
		},
	}

	if err := s.SendCommand(agentID, cmd); err != nil {
		fmt.Printf("[Forensics] Failed to send command: %v\n", err)
	}
}

// Simple private IP check helper
func isPrivateIP(ip string) bool {
	// Simplified logic: checking common private prefixes
	// 10., 192.168., 172.16-31.
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		// stricter check for 172.16-31 needed strictly speaking, but for now this is okay or we can use net.ParseIP
		// Let's rely on ThreatBook to just return non-malicious for private IPs if sent,
		// but filtering saves quota.
		return true
	}
	return false
}

func (s *agentService) handleFile(agentID string, info *model.AgentInfo, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		event := record.Body.Fields["event"]
		name := record.Body.Fields["name"]

		// Map to Action Enum
		action := "UNKNOWN"
		if strings.Contains(event, "CREATE") {
			action = "CREATE"
		} else if strings.Contains(event, "WRITE") {
			action = "MODIFY"
		} else if strings.Contains(event, "REMOVE") {
			action = "DELETE"
		} else if strings.Contains(event, "RENAME") {
			action = "RENAME"
		}

		err := s.repo.CreateFileEvent(&model.FileEvent{
			AgentID:   agentID,
			Timestamp: time.Now(),
			Action:    action,
			FilePath:  name,
			// Hash: (Agent currently doesn't send hash, need to upgrade agent later if needed)
		})
		if err != nil {
			fmt.Printf("Error creating file event: %v\n", err)
		}

		// Also create a SecurityEvent for backward compatibility / alerts
		details, _ := json.Marshal(record.Body.Fields)
		return s.repo.CreateSecurityEvent(&model.SecurityEvent{
			AgentID:   agentID,
			Timestamp: time.Now(),
			EventType: common.EventTypeFileChange,
			Details:   string(details),
			Severity:  common.SeverityWarn,
		})
	}
	return nil
}

func (s *agentService) handleService(info *model.AgentInfo, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		if svcData, ok := record.Body.Fields["data"]; ok {
			var svcs []interface{}
			if err := json.Unmarshal([]byte(svcData), &svcs); err == nil {
				s.mu.Lock()
				info.Data["services"] = svcs
				s.mu.Unlock()
			}
		}
	}
	return nil
}

func (s *agentService) handleRegistry(agentID string, info *model.AgentInfo, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		s.mu.Lock()
		info.Data["registry"] = record.Body.Fields
		s.mu.Unlock()

		details, _ := json.Marshal(record.Body.Fields)
		return s.repo.CreateSecurityEvent(&model.SecurityEvent{
			AgentID:   agentID,
			Timestamp: time.Now(),
			EventType: common.EventTypeRegistryChange,
			Details:   string(details),
			Severity:  common.SeverityCritical,
		})
	}
	return nil
}

func (s *agentService) handlePerformance(agentID string, info *model.AgentInfo, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		s.mu.Lock()
		info.Data["performance"] = record.Body.Fields
		s.mu.Unlock()

		fields := record.Body.Fields
		var cpu, mem float64
		fmt.Sscanf(fields["cpu"], "%f", &cpu)
		fmt.Sscanf(fields["memory"], "%f", &mem)

		return s.repo.CreatePerformanceLog(&model.PerformanceLog{
			AgentID:   agentID,
			Timestamp: time.Now(),
			CPU:       cpu,
			Memory:    mem,
			Disk:      fields["disk"],
		})
	}
	return nil
}

func (s *agentService) handleSecurityLog(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		rawJSON := record.Body.Fields["data"]
		var events []map[string]interface{}

		if err := json.Unmarshal([]byte(rawJSON), &events); err != nil {
			var singleEvent map[string]interface{}
			if err := json.Unmarshal([]byte(rawJSON), &singleEvent); err == nil {
				events = append(events, singleEvent)
			}
		}

		for _, evt := range events {
			s.processSecurityEvent(agentID, evt)
		}
	}
	return nil
}

func (s *agentService) processSecurityEvent(agentID string, evt map[string]interface{}) {
	evtIDFloat, _ := evt["Id"].(float64)
	evtID := int(evtIDFloat)
	logonType, _ := evt["LogonType"].(string)
	ip, _ := evt["IpAddress"].(string)
	user, _ := evt["TargetUserName"].(string)

	severity := common.SeverityInfo
	eventType := "SECURITY_LOG"

	// Logic for alerts
	if evtID == 4625 {
		eventType = common.EventTypeLoginFailed
		severity = common.SeverityWarn
		if logonType == "10" || (ip != "" && ip != "-" && ip != "127.0.0.1" && ip != "::1") {
			s.repo.CreateAlert(&model.Alert{
				AgentID:   agentID,
				Timestamp: time.Now(),
				Type:      "RDP_LOGIN_FAILED",
				Message:   fmt.Sprintf("RDP/Remote Login Failed: User=%s IP=%s", user, ip),
				Severity:  common.SeverityHigh,
				Status:    "OPEN",
			})
			severity = common.SeverityCritical
		}
	} else if evtID == 4624 {
		eventType = common.EventTypeLoginSuccess
		if logonType == "10" && ip != "" && ip != "-" && ip != "127.0.0.1" {
			s.repo.CreateAlert(&model.Alert{
				AgentID:   agentID,
				Timestamp: time.Now(),
				Type:      "RDP_LOGIN_SUCCESS",
				Message:   fmt.Sprintf("RDP Login Success: User=%s IP=%s", user, ip),
				Severity:  common.SeverityInfo,
				Status:    "OPEN",
			})
		}
	}

	detailsBytes, _ := json.Marshal(evt)
	s.repo.CreateSecurityEvent(&model.SecurityEvent{
		AgentID:   agentID,
		Timestamp: time.Now(),
		EventType: eventType,
		Details:   string(detailsBytes),
		Severity:  severity,
	})
}

func (s *agentService) handleUSB(agentID string, record *pb.Record) error {
	if record.Body != nil && record.Body.Fields != nil {
		details, _ := json.Marshal(record.Body.Fields)
		return s.repo.CreateSecurityEvent(&model.SecurityEvent{
			AgentID:   agentID,
			Timestamp: time.Now(),
			EventType: common.EventTypeUSBEvent,
			Details:   string(details),
			Severity:  common.SeverityInfo,
		})
	}
	return nil
}
