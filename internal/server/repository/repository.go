package repository

import (
	"gohids/internal/server/model"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Repository interface {
	UpsertAgent(agent *model.Agent) error
	CreatePerformanceLog(log *model.PerformanceLog) error
	CreateSecurityEvent(event *model.SecurityEvent) error
	CreateAlert(alert *model.Alert) error
	GetAgents() ([]model.Agent, error)
	GetAlerts(limit int) ([]model.Alert, error)
	GetSecurityEvents(agentID string, limit int) ([]model.SecurityEvent, error)
	CreateProcessEvent(event *model.ProcessEvent) error
	CreateNetworkEvent(event *model.NetworkEvent) error
	CreateFileEvent(event *model.FileEvent) error
	GetProcessEvents(agentID string, limit int) ([]model.ProcessEvent, error)
	GetNetworkEvents(agentID string, limit int) ([]model.NetworkEvent, error)
	GetFileEvents(agentID string, limit int) ([]model.FileEvent, error)
	// User related
	GetUserByUsername(username string) (*model.User, error)
	CreateUser(user *model.User) error

	// Asset related
	UpsertAssetPort(port *model.AssetPort) error
	DeleteAssetPort(agentID string, port uint32, proto string) error
	GetAssetPorts(agentID string) ([]model.AssetPort, error)
	UpsertAssetUser(user *model.AssetUser) error
	DeleteAssetUser(agentID string, username string) error
	GetAssetUsers(agentID string) ([]model.AssetUser, error)
	CreateAssetChange(change *model.AssetChange) error
	GetAssetChanges(agentID string, limit int) ([]model.AssetChange, error)
}

type mysqlRepository struct {
	db *gorm.DB
}

func NewMySQLRepository(dsn string) (Repository, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	// AutoMigrate
	err = db.AutoMigrate(
		&model.Agent{},
		&model.PerformanceLog{},
		&model.SecurityEvent{},
		&model.Alert{},
		&model.User{},
		&model.ProcessEvent{},
		&model.NetworkEvent{},
		&model.FileEvent{},
		&model.AssetPort{},
		&model.AssetUser{},
		&model.AssetChange{},
	)
	if err != nil {
		return nil, err
	}
	return &mysqlRepository{db: db}, nil
}

func (r *mysqlRepository) UpsertAgent(agent *model.Agent) error {
	var existing model.Agent
	result := r.db.First(&existing, "id = ?", agent.ID)
	if result.Error != nil {
		return r.db.Create(agent).Error
	}
	// Update specific fields
	existing.Hostname = agent.Hostname
	existing.LastSeen = agent.LastSeen
	existing.Status = agent.Status
	if agent.IntranetIPv4 != "" {
		existing.IntranetIPv4 = agent.IntranetIPv4
	}
	return r.db.Save(&existing).Error
}

func (r *mysqlRepository) CreatePerformanceLog(log *model.PerformanceLog) error {
	return r.db.Create(log).Error
}

func (r *mysqlRepository) CreateSecurityEvent(event *model.SecurityEvent) error {
	return r.db.Create(event).Error
}

func (r *mysqlRepository) CreateAlert(alert *model.Alert) error {
	return r.db.Create(alert).Error
}

func (r *mysqlRepository) GetAgents() ([]model.Agent, error) {
	var agents []model.Agent
	err := r.db.Find(&agents).Error
	return agents, err
}

func (r *mysqlRepository) GetAlerts(limit int) ([]model.Alert, error) {
	var alerts []model.Alert
	err := r.db.Order("timestamp desc").Limit(limit).Find(&alerts).Error
	return alerts, err
}

func (r *mysqlRepository) GetSecurityEvents(agentID string, limit int) ([]model.SecurityEvent, error) {
	var events []model.SecurityEvent
	query := r.db.Order("timestamp desc")
	if agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	err := query.Limit(limit).Find(&events).Error
	return events, err
}

func (r *mysqlRepository) CreateProcessEvent(event *model.ProcessEvent) error {
	return r.db.Create(event).Error
}

func (r *mysqlRepository) CreateNetworkEvent(event *model.NetworkEvent) error {
	return r.db.Create(event).Error
}

func (r *mysqlRepository) CreateFileEvent(event *model.FileEvent) error {
	return r.db.Create(event).Error
}

func (r *mysqlRepository) GetProcessEvents(agentID string, limit int) ([]model.ProcessEvent, error) {
	var events []model.ProcessEvent
	query := r.db.Order("timestamp desc")
	if agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	err := query.Limit(limit).Find(&events).Error
	return events, err
}

func (r *mysqlRepository) GetNetworkEvents(agentID string, limit int) ([]model.NetworkEvent, error) {
	var events []model.NetworkEvent
	query := r.db.Order("timestamp desc")
	if agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	err := query.Limit(limit).Find(&events).Error
	return events, err
}

func (r *mysqlRepository) GetFileEvents(agentID string, limit int) ([]model.FileEvent, error) {
	var events []model.FileEvent
	query := r.db.Order("timestamp desc")
	if agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	err := query.Limit(limit).Find(&events).Error
	return events, err
}

func (r *mysqlRepository) GetUserByUsername(username string) (*model.User, error) {
	var user model.User
	if err := r.db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *mysqlRepository) CreateUser(user *model.User) error {
	return r.db.Create(user).Error
}

// Asset Implementations

func (r *mysqlRepository) UpsertAssetPort(port *model.AssetPort) error {
	var existing model.AssetPort
	result := r.db.Where("agent_id = ? AND port = ? AND protocol = ?", port.AgentID, port.Port, port.Protocol).First(&existing)
	if result.Error != nil {
		// Create new
		return r.db.Create(port).Error
	}
	// Update
	existing.ProcessName = port.ProcessName
	existing.PID = port.PID
	existing.State = port.State
	existing.UpdatedAt = port.UpdatedAt
	return r.db.Save(&existing).Error
}

func (r *mysqlRepository) DeleteAssetPort(agentID string, port uint32, proto string) error {
	return r.db.Where("agent_id = ? AND port = ? AND protocol = ?", agentID, port, proto).Delete(&model.AssetPort{}).Error
}

func (r *mysqlRepository) GetAssetPorts(agentID string) ([]model.AssetPort, error) {
	var ports []model.AssetPort
	err := r.db.Where("agent_id = ?", agentID).Find(&ports).Error
	return ports, err
}

func (r *mysqlRepository) UpsertAssetUser(user *model.AssetUser) error {
	var existing model.AssetUser
	result := r.db.Where("agent_id = ? AND username = ?", user.AgentID, user.Username).First(&existing)
	if result.Error != nil {
		return r.db.Create(user).Error
	}
	existing.UID = user.UID
	existing.GID = user.GID
	existing.HomeDir = user.HomeDir
	existing.Shell = user.Shell
	existing.UpdatedAt = user.UpdatedAt
	return r.db.Save(&existing).Error
}

func (r *mysqlRepository) DeleteAssetUser(agentID string, username string) error {
	return r.db.Where("agent_id = ? AND username = ?", agentID, username).Delete(&model.AssetUser{}).Error
}

func (r *mysqlRepository) GetAssetUsers(agentID string) ([]model.AssetUser, error) {
	var users []model.AssetUser
	err := r.db.Where("agent_id = ?", agentID).Find(&users).Error
	return users, err
}

func (r *mysqlRepository) CreateAssetChange(change *model.AssetChange) error {
	return r.db.Create(change).Error
}

func (r *mysqlRepository) GetAssetChanges(agentID string, limit int) ([]model.AssetChange, error) {
	var changes []model.AssetChange
	query := r.db.Order("timestamp desc")
	if agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	err := query.Limit(limit).Find(&changes).Error
	return changes, err
}
