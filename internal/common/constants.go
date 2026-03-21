package common

const (
	// Data Types
	DataTypeHeartbeat     = 1
	DataTypeProcess       = 2
	DataTypeNetwork       = 3
	DataTypeFile          = 4
	DataTypeService       = 5
	DataTypeRegistry      = 6
	DataTypePerformance   = 7
	DataTypeSecurityLog   = 8
	DataTypeUSB           = 9
	DataTypeIntrusion     = 10
	DataTypeForensics     = 11
	DataTypeAssetPort     = 12
	DataTypeAssetUser     = 13
	DataTypeAssetSnapshot = 14 // New: 首次/基线数据
	DataTypeAssetChange   = 15 // New: 变更数据

	// Event Types
	EventTypeLoginFailed    = "LOGIN_FAILED"
	EventTypeLoginSuccess   = "LOGIN_SUCCESS"
	EventTypeProcessStart   = "PROCESS_START"
	EventTypeFileChange     = "FILE_CHANGE"
	EventTypeRegistryChange = "REGISTRY_CHANGE"
	EventTypeUSBEvent       = "USB_EVENT"
	EventTypeIntrusion      = "INTRUSION_DETECTION"
	EventTypeForensics      = "FORENSICS_REPORT"

	// Task Names
	TaskTypeForensics = "FORENSICS"

	// Severity
	SeverityInfo     = "INFO"
	SeverityWarn     = "WARN"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)
