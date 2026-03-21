package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"io"
	"log"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// ForensicReport 定义取证结果的 JSON 结构
type ForensicReport struct {
	TargetIP      string   `json:"target_ip"`
	Timestamp     int64    `json:"timestamp"`
	Status        string   `json:"status"` // "FOUND" or "NOT_FOUND"
	PID           int32    `json:"pid"`
	ProcessName   string   `json:"process_name"`
	Executable    string   `json:"executable"`
	CommandLine   string   `json:"command_line"`
	PPID          int32    `json:"ppid"`
	ParentName    string   `json:"parent_name"`
	FileSHA256    string   `json:"file_sha256"`
	LocalAddress  string   `json:"local_address"`
	RemoteAddress string   `json:"remote_address"`
	Error         string   `json:"error,omitempty"`
}

// ForensicCollector 是一个特殊的 Collector，它不定期运行，而是响应任务
type ForensicCollector struct {
	taskCh chan string // 接收恶意 IP 的通道
	outCh  chan<- *pb.RawData
}

var globalForensicCollector *ForensicCollector

func NewForensicCollector() *ForensicCollector {
	c := &ForensicCollector{
		taskCh: make(chan string, 10),
	}
	globalForensicCollector = c
	return c
}

// GetForensicCollector 获取单例，用于外部触发任务
func GetForensicCollector() *ForensicCollector {
	return globalForensicCollector
}

// TriggerForensics 触发一次对指定 IP 的取证
func (c *ForensicCollector) TriggerForensics(maliciousIP string) {
	select {
	case c.taskCh <- maliciousIP:
		log.Printf("[Forensics] Task queued for IP: %s", maliciousIP)
	default:
		log.Printf("[Forensics] Task queue full, dropping task for IP: %s", maliciousIP)
	}
}

func (c *ForensicCollector) Name() string {
	return "Forensics"
}

func (c *ForensicCollector) Start(ch chan<- *pb.RawData) {
	c.outCh = ch
	log.Println("[Forensics] Module started, waiting for tasks...")

	for ip := range c.taskCh {
		log.Printf("[Forensics] Executing forensics for IP: %s", ip)
		report := c.performForensics(ip)
		
		// 发送报告
		reportBytes, _ := json.Marshal(report)
		data := createRawData(common.DataTypeForensics, map[string]string{
			"data": string(reportBytes),
		})
		data.Data[0].Timestamp = time.Now().Unix()
		ch <- data
		log.Printf("[Forensics] Report sent for IP: %s", ip)
	}
}

func (c *ForensicCollector) Stop() {
	close(c.taskCh)
}

// performForensics 执行具体的取证逻辑
func (c *ForensicCollector) performForensics(targetIP string) *ForensicReport {
	report := &ForensicReport{
		TargetIP:  targetIP,
		Timestamp: time.Now().Unix(),
		Status:    "NOT_FOUND",
	}

	// 1. 网络关联：查找与恶意 IP 建立连接的 PID
	// gopsutil 底层在 Windows 上使用了 GetExtendedTcpTable 等 API
	conns, err := net.Connections("inet")
	if err != nil {
		report.Error = fmt.Sprintf("Failed to get connections: %v", err)
		return report
	}

	var targetConn *net.ConnectionStat
	for _, conn := range conns {
		if conn.Raddr.IP == targetIP {
			targetConn = &conn
			break
		}
	}

	if targetConn == nil {
		report.Error = "No active connection found for this IP"
		return report
	}

	report.Status = "FOUND"
	report.PID = targetConn.Pid
	report.LocalAddress = fmt.Sprintf("%s:%d", targetConn.Laddr.IP, targetConn.Laddr.Port)
	report.RemoteAddress = fmt.Sprintf("%s:%d", targetConn.Raddr.IP, targetConn.Raddr.Port)

	// 2. 进程元数据：获取进程详情
	proc, err := process.NewProcess(targetConn.Pid)
	if err != nil {
		report.Error = fmt.Sprintf("Process found (PID %d) but exited or access denied: %v", targetConn.Pid, err)
		return report
	}

	// 尽最大努力获取信息，忽略部分错误
	name, _ := proc.Name()
	report.ProcessName = name

	exe, err := proc.Exe()
	if err == nil {
		report.Executable = exe
		// 4. 静态指纹：计算 Hash
		if hash, err := calculateSHA256(exe); err == nil {
			report.FileSHA256 = hash
		} else {
			log.Printf("[Forensics] Failed to hash file %s: %v", exe, err)
		}
	} else {
		report.Executable = "Access Denied or Unknown"
	}

	cmdline, _ := proc.Cmdline()
	report.CommandLine = cmdline

	// 3. 上下文增强：父进程信息
	ppid, _ := proc.Ppid()
	report.PPID = ppid
	if pproc, err := process.NewProcess(ppid); err == nil {
		pname, _ := pproc.Name()
		report.ParentName = pname
	}

	return report
}

func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
