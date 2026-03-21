package collector

import (
	"gohids/internal/agent/config"
	pb "gohids/pkg/protocol"
	"log"
	"net"
	"os"
	"sync"

	"github.com/shirou/gopsutil/v3/host"
)

type Collector interface {
	Name() string
	Start(ch chan<- *pb.RawData)
	Stop()
}

type Manager struct {
	collectors []Collector
	dataCh     chan *pb.RawData
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func NewManager(ch chan *pb.RawData) *Manager {
	return &Manager{
		collectors: make([]Collector, 0),
		dataCh:     ch,
		stopCh:     make(chan struct{}),
	}
}

func (m *Manager) Register(c Collector) {
	m.collectors = append(m.collectors, c)
}

func (m *Manager) StartAll() {
	for _, c := range m.collectors {
		m.wg.Add(1)
		go func(col Collector) {
			defer m.wg.Done()
			log.Printf("Starting collector: %s", col.Name())
			col.Start(m.dataCh)
		}(c)
	}
}

func (m *Manager) StopAll() {
	close(m.stopCh)
	for _, c := range m.collectors {
		c.Stop()
	}
	m.wg.Wait()
}

// Global cache for static info
var (
	cachedOS      string
	cachedVersion string
	infoOnce      sync.Once
)

// Helper for basic info
func getBasicInfo() (string, string, []string) {
	hostname, _ := os.Hostname()

	// Cache OS info as it doesn't change
	infoOnce.Do(func() {
		h, err := host.Info()
		if err == nil {
			cachedOS = h.Platform + " " + h.PlatformVersion
			cachedVersion = h.KernelVersion
		} else {
			cachedOS = "Unknown"
			cachedVersion = "Unknown"
		}
	})

	// IPs might change, check every time (or cache with expiry)
	// Filter for valid IPv4 non-loopback
	addrs, _ := net.InterfaceAddrs()
	var validIPs []string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				validIPs = append(validIPs, ipnet.IP.String())
			}
		}
	}

	return hostname, cachedOS, validIPs
}

func createRawData(dataType int32, fields map[string]string) *pb.RawData {
	hostname, osInfo, ips := getBasicInfo()

	// If OS info is missing (e.g. error), fallback
	product := osInfo
	if product == "" || product == "Unknown" {
		product = "GoAgent"
	}

	return &pb.RawData{
		AgentID:      config.AgentID,
		Hostname:     hostname,
		Product:      product, // Now sends actual OS (e.g. "windows 10.0.19045")
		Version:      "1.0.0", // Agent Version
		IntranetIPv4: ips,
		Data: []*pb.Record{
			{
				DataType:  dataType,
				Timestamp: 0, // Should be set by caller or now
				Body: &pb.Item{
					Fields: fields,
				},
			},
		},
	}
}
