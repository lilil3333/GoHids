package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gohids/internal/agent/collector"
	"gohids/internal/agent/config"
	"gohids/internal/agent/transport"
	pb "gohids/pkg/protocol"
)

func main() {
	flag.StringVar(&config.ServerIP, "server", "127.0.0.1:8888", "Server IP:Port")
	flag.StringVar(&config.AgentID, "id", "agent-001", "Agent ID")
	flag.Parse()

	// Ensure port is present
	if !strings.Contains(config.ServerIP, ":") {
		config.ServerIP = config.ServerIP + ":8888"
	}

	log.Printf("Starting Agent %s, connecting to %s", config.AgentID, config.ServerIP)

	// Transport
	client := transport.NewClient(config.ServerIP)
	if err := client.Connect(); err != nil {
		log.Printf("Warning: Failed to connect initially: %v", err)
		// We continue, as Send() tries to reconnect
	}
	defer client.Close()

	// Collectors
	dataCh := make(chan *pb.RawData, 100)
	mgr := collector.NewManager(dataCh)

	mgr.Register(collector.NewHeartbeatCollector())
	mgr.Register(collector.NewProcessCollector())
	mgr.Register(collector.NewNetworkCollector())
	mgr.Register(collector.NewPerformanceCollector())

	// Windows specific collectors (assumed strictly windows env for now)
	mgr.Register(collector.NewServiceCollector())
	mgr.Register(collector.NewRegistryCollector())
	mgr.Register(collector.NewSecurityLogCollector())
	mgr.Register(collector.NewUSBCollector())
	mgr.Register(collector.NewPortCollector())     // Added
	mgr.Register(collector.NewUserCollector())     // Added
	mgr.Register(collector.NewBaselineCollector()) // Added: 基线监控
	mgr.Register(collector.NewForensicCollector())

	// File Monitor (Use a specific test directory if possible, or CWD)
	cwd, _ := os.Getwd()
	testDir := cwd // Default to CWD
	// Create a test directory for better visibility of file events
	testMonitorPath := "C:\\GoHIDS_Monitor_Test"
	if err := os.MkdirAll(testMonitorPath, 0755); err == nil {
		testDir = testMonitorPath
		log.Printf("Monitoring dedicated test directory: %s", testDir)
	} else {
		log.Printf("Failed to create test dir, monitoring CWD: %s", cwd)
	}
	mgr.Register(collector.NewFileCollector(testDir))

	mgr.StartAll()

	// Sender Loop
	go func() {
		for data := range dataCh {
			if err := client.Send(data); err != nil {
				log.Printf("Failed to send data: %v", err)
			}
		}
	}()

	// Graceful Stop
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("Stopping agent...")
	mgr.StopAll()
	log.Println("Agent stopped")
}
