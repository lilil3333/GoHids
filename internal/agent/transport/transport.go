package transport

import (
	"context"
	"encoding/json"
	"gohids/internal/agent/collector"
	"gohids/internal/agent/config"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"io"
	"log"

	"google.golang.org/grpc"
)

type Client struct {
	serverIP string
	conn     *grpc.ClientConn
	stream   pb.Transfer_TransferClient
}

func NewClient(serverIP string) *Client {
	return &Client{
		serverIP: serverIP,
	}
}

func (c *Client) Connect() error {
	conn, err := grpc.Dial(c.serverIP, grpc.WithInsecure())
	if err != nil {
		return err
	}
	c.conn = conn

	client := pb.NewTransferClient(conn)
	stream, err := client.Transfer(context.Background())
	if err != nil {
		conn.Close()
		return err
	}
	c.stream = stream
	
	// Start receiving commands (tasks) from server in a separate goroutine
	go c.receiveLoop()
	
	return nil
}

func (c *Client) receiveLoop() {
	for {
		if c.stream == nil {
			return
		}
		cmd, err := c.stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Printf("Receive error: %v", err)
			return
		}
		
		// Handle Command
		c.handleCommand(cmd)
	}
}

func (c *Client) handleCommand(cmd *pb.Command) {
	// Logic to handle command
	if cmd.Task != nil {
		log.Printf("Received Task: Name=%s, DataType=%d", cmd.Task.Name, cmd.Task.DataType)
		
		if int(cmd.Task.DataType) == common.DataTypeForensics {
			var args map[string]string
			if err := json.Unmarshal([]byte(cmd.Task.Data), &args); err != nil {
				log.Printf("Failed to parse forensics task args: %v", err)
				return
			}
			
			maliciousIP := args["target_ip"]
			if maliciousIP != "" {
				if fc := collector.GetForensicCollector(); fc != nil {
					fc.TriggerForensics(maliciousIP)
				} else {
					log.Println("Forensic Collector not initialized!")
				}
			}
		}
	} else {
		log.Printf("Received unknown command structure: %v", cmd)
	}
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) Send(data *pb.RawData) error {
	if c.stream == nil {
		// Try to reconnect
		if err := c.Connect(); err != nil {
			return err
		}
	}
	// Enrich common fields if missing
	if data.AgentID == "" {
		data.AgentID = config.AgentID
	}
	return c.stream.Send(data)
}
