package grpc

import (
	"io"
	"log"
	"net"

	"gohids/internal/server/service"
	pb "gohids/pkg/protocol"

	"google.golang.org/grpc"
)

type Server struct {
	svc service.AgentService
}

func NewServer(svc service.AgentService) *Server {
	return &Server{svc: svc}
}

func (s *Server) Transfer(stream pb.Transfer_TransferServer) error {
	// First message usually contains AgentID (or we wait for first data)
	// We need to register this stream to the service so we can send commands back
	
	// A better way is to wait for the first message to identify the agent
	firstData, err := stream.Recv()
	if err != nil {
		return err
	}
	
	agentID := firstData.AgentID
	s.svc.RegisterAgentStream(agentID, stream)
	defer s.svc.UnregisterAgentStream(agentID)

	// Process first message
	if err := s.svc.ProcessData(agentID, firstData); err != nil {
		log.Printf("Error processing data from %s: %v", agentID, err)
	}

	for {
		data, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Printf("Error receiving from %s: %v", agentID, err)
			return err
		}
		if err := s.svc.ProcessData(data.AgentID, data); err != nil {
			log.Printf("Error processing data from %s: %v", data.AgentID, err)
		}
	}
}

func Run(addr string, svc service.AgentService) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterTransferServer(s, NewServer(svc))
	log.Printf("gRPC server listening at %s", addr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
