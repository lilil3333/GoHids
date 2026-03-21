package main

import (
	"log"

	"gohids/internal/server/api"
	"gohids/internal/server/grpc"
	"gohids/internal/server/repository"
	"gohids/internal/server/service"
	"gohids/pkg/auth"
	"time"
)

func main() {
	// 0. Init Auth (JWT)
	// In production, load secret from env or config file
	auth.InitAuth("your-production-secret-key-change-me", 24*time.Hour)

	// 1. Init DB
	// In a real app, load this from config
	dsn := "hids:hids123@tcp(127.0.0.1:3306)/hids?charset=utf8mb4&parseTime=True&loc=Local"
	repo, err := repository.NewMySQLRepository(dsn)
	if err != nil {
		log.Fatalf("failed to init db: %v", err)
	}

	// 2. Init Service
	svc := service.NewAgentService(repo)

	// Initialize default admin user if not exists
	// Ideally this should be in a migration script or a separate command
	if err := svc.Register("admin", "hids123"); err != nil {
		// Log error only if it's not "user already exists"
		log.Printf("Init admin user: %v", err)
	} else {
		log.Printf("Created default admin user (admin/hids123)")
	}

	// Initialize user 'hids'
	if err := svc.Register("hids", "hids"); err != nil {
		log.Printf("Init hids user: %v", err)
	} else {
		log.Printf("Created user (hids/hids)")
	}

	// 3. Start gRPC Server
	go grpc.Run(":8888", svc)

	// 4. Start HTTP Server
	log.Printf("HTTP server listening at :8080")
	api.Run(":8080", svc, repo)
}
