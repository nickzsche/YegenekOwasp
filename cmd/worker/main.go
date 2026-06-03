package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/temren/internal/config"
	"github.com/temren/internal/database"
	"github.com/temren/internal/queue"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg := config.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := database.Connect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}
	defer database.Close()
	log.Println("[worker] database connected")

	worker := queue.NewWorker()

	go func() {
		log.Println("[worker] starting scan worker...")
		if err := worker.Run(); err != nil {
			log.Printf("[worker] worker error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[worker] shutting down...")
	cancel()
	return nil
}
