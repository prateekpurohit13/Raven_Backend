package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/RavenSec10/Raven_Backend/db"
	"github.com/RavenSec10/Raven_Backend/internal/routes"
	"github.com/RavenSec10/Raven_Backend/internal/services"
)

func main() {
	mongoInstance, err := db.ConnectDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer mongoInstance.CloseDB(ctx)

	piiService, err := services.NewPIIService(mongoInstance)
	if err != nil {
		log.Fatalf("Failed to initialize PII service: %v", err)
	}

	kafkaBrokerAddress := "localhost:9093"
	kafkaTopic := "api_logs"
	kafkaGroupID := "raven-backend-consumer-group"
	kafkaConsumerService := services.NewKafkaConsumerService(kafkaBrokerAddress, kafkaTopic, kafkaGroupID, piiService, mongoInstance)

	go kafkaConsumerService.Start(ctx)

	router := gin.Default()

	routes.SetupRoutes(router)

	srv := &http.Server{
		Addr:    ":7000",
		Handler: router,
	}

	go func() {
		log.Println("Server running on :7000")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server and Kafka consumer...")

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server and Kafka consumer exited properly.")
}