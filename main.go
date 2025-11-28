package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/emil-lohmann/meraki-exporter/collector"
	"github.com/emil-lohmann/meraki-exporter/meraki"
)

// Config holds the application configuration
type Config struct {
	APIKey        string
	OrgID         string
	FetchInterval time.Duration
	ListenAddr    string
	LogLevel      string
}

// loadConfig loads configuration from environment variables
func loadConfig() (*Config, error) {
	apiKey := os.Getenv("MERAKI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("MERAKI_API_KEY environment variable is required")
	}

	orgID := os.Getenv("MERAKI_ORG_ID")
	if orgID == "" {
		return nil, fmt.Errorf("MERAKI_ORG_ID environment variable is required")
	}

	fetchIntervalStr := os.Getenv("FETCH_INTERVAL")
	if fetchIntervalStr == "" {
		fetchIntervalStr = "300" // Default to 5 minutes
	}

	fetchIntervalSec, err := strconv.Atoi(fetchIntervalStr)
	if err != nil {
		return nil, fmt.Errorf("invalid FETCH_INTERVAL: %w", err)
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9100"
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	return &Config{
		APIKey:        apiKey,
		OrgID:         orgID,
		FetchInterval: time.Duration(fetchIntervalSec) * time.Second,
		ListenAddr:    listenAddr,
		LogLevel:      logLevel,
	}, nil
}

// setupLogger configures the logger
func setupLogger(level string) error {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	logLevel, err := log.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	log.SetLevel(logLevel)
	return nil
}

// backgroundFetcher periodically fetches data from the Meraki API
func backgroundFetcher(ctx context.Context, collector *collector.MerakiCollector, interval time.Duration) {
	// Initial fetch
	collector.UpdateData()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping background fetcher")
			return
		case <-ticker.C:
			collector.UpdateData()
		}
	}
}

func main() {
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Setup logger
	if err := setupLogger(config.LogLevel); err != nil {
		log.Fatalf("Failed to setup logger: %v", err)
	}

	log.Info("Starting Meraki Prometheus Exporter")
	log.Infof("Organization ID: %s", config.OrgID)
	log.Infof("Fetch interval: %s", config.FetchInterval)
	log.Infof("Listen address: %s", config.ListenAddr)

	// Create Meraki client
	client := meraki.NewClient(config.APIKey, config.OrgID)

	// Create collector
	merakiCollector := collector.NewMerakiCollector(client)

	// Register collector with Prometheus
	prometheus.MustRegister(merakiCollector)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background fetcher
	go backgroundFetcher(ctx, merakiCollector, config.FetchInterval)

	// Setup HTTP server
	mux := http.NewServeMux()
	
	// Metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())
	
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Root endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		html := `<!DOCTYPE html>
<html>
<head>
	<title>Meraki Exporter</title>
</head>
<body>
	<h1>Meraki Prometheus Exporter</h1>
	<p><a href="/metrics">Metrics</a></p>
	<p><a href="/health">Health</a></p>
</body>
</html>`
		w.Write([]byte(html))
	})

	server := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for errors from the server
	serverErrors := make(chan error, 1)

	// Start HTTP server in a goroutine
	go func() {
		log.Infof("HTTP server listening on %s", config.ListenAddr)
		serverErrors <- server.ListenAndServe()
	}()

	// Channel to listen for interrupt signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a signal or an error
	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)

	case sig := <-shutdown:
		log.Infof("Received signal %v, starting graceful shutdown", sig)

		// Cancel background fetcher
		cancel()

		// Give outstanding requests 30 seconds to complete
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Errorf("Error during shutdown: %v", err)
			server.Close()
		}

		log.Info("Shutdown complete")
	}
}
