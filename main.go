package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	capkg "mitm-proxy/internal/ca"
	cfgpkg "mitm-proxy/internal/config"
	proxypkg "mitm-proxy/internal/proxy"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Command-line flags
	configPath := flag.String("config", "", "Path to config.json file")
	listenAddr := flag.String("listen", "", "Listen address (overrides config)")
	caCertPath := flag.String("ca-cert", "", "Path to existing CA certificate (overrides config)")
	caKeyPath := flag.String("ca-key", "", "Path to existing CA key (overrides config)")
	enableMITM := flag.Bool("mitm", true, "Enable MITM interception (overrides config)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging (overrides config)")

	// Default for --watch-config is centralized here for easy future changes
	const defaultWatchConfig = true

	watchConfig := flag.Bool("watch-config", defaultWatchConfig, "Watch config.json for changes and auto-apply (default true)")

	flag.Parse()

	// Load configuration
	config, err := cfgpkg.Load(*configPath)

	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override with CLI flags if provided
	if *listenAddr != "" {
		config.ListenAddr = *listenAddr
	}

	if *caCertPath != "" {
		config.CACertPath = *caCertPath
	}

	if *caKeyPath != "" {
		config.CAKeyPath = *caKeyPath
	}

	if !*enableMITM {
		config.EnableMITM = false
	}

	if *verbose {
		config.VerboseLogging = true
	}

	// Initialize CA
	ca, err := capkg.LoadOrCreate(config)

	if err != nil {
		log.Fatalf("failed to init CA: %v", err)
	}

	// Print startup information
	log.Printf("=== Go MITM Proxy Configuration ===")
	log.Printf("Listen address: %s", config.ListenAddr)
	log.Printf("MITM enabled: %v", config.EnableMITM)

	if len(config.ExcludedDomains) > 0 {
		log.Printf("Excluded domains: %v", config.ExcludedDomains)
	}

	log.Printf("Verbose logging: %v", config.VerboseLogging)
	log.Printf("Request logging: %v", config.LogRequests)
	log.Printf("===================================")

	if config.EnableMITM {
		log.Printf("IMPORTANT: Trust the CA certificate at %s in your browser/OS", config.CACertOutputPath)
	}

	log.Printf("Starting proxy (HTTP + HTTPS, HTTP/1.1 + HTTP/2, ws + wss)")

	proxy := proxypkg.New(ca, config)

	// Determine path to watch (do not honor any watch-related config from config.json)
	var cfgPathToWatch string

	if *configPath != "" {
		cfgPathToWatch = *configPath
	} else {
		if _, err := os.Stat("config.json"); err == nil {
			cfgPathToWatch = "config.json"
		}
	}

	if *watchConfig && cfgPathToWatch != "" {
		// Start a lightweight watcher that polls modtime periodically
		go func(path string) {
			log.Printf("Watching %s for changes...", path)
			var lastModTime time.Time
			var lastSize int64

			// initialize baseline
			if fi, err := os.Stat(path); err == nil {
				lastModTime = fi.ModTime()
				lastSize = fi.Size()
			}

			ticker := time.NewTicker(1 * time.Second)

			defer ticker.Stop()

			for range ticker.C {
				fi, err := os.Stat(path)
				if err != nil {
					// If file temporarily unavailable, skip
					continue
				}

				if fi.ModTime() != lastModTime || fi.Size() != lastSize {
					lastModTime = fi.ModTime()
					lastSize = fi.Size()

					if newCfg, err := cfgpkg.Load(path); err != nil {
						log.Printf("Failed to reload config after change: %v", err)
						continue
					} else {
						// Preserve any CLI overrides that should remain dominant
						if *listenAddr != "" {
							newCfg.ListenAddr = *listenAddr
						}
						if *caCertPath != "" {
							newCfg.CACertPath = *caCertPath
						}
						if *caKeyPath != "" {
							newCfg.CAKeyPath = *caKeyPath
						}
						if !*enableMITM {
							newCfg.EnableMITM = false
						}
						if *verbose {
							newCfg.VerboseLogging = true
						}

						proxy.SetConfig(newCfg)
						log.Printf("Applied updated configuration from %s", path)
					}
				}
			}
		}(cfgPathToWatch)
	}

	server := &http.Server{
		Addr:    config.ListenAddr,
		Handler: proxy,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
