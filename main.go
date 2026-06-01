package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	adminpkg "mitm-proxy/internal/admin"
	capkg "mitm-proxy/internal/ca"
	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	proxypkg "mitm-proxy/internal/proxy"
	"mitm-proxy/internal/store"
)

const (
	restartAdminTokenEnv = "MITM_PROXY_RESTART_ADMIN_TOKEN"
	restartDelayEnv      = "MITM_PROXY_RESTART_DELAY_MS"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	startedAt := time.Now()

	// Command-line flags
	configPath := flag.String("config", "", "Path to config.json file")
	listenAddr := flag.String("listen", "", "Listen address (overrides config)")
	caCertPath := flag.String("ca-cert", "", "Path to existing CA certificate (overrides config)")
	caKeyPath := flag.String("ca-key", "", "Path to existing CA key (overrides config)")
	enableMITM := flag.Bool("mitm", true, "Enable MITM interception (overrides config)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging (overrides config)")
	adminEnabled := flag.Bool("admin-enabled", true, "Enable local admin API/dashboard")
	adminAddr := flag.String("admin-addr", "127.0.0.1:9090", "Admin API/dashboard listen address")
	adminToken := flag.String("admin-token", "", "Admin bearer token (generated when admin is enabled and token is empty)")
	adminReadToken := flag.String("admin-read-token", "", "Read-only admin bearer token")
	adminUI := flag.Bool("admin-ui", true, "Serve embedded admin UI")
	adminStore := flag.String("admin-store", "dashboard.db", "Admin SQLite store path")

	// Default for --watch-config is centralized here for easy future changes
	const defaultWatchConfig = true

	watchConfig := flag.Bool("watch-config", defaultWatchConfig, "Watch config.json for changes and auto-apply (default true)")

	flag.Parse()
	if delay := restartDelay(); delay > 0 {
		log.Printf("Delaying startup for restart handoff: %s", delay)
		time.Sleep(delay)
	}
	_ = os.Unsetenv(restartDelayEnv)
	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

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

	if setFlags["admin-enabled"] {
		config.AdminEnabled = *adminEnabled
	}
	if setFlags["admin-addr"] {
		config.AdminAddr = *adminAddr
	}
	if setFlags["admin-token"] {
		config.AdminToken = *adminToken
	}
	if setFlags["admin-read-token"] {
		config.AdminReadToken = *adminReadToken
	}
	if setFlags["admin-ui"] {
		config.AdminUI = *adminUI
	}
	if setFlags["admin-store"] {
		config.AdminStore = *adminStore
	}

	cacheStore, err := store.Open(config.AdminStore)
	if err != nil {
		log.Fatalf("failed to open SQLite cache store: %v", err)
	}
	defer cacheStore.Close()

	eventBus := events.NewBus(256)
	proxy := proxypkg.NewWithEvents(ca, config, eventBus)
	proxy.SetCacheStore(cacheStore)
	var proxyServer *http.Server
	var adminServer *adminpkg.Server
	var restartMu sync.Mutex
	restartStarted := false

	if config.AdminEnabled {
		token := config.AdminToken
		generatedAuth := false
		restoredAuth := false
		if token == "" {
			if restartToken := strings.TrimSpace(os.Getenv(restartAdminTokenEnv)); restartToken != "" {
				token = restartToken
				generatedAuth = true
				restoredAuth = true
			} else {
				var err error
				token, err = adminpkg.GenerateToken()
				if err != nil {
					log.Fatalf("failed to generate admin token: %v", err)
				}
				generatedAuth = true
			}
		}
		_ = os.Unsetenv(restartAdminTokenEnv)
		config.AdminToken = token

		adminServer = adminpkg.New(adminpkg.Options{
			Addr:          config.AdminAddr,
			Token:         token,
			ReadToken:     config.AdminReadToken,
			UIEnabled:     config.AdminUI,
			Store:         cacheStore,
			Config:        proxy.CurrentConfig,
			ConfigPath:    cfgPathForDisplay(*configPath),
			ProxyVersion:  "dev",
			ProxyStarted:  startedAt,
			GeneratedAuth: generatedAuth,
			ThreatScanner: proxy.ThreatScanner(),
			EventBus:      eventBus,
			SaveConfig: func(_ context.Context, cfg *cfgpkg.Config) error {
				path := cfgPathForWrite(*configPath)
				toWrite := *cfg
				if generatedAuth {
					toWrite.AdminToken = ""
				}
				data, err := json.MarshalIndent(toWrite, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal config: %w", err)
				}
				data = append(data, '\n')
				if err := os.WriteFile(path, data, 0600); err != nil {
					return fmt.Errorf("write config %s: %w", path, err)
				}
				eventBus.Publish(events.Event{
					Topic: events.TopicConfigUpdated,
					Time:  time.Now().UTC(),
					Payload: map[string]any{
						"path":   path,
						"source": "admin.settings.persist",
					},
				})
				return nil
			},
			ApplyConfig: proxy.SetConfig,
			ReloadConfig: func(ctx context.Context) error {
				path := cfgPathForDisplay(*configPath)
				if path == "" {
					return fmt.Errorf("no config file is available to reload")
				}
				newCfg, err := cfgpkg.Load(path)
				if err != nil {
					return err
				}
				applyCLIOverrides(newCfg, *listenAddr, *caCertPath, *caKeyPath, *enableMITM, *verbose)
				if setFlags["admin-enabled"] {
					newCfg.AdminEnabled = *adminEnabled
				}
				if setFlags["admin-addr"] {
					newCfg.AdminAddr = *adminAddr
				}
				newCfg.AdminToken = token
				if setFlags["admin-read-token"] {
					newCfg.AdminReadToken = *adminReadToken
				}
				if setFlags["admin-ui"] {
					newCfg.AdminUI = *adminUI
				}
				if setFlags["admin-store"] {
					newCfg.AdminStore = *adminStore
				}
				proxy.SetConfig(newCfg)
				eventBus.Publish(events.Event{
					Topic: events.TopicConfigUpdated,
					Time:  time.Now().UTC(),
					Payload: map[string]any{
						"path": path,
					},
				})
				return nil
			},
			Restart: func(ctx context.Context) error {
				restartMu.Lock()
				if restartStarted {
					restartMu.Unlock()
					return nil
				}
				if err := spawnRestartProcess(token); err != nil {
					restartMu.Unlock()
					log.Printf("restart spawn failed: %v", err)
					return err
				}
				restartStarted = true
				restartMu.Unlock()
				go func() {
					time.Sleep(250 * time.Millisecond)
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if adminServer != nil {
						_ = adminServer.Shutdown(shutdownCtx)
					}
					if proxyServer != nil {
						_ = proxyServer.Shutdown(shutdownCtx)
					}
				}()
				return nil
			},
			RotateCA: func(ctx context.Context) error {
				newCA, err := capkg.Rotate(proxy.CurrentConfig())
				if err != nil {
					return err
				}
				proxy.SetCA(newCA)
				eventBus.Publish(events.Event{
					Topic: events.TopicCertGenerated,
					Time:  time.Now().UTC(),
					Payload: map[string]any{
						"host": "CA",
					},
				})
				return nil
			},
			ImportCA: func(ctx context.Context, certPath, keyPath string) error {
				newCA, err := capkg.LoadFromFiles(certPath, keyPath)
				if err != nil {
					return err
				}
				cfg := proxy.CurrentConfig()
				cfg.CACertPath = certPath
				cfg.CAKeyPath = keyPath
				proxy.SetCA(newCA)
				return nil
			},
			PublishEvent: eventBus.Publish,
		})

		go func() {
			log.Printf("Admin API/dashboard listening on http://%s/admin/", config.AdminAddr)
			if restoredAuth {
				log.Printf("Restored generated admin token from restart handoff")
			} else if generatedAuth {
				log.Printf("Generated admin token: %s", token)
			}
			if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("admin server error: %v", err)
			}
		}()
	}

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
						eventBus.Publish(events.Event{
							Topic: events.TopicConfigUpdated,
							Time:  time.Now().UTC(),
							Payload: map[string]any{
								"path": path,
							},
						})
						log.Printf("Applied updated configuration from %s", path)
					}
				}
			}
		}(cfgPathToWatch)
	}

	proxyServer = &http.Server{
		Addr:    config.ListenAddr,
		Handler: proxy,
	}

	if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

func cfgPathForDisplay(configPath string) string {
	if configPath != "" {
		return configPath
	}
	if _, err := os.Stat("config.json"); err == nil {
		return "config.json"
	}
	return ""
}

func cfgPathForWrite(configPath string) string {
	if configPath != "" {
		return configPath
	}
	return "config.json"
}

func applyCLIOverrides(config *cfgpkg.Config, listenAddr, caCertPath, caKeyPath string, enableMITM, verbose bool) {
	if listenAddr != "" {
		config.ListenAddr = listenAddr
	}
	if caCertPath != "" {
		config.CACertPath = caCertPath
	}
	if caKeyPath != "" {
		config.CAKeyPath = caKeyPath
	}
	if !enableMITM {
		config.EnableMITM = false
	}
	if verbose {
		config.VerboseLogging = true
	}
}

func restartDelay() time.Duration {
	raw := strings.TrimSpace(os.Getenv(restartDelayEnv))
	if raw == "" {
		return 0
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return 0
	}
	if ms > 10000 {
		ms = 10000
	}
	return time.Duration(ms) * time.Millisecond
}

func spawnRestartProcess(adminToken string) error {
	if strings.TrimSpace(adminToken) == "" {
		return fmt.Errorf("admin token is required for restart handoff")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(),
		restartAdminTokenEnv+"="+adminToken,
		restartDelayEnv+"=750",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start replacement process: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release replacement process: %w", err)
	}
	log.Printf("Started replacement process pid=%d", cmd.Process.Pid)
	return nil
}
