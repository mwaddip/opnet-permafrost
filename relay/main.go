package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"
)

// envOrDefault returns the env var value if set, otherwise the default.
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrDefaultInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	addr := flag.String("addr", envOrDefault("RELAY_ADDR", ":8080"), "listen address")
	baseURL := flag.String("base-url", envOrDefault("RELAY_BASE_URL", ""), "base URL for session links")
	maxSessions := flag.Int("max-sessions", envOrDefaultInt("RELAY_MAX_SESSIONS", 50), "max concurrent sessions")
	maxParties := flag.Int("max-parties", envOrDefaultInt("RELAY_MAX_PARTIES", 10), "max parties per session")
	maxMsg := flag.Int("max-message", envOrDefaultInt("RELAY_MAX_MESSAGE", 1048576), "max WebSocket message size in bytes")
	maxPerIP := flag.Int("max-per-ip", envOrDefaultInt("RELAY_MAX_PER_IP", 5), "max connections per IP")
	pingInterval := flag.Int("ping-interval", envOrDefaultInt("RELAY_PING_INTERVAL", 30), "WebSocket ping interval in seconds")
	abandonTimeout := flag.Int("abandon-timeout", envOrDefaultInt("RELAY_ABANDON_TIMEOUT", 600), "abandoned session cleanup in seconds")
	flag.Parse()

	limits := &Limits{
		MaxSessions:     *maxSessions,
		MaxParties:      *maxParties,
		MaxMessageBytes: *maxMsg,
		MaxPerIP:        *maxPerIP,
		PingInterval:    time.Duration(*pingInterval) * time.Second,
		AbandonTimeout:  time.Duration(*abandonTimeout) * time.Second,
		ipConns:         make(map[string]int),
	}

	hub := &Hub{
		sessions: make(map[string]*Session),
		limits:   limits,
		baseURL:  *baseURL,
	}

	go hub.cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hub.mu.RLock()
		count := len(hub.sessions)
		hub.mu.RUnlock()
		fmt.Fprintf(w, `{"active":%d}`, count)
	})

	srv := &http.Server{Addr: *addr, Handler: mux}

	go func() {
		log.Printf("relay listening on %s", *addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("relay shut down")
}
