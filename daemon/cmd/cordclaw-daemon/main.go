package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/server"
)

func main() {
	var daemonize bool
	flag.BoolVar(&daemonize, "daemonize", false, "run daemon in background (not yet implemented)")
	flag.Parse()

	if daemonize {
		log.Println("[cordclaw-daemon] --daemonize requested; running foreground process in this build")
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	handler := server.New(cfg, nil)
	defer handler.Close()
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("[cordclaw-daemon] listening on %s", cfg.ListenAddr)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
