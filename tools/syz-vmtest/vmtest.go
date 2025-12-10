// tools/syz-vmtest/main.go
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "path to syz-manager config file")
	flagDebug  = flag.Bool("debug", true, "enable vm debug mode")
)

func main() {
	flag.Parse()
	if *flagConfig == "" {
		log.Fatal("-config is required")
	}

	// 1. Load syz-manager configuration.
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	// 2. Create a VM pool (this does NOT boot any VM yet).
	pool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("create vm pool failed: %v", err)
	}
	defer pool.Close()

	if pool.Count() < 1 {
		log.Fatalf("vm pool count is 0 (cfg.Type=%q)", cfg.Type)
	}

	// 3. Create a crash reporter (used by Instance.Run to parse kernel output).
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("create reporter failed: %v", err)
	}
	_ = reporter // not used yet

	// 4. Build a context that is cancelled on vm.Shutdown.
	baseCtx := vm.ShutdownCtx()
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()

	// 5. Create multiple VM instances according to pool.Count().
	var instances []*vm.Instance
	for i := 0; i < pool.Count(); i++ {
		inst, err := pool.Create(ctx, i)
		if err != nil {
			log.Fatalf("create vm instance %d failed: %v", i, err)
		}
		log.Printf("VM instance %d created.", inst.Index())
		instances = append(instances, inst)
	}

	// 6. Ensure all instances are closed on exit.
	defer func() {
		for _, inst := range instances {
			inst.Close()
		}
	}()

	log.Printf("All VM instances are created (count=%d).", len(instances))
	log.Printf("You can now SSH into the VMs (depending on your config).")
	log.Printf("Waiting for signal (Ctrl+C or SIGTERM) to shut down...")

	// 7. Wait for OS signal or vm.Shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %s, shutting down VMs", sig)
	case <-ctx.Done():
		log.Printf("VM shutdown context cancelled (%v), shutting down VMs", ctx.Err())
	}

	log.Printf("Done, exiting")
}
