// tools/syz-vmtest/main.go
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "comma-separated list of syz-manager config files")
	flagDebug  = flag.Bool("debug", true, "enable vm debug mode")
)

type vmGroup struct {
	name      string
	cfg       *mgrconfig.Config
	pool      *vm.Pool
	instances []*vm.Instance
}

func main() {
	flag.Parse()
	if *flagConfig == "" {
		log.Fatal("-config is required (can be a single file or comma-separated list)")
	}

	// 1. Parse config file list.
	configFiles := splitConfigFiles(*flagConfig)
	if len(configFiles) == 0 {
		log.Fatal("no valid config files specified")
	}

	// 2. Build a context that is cancelled on vm.Shutdown.
	baseCtx := vm.ShutdownCtx()
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()

	var groups []vmGroup

	// 3. For each config, create a pool and one or more instances.
	for _, cfgPath := range configFiles {
		log.Printf("Loading config: %s", cfgPath)

		cfg, err := mgrconfig.LoadFile(cfgPath)
		if err != nil {
			log.Fatalf("load config %q failed: %v", cfgPath, err)
		}

		pool, err := vm.Create(cfg, *flagDebug)
		if err != nil {
			log.Fatalf("create vm pool for %q failed: %v", cfgPath, err)
		}

		if pool.Count() < 1 {
			log.Fatalf("vm pool count is 0 for cfg %q (cfg.Type=%q)", cfgPath, cfg.Type)
		}

		// Create a crash reporter (not used yet, but kept for possible future Instance.Run).
		reporter, err := report.NewReporter(cfg)
		if err != nil {
			log.Fatalf("create reporter for %q failed: %v", cfgPath, err)
		}
		_ = reporter

		group := vmGroup{
			name: cfgPath,
			cfg:  cfg,
			pool: pool,
		}

		// For each config, start as many instances as pool.Count().
		for i := 0; i < pool.Count(); i++ {
			inst, err := pool.Create(ctx, i)
			if err != nil {
				log.Fatalf("create vm instance %d for %q failed: %v", i, cfgPath, err)
			}
			log.Printf("Config %q: VM instance index=%d created.", cfgPath, inst.Index())
			group.instances = append(group.instances, inst)
		}

		groups = append(groups, group)
	}

	// 4. Ensure all instances and pools are closed on exit.
	defer func() {
		for _, g := range groups {
			log.Printf("Shutting down VMs for config %q", g.name)
			for _, inst := range g.instances {
				inst.Close()
			}
			g.pool.Close()
		}
	}()

	log.Printf("All VM groups are created (group count=%d).", len(groups))
	for _, g := range groups {
		log.Printf("Config %q: instances=%d", g.name, len(g.instances))
	}
	log.Printf("You can now SSH into the VMs (depending on each config).")
	log.Printf("Waiting for signal (Ctrl+C or SIGTERM) to shut down all VMs...")

	// 5. Wait for OS signal or vm.Shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %s, shutting down all VMs", sig)
	case <-ctx.Done():
		log.Printf("VM shutdown context cancelled (%v), shutting down all VMs", ctx.Err())
	}

	log.Printf("Done, exiting")
}

func splitConfigFiles(s string) []string {
	raw := strings.Split(s, ",")
	var out []string
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
