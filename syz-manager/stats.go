// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/stat"
)

type Stats struct {
	statCrashes           *stat.Val
	statCrashTypes        *stat.Val
	statSuppressed        *stat.Val
	statUptime            *stat.Val
	statFuzzingTime       *stat.Val
	statAvgBootTime       *stat.Val
	statCoverFiltered     *stat.Val
	statFirstRunInflight  *stat.Val
	statFirstRunThrottled *stat.Val
	statFirstRunQueues    map[string]*stat.Val
	statReproduceQueues   map[string]*stat.Val
}

func (mgr *Manager) initStats() {
	mgr.statCrashes = stat.New("crashes", "Total number of VM crashes",
		stat.Simple, stat.Prometheus("syz_crash_total"))
	mgr.statCrashTypes = stat.New("crash types", "Number of unique crashes types",
		stat.Simple, stat.NoGraph)
	mgr.statSuppressed = stat.New("suppressed", "Total number of suppressed VM crashes",
		stat.Simple, stat.Graph("crashes"))
	mgr.statFuzzingTime = stat.New("fuzzing", "Total fuzzing time in all VMs (seconds)",
		stat.NoGraph, func(v int, period time.Duration) string { return fmt.Sprintf("%v sec", v/1e9) })
	mgr.statUptime = stat.New("uptime", "Total uptime (seconds)", stat.Simple, stat.NoGraph,
		func() int {
			firstConnect := mgr.firstConnect.Load()
			if firstConnect == 0 {
				return 0
			}
			return int(time.Now().Unix() - firstConnect)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})
	mgr.statAvgBootTime = stat.New("instance restart", "Average VM restart time (sec)",
		stat.NoGraph,
		func() int {
			if pool := mgr.runtime.Pool(); pool != nil {
				return int(pool.BootTime.Value().Seconds())
			}
			return 0
		},
		func(v int, _ time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})

	stat.New("heap", "Process heap size (bytes)", stat.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Alloc)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stat.New("VM", "Process VM size (bytes)", stat.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Sys - ms.HeapReleased)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stat.New("images memory", "Uncompressed images memory (bytes)", stat.Graph("memory"),
		func() int {
			return int(image.StatMemory.Load())
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stat.New("uncompressed images", "Total number of uncompressed images in memory",
		func() int {
			return int(image.StatImages.Load())
		})
	mgr.statCoverFiltered = stat.New("filtered coverage", "", stat.NoGraph)
	mgr.initMultiRuntimeStats()
}

func (mgr *Manager) initMultiRuntimeStats() {
	coord := mgr.programRegistry
	if coord == nil {
		return
	}
	const queueGraph = "multi-runtime queues"
	mgr.statFirstRunInflight = stat.New("multi-runtime first-run inflight",
		"Programs waiting for initial results from all runtimes",
		stat.Simple, stat.Graph(queueGraph),
		stat.Prometheus("syz_multi_runtime_first_run_inflight"),
		func() int {
			return coord.statsSnapshot().FirstRunInflight
		})
	mgr.statFirstRunThrottled = stat.New("multi-runtime first-run throttled",
		"Whether generation of new multi-runtime fuzz programs is paused",
		stat.Simple, stat.NoGraph,
		stat.Prometheus("syz_multi_runtime_first_run_throttled"),
		func() int {
			if coord.statsSnapshot().FirstRunThrottled {
				return 1
			}
			return 0
		}, func(value int, _ time.Duration) string {
			if value != 0 {
				return "yes"
			}
			return "no"
		})

	mgr.statFirstRunQueues = make(map[string]*stat.Val)
	mgr.statReproduceQueues = make(map[string]*stat.Val)
	for _, slot := range mgr.runtimeList() {
		runtimeName := slot.name
		mgr.statFirstRunQueues[runtimeName] = stat.New(
			"first-run queue ["+runtimeName+"]",
			"Initial programs waiting to be issued to this runtime",
			stat.Simple, stat.Graph(queueGraph),
			stat.Prometheus(multiRuntimePrometheusName(
				"syz_multi_runtime_first_run_queue", runtimeName)),
			func() int {
				return coord.statsSnapshot().Queues[runtimeName].FirstRun
			})
		mgr.statReproduceQueues[runtimeName] = stat.New(
			"reproduce queue ["+runtimeName+"]",
			"Multi-runtime validation reproductions waiting for this runtime",
			stat.Simple, stat.Graph(queueGraph),
			stat.Prometheus(multiRuntimePrometheusName(
				"syz_multi_runtime_reproduce_queue", runtimeName)),
			func() int {
				return coord.statsSnapshot().Queues[runtimeName].Repro
			})
	}
}

func multiRuntimePrometheusName(base, runtimeName string) string {
	var ret strings.Builder
	ret.WriteString(base)
	ret.WriteByte('_')
	for _, ch := range runtimeName {
		switch {
		case ch >= 'a' && ch <= 'z',
			ch >= 'A' && ch <= 'Z',
			ch >= '0' && ch <= '9',
			ch == '_':
			ret.WriteRune(ch)
		default:
			ret.WriteByte('_')
		}
	}
	return ret.String()
}
