package main

import (
	"alertkick-poller/checker"
	"alertkick-poller/client"
	"alertkick-poller/config"
	"alertkick-poller/dispatcher"
	"alertkick-poller/health"
	"alertkick-poller/leader"
	"alertkick-poller/resultsink"
	"alertkick-poller/scheduler"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Set via -ldflags at build time
var (
	version   = "1.0.0"
	gitHash   = "unknown"
	gitBranch = "unknown"
	buildTime = "unknown"
)

func main() {
	configFile := flag.String("config", "", "path to config file (optional)")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("[main] configuration error: %v", err)
	}

	hostname, _ := os.Hostname()
	log.Printf("[main] AlertKick Poller v%s starting on %s (mode=%s)", version, hostname, cfg.Mode)
	log.Printf("[main] API URL: %s", cfg.APIURL)
	log.Printf("[main] poll_interval=%ds max_concurrency=%d batch_size=%d batch_interval=%ds",
		cfg.PollInterval, cfg.MaxConcurrency, cfg.BatchSize, cfg.BatchInterval)
	if cfg.Mode == config.ModeKafka {
		log.Printf("[main] kafka brokers=%v region=%s assignments=%s results=%s",
			cfg.KafkaBrokers, cfg.Region, cfg.KafkaAssignmentsTopic, cfg.KafkaResultsTopic)
	}

	// Initialize API client — always used for register + heartbeat; results
	// go through the sink which may or may not be HTTP.
	apiClient := client.NewClient(cfg)

	// Register with API
	log.Printf("[main] registering with API...")
	regResp, err := apiClient.Register(hostname, version)
	if err != nil {
		log.Fatalf("[main] failed to register: %v", err)
	}
	log.Printf("[main] registered as poller %s at location %s (%s)",
		regResp.PollerUUID, regResp.LocationName, regResp.LocationKey)

	pollerUUID := regResp.PollerUUID

	// Start health server with probe targets resolved from config. In
	// kafka mode we probe the brokers; in http mode we probe the api's
	// /livez. /readyz reports degraded if any probe fails.
	healthServer := health.NewServer(cfg.HealthPort)
	healthServer.SetBuild(health.BuildInfo{
		Service:   "alertkick-poller",
		Version:   version,
		GitHash:   gitHash,
		GitBranch: gitBranch,
		BuildTime: buildTime,
	})
	if cfg.Mode == config.ModeKafka {
		healthServer.SetProbeTargets("", cfg.KafkaBrokers)
	} else {
		healthServer.SetProbeTargets(cfg.APIURL, nil)
	}
	healthServer.Start()

	// Result buffer for batch submission (shared by both modes)
	var resultMu sync.Mutex
	resultBuffer := make([]client.CheckResult, 0, cfg.BatchSize)

	// Shutdown coordination: cancel ctx stops all loops; done blocks on workers.
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	// Worker pool for executing checks. Always runs — workers sit idle when
	// we're a follower and no assignments land on checkChan. Cheaper than
	// stopping/starting the pool on leadership transitions.
	checkChan := make(chan *client.MonitorAssignment, cfg.MaxConcurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < cfg.MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range checkChan {
				result := checker.Execute(m, cfg.TLSInsecure)
				healthServer.ChecksExecuted.Add(1)
				if !result.Success {
					healthServer.Errors.Add(1)
				}

				cr := result.ToClientResult(pollerUUID)
				resultMu.Lock()
				resultBuffer = append(resultBuffer, cr)
				resultMu.Unlock()
			}
		}()
	}

	// Active/passive HA: both pollers at a location run this binary, but
	// only the one holding the Mongo-backed lease runs the dispatcher and
	// submits results. Followers keep registering and heartbeating so the
	// fleet can see them, ready to take over on TTL expiry.
	elector := leader.New(apiClient, leader.Config{PollerUUID: pollerUUID})

	// workLifecycle holds the transport + goroutine state that exists only
	// while we're leader. Rebuilt on each leader→follower→leader cycle so
	// the Kafka consumer cleanly leaves its group when we step down and
	// rejoins fresh when we take over again.
	type workLifecycle struct {
		ctx    context.Context
		cancel context.CancelFunc
		disp   dispatcher.Dispatcher
		sink   resultsink.ResultSink
		wg     sync.WaitGroup
	}
	var workMu sync.Mutex
	var work *workLifecycle

	startLeaderWork := func() {
		workMu.Lock()
		defer workMu.Unlock()
		if work != nil {
			return // defensive: already running
		}
		disp, sink, err := buildTransport(cfg, apiClient, regResp, healthServer)
		if err != nil {
			log.Printf("[main] transport setup on leader-acquire failed: %v", err)
			return
		}
		lctx, lcancel := context.WithCancel(ctx)
		work = &workLifecycle{ctx: lctx, cancel: lcancel, disp: disp, sink: sink}

		work.wg.Add(1)
		go func() {
			defer work.wg.Done()
			if err := disp.Run(lctx, checkChan); err != nil {
				log.Printf("[main] dispatcher exited with error: %v", err)
			}
		}()

		work.wg.Add(1)
		go func() {
			defer work.wg.Done()
			ticker := time.NewTicker(time.Duration(cfg.BatchInterval) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-lctx.Done():
					return
				case <-ticker.C:
					flushResults(lctx, sink, pollerUUID, &resultMu, &resultBuffer)
				}
			}
		}()
	}

	// stopLeaderWork does a final drain so in-flight results aren't lost,
	// then closes the transport so the Kafka consumer group rebalances
	// promptly. Safe to call when not running (no-op).
	stopLeaderWork := func() {
		workMu.Lock()
		w := work
		work = nil
		workMu.Unlock()
		if w == nil {
			return
		}
		w.cancel()
		w.wg.Wait()

		// Final flush of whatever was in the buffer. Use a fresh context —
		// w.ctx is already canceled.
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 10*time.Second)
		flushResults(flushCtx, w.sink, pollerUUID, &resultMu, &resultBuffer)
		if err := w.sink.Flush(flushCtx); err != nil {
			log.Printf("[main] sink flush on step-down: %v", err)
		}
		flushCancel()

		if err := w.sink.Close(); err != nil {
			log.Printf("[main] sink close on step-down: %v", err)
		}
		if err := w.disp.Close(); err != nil {
			log.Printf("[main] dispatcher close on step-down: %v", err)
		}

		// Any results that couldn't flush are dropped — we're no longer the
		// authoritative submitter. The new leader will re-run any pending
		// checks through its own pipeline.
		resultMu.Lock()
		if len(resultBuffer) > 0 {
			log.Printf("[main] dropping %d unflushed results on step-down", len(resultBuffer))
			resultBuffer = resultBuffer[:0]
		}
		resultMu.Unlock()
	}

	// Leadership transition consumer — drives start/stop of the work loops.
	go func() {
		for state := range elector.State() {
			switch state {
			case leader.StateLeader:
				log.Printf("[main] role=leader: starting dispatcher and result submitter")
				startLeaderWork()
			case leader.StateFollower:
				log.Printf("[main] role=follower: stopping dispatcher and result submitter")
				stopLeaderWork()
			}
		}
	}()

	// Run the election loop. On ctx cancellation it best-effort releases
	// the lease before returning.
	go elector.Run(ctx)

	// Heartbeat loop
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Liveness beacon: marks the core loop as still iterating so
				// the watchdog can tell a wedged process from a healthy one.
				// Poked before the api call so it reflects loop liveness, not
				// api reachability (the api can be down during a deploy without
				// the poller being wedged).
				healthServer.Beat()

				status := "online"
				resultMu.Lock()
				queueSize := len(resultBuffer)
				resultMu.Unlock()
				if queueSize > cfg.BatchSize {
					status = "busy"
				}

				err := apiClient.Heartbeat(&client.HeartbeatRequest{
					PollerUUID:         pollerUUID,
					Status:             status,
					ChecksExecuted:     healthServer.ChecksExecuted.Load(),
					ChecksPerMinute:    float64(healthServer.ChecksPerMinute.Load()),
					AvgCheckDurationMs: healthServer.AvgCheckDurationMs.Load(),
					Errors:             healthServer.Errors.Load(),
					UptimeSeconds:      healthServer.UptimeSeconds(),
					QueueDepth:         queueSize,
					Version:            version,
				})
				if err != nil {
					log.Printf("[main] heartbeat failed: %v", err)
				}
			}
		}
	}()

	// Mark as ready
	healthServer.SetReady(true)
	log.Printf("[main] poller is ready, health endpoint on :%d", cfg.HealthPort)

	// Liveness watchdog. A wedged poller — every goroutine blocked, e.g. on a
	// stalled stdout write held under the stdlib log mutex during log-driver
	// back-pressure — keeps its TCP health server answering, so Docker reports
	// it "healthy" and restart:unless-stopped never fires; it stays dark until
	// a manual `docker restart`. The heartbeat loop pokes healthServer.Beat()
	// each tick; if that beacon goes stale the process is wedged, so exit and
	// let the supervisor restart us with a fresh stdout pipe. The watchdog
	// touches only atomics + time + os.Exit, so the same wedge cannot block it.
	const (
		watchdogInterval    = 15 * time.Second
		watchdogLivenessTTL = 120 * time.Second // 4 missed 30s heartbeat ticks
	)
	healthServer.SetLivenessTimeout(watchdogLivenessTTL)
	go func() {
		t := time.NewTicker(watchdogInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				age := healthServer.LastBeatAge()
				if age <= watchdogLivenessTTL {
					continue
				}
				// Best-effort log (may itself block if stdout is the wedge),
				// then exit regardless so recovery never depends on logging.
				go log.Printf("[watchdog] heartbeat loop stalled for %s (>%s); exiting for supervisor restart",
					age.Round(time.Second), watchdogLivenessTTL)
				time.Sleep(2 * time.Second)
				os.Exit(1)
			}
		}
	}()

	// Wait for shutdown signal
	<-signals
	log.Printf("[main] received shutdown signal, draining...")

	// Graceful shutdown: stop leader work first so in-flight results get a
	// chance to flush through the (still-valid) transport. Then cancel the
	// root ctx to stop the elector (which releases the lease) and the
	// heartbeat loop.
	stopLeaderWork()
	cancel()

	// Stop the worker pool. Dispatcher is already stopped by stopLeaderWork,
	// so checkChan won't see new work — closing it lets workers drain and exit.
	close(checkChan)

	// Wait for in-flight checks (max 30s).
	shutdownDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		log.Printf("[main] all checks completed")
	case <-time.After(30 * time.Second):
		log.Printf("[main] shutdown timeout, some checks may not have completed")
	}

	// Send final shutting_down heartbeat
	_ = apiClient.Heartbeat(&client.HeartbeatRequest{
		PollerUUID:    pollerUUID,
		Status:        "shutting_down",
		UptimeSeconds: healthServer.UptimeSeconds(),
		Version:       version,
	})

	hbWG.Wait()
	log.Printf("[main] poller shut down gracefully")
}

// buildTransport constructs the dispatcher + result sink pair for the
// configured mode. HTTP mode owns a scheduler internally; Kafka mode gets
// pre-scheduled assignments from apapi so no local scheduler is needed.
func buildTransport(
	cfg *config.Config,
	apiClient *client.Client,
	regResp *client.RegisterResponse,
	healthServer *health.Server,
) (dispatcher.Dispatcher, resultsink.ResultSink, error) {
	switch cfg.Mode {
	case config.ModeHTTP:
		sched := scheduler.NewScheduler()
		disp := dispatcher.NewHTTPDispatcher(
			apiClient,
			sched,
			time.Duration(cfg.PollInterval)*time.Second,
			cfg.MaxConcurrency,
			func(depth int) { healthServer.QueueDepth.Store(int64(depth)) },
		)
		return disp, resultsink.NewHTTPResultSink(apiClient), nil

	case config.ModeKafka:
		groupID := cfg.KafkaGroupID
		if groupID == "" {
			locUUID := cfg.LocationUUID
			if locUUID == "" {
				locUUID = regResp.LocationUUID
			}
			groupID = "poller-" + locUUID
		}
		disp := dispatcher.NewKafkaDispatcher(cfg.KafkaBrokers, cfg.KafkaAssignmentsTopic, groupID)
		sink := resultsink.NewKafkaResultSink(cfg.KafkaBrokers, cfg.KafkaResultsTopic)
		return disp, sink, nil

	default:
		return nil, nil, fmt.Errorf("unsupported poller mode %q", cfg.Mode)
	}
}

// flushResults drains the result buffer through the sink. On failure the
// batch is prepended back to the buffer so the next tick retries it.
func flushResults(
	ctx context.Context,
	sink resultsink.ResultSink,
	pollerUUID string,
	mu *sync.Mutex,
	buf *[]client.CheckResult,
) {
	mu.Lock()
	if len(*buf) == 0 {
		mu.Unlock()
		return
	}
	batch := make([]client.CheckResult, len(*buf))
	copy(batch, *buf)
	*buf = (*buf)[:0]
	mu.Unlock()

	stats, err := sink.Submit(ctx, pollerUUID, batch)
	if err != nil {
		log.Printf("[main] failed to submit %d results: %v", len(batch), err)
		mu.Lock()
		*buf = append(batch, *buf...)
		mu.Unlock()
		return
	}
	log.Printf("[main] submitted %d results (accepted: %d, rejected: %d)",
		len(batch), stats.Accepted, stats.Rejected)
}
