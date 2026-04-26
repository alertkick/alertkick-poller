package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PollerMode selects how the poller receives assignments and submits results.
const (
	ModeHTTP  = "http"  // customer on-prem: HTTP pull + POST results (default)
	ModeKafka = "kafka" // managed system pollers: Kafka consumer + producer
)

// Config holds all poller configuration.
type Config struct {
	PollerToken    string `json:"poller_token"`    // AP_POLLER_TOKEN (required)
	APIURL         string `json:"api_url"`         // AP_API_URL (default: https://app.alertkick.com)
	PollInterval   int    `json:"poll_interval"`   // AP_POLL_INTERVAL — seconds between monitor fetches (default: 60)
	MaxConcurrency int    `json:"max_concurrency"` // AP_MAX_CONCURRENCY — max concurrent checks (default: 50)
	BatchSize      int    `json:"batch_size"`      // AP_BATCH_SIZE — max results per batch POST (default: 100)
	BatchInterval  int    `json:"batch_interval"`  // AP_BATCH_INTERVAL — seconds between batch submissions (default: 10)
	HealthPort     int    `json:"health_port"`     // AP_HEALTH_PORT — local health endpoint port (default: 8089)
	LogLevel       string `json:"log_level"`       // AP_LOG_LEVEL — "debug", "info", "warn", "error" (default: "info")
	TLSInsecure    bool   `json:"tls_insecure"`    // AP_TLS_INSECURE — skip TLS verification for checks (default: false)

	// Mode + Kafka transport (only used when Mode == "kafka"; managed fleet only).
	// Customer on-prem pollers leave these empty and run in HTTP mode.
	Mode                  string   `json:"mode"`                    // AP_POLLER_MODE — "http" or "kafka" (default: "http")
	KafkaBrokers          []string `json:"kafka_brokers"`           // AP_KAFKA_BROKERS — comma-separated host:port list
	KafkaGroupID          string   `json:"kafka_group_id"`          // AP_KAFKA_GROUP_ID — consumer group (default: "poller-<location_uuid>")
	KafkaAssignmentsTopic string   `json:"kafka_assignments_topic"` // AP_KAFKA_ASSIGNMENTS_TOPIC — default: "poller.assignments.<region>"
	KafkaResultsTopic     string   `json:"kafka_results_topic"`     // AP_KAFKA_RESULTS_TOPIC — default: "poller.results.<region>"
	Region                string   `json:"region"`                  // AP_POLLER_REGION — e.g. "hel1", "ash1"
	LocationUUID          string   `json:"location_uuid"`           // AP_POLLER_LOCATION_UUID — optional override; normally derived from token
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		APIURL:         "https://app.alertkick.com",
		PollInterval:   60,
		MaxConcurrency: 50,
		BatchSize:      100,
		BatchInterval:  10,
		HealthPort:     8089,
		LogLevel:       "info",
		TLSInsecure:    false,
		Mode:           ModeHTTP,
	}
}

// Load loads configuration with priority: env vars > config file > defaults.
func Load(configFile string) (*Config, error) {
	cfg := DefaultConfig()

	// Load from file if specified and exists
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err == nil {
			if err := json.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables
	if v := os.Getenv("AP_POLLER_TOKEN"); v != "" {
		cfg.PollerToken = v
	}
	if v := os.Getenv("AP_API_URL"); v != "" {
		cfg.APIURL = strings.TrimRight(v, "/")
	}
	if v := os.Getenv("AP_POLL_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.PollInterval = n
		}
	}
	if v := os.Getenv("AP_MAX_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxConcurrency = n
		}
	}
	if v := os.Getenv("AP_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.BatchSize = n
		}
	}
	if v := os.Getenv("AP_BATCH_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.BatchInterval = n
		}
	}
	if v := os.Getenv("AP_HEALTH_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.HealthPort = n
		}
	}
	if v := os.Getenv("AP_LOG_LEVEL"); v != "" {
		cfg.LogLevel = strings.ToLower(v)
	}
	if v := os.Getenv("AP_TLS_INSECURE"); v != "" {
		cfg.TLSInsecure = v == "true" || v == "1"
	}
	if v := os.Getenv("AP_POLLER_MODE"); v != "" {
		cfg.Mode = strings.ToLower(v)
	}
	if v := os.Getenv("AP_KAFKA_BROKERS"); v != "" {
		cfg.KafkaBrokers = splitAndTrim(v, ",")
	}
	if v := os.Getenv("AP_KAFKA_GROUP_ID"); v != "" {
		cfg.KafkaGroupID = v
	}
	if v := os.Getenv("AP_KAFKA_ASSIGNMENTS_TOPIC"); v != "" {
		cfg.KafkaAssignmentsTopic = v
	}
	if v := os.Getenv("AP_KAFKA_RESULTS_TOPIC"); v != "" {
		cfg.KafkaResultsTopic = v
	}
	if v := os.Getenv("AP_POLLER_REGION"); v != "" {
		cfg.Region = v
	}
	if v := os.Getenv("AP_POLLER_LOCATION_UUID"); v != "" {
		cfg.LocationUUID = v
	}

	// Validate required fields
	if cfg.PollerToken == "" {
		return nil, fmt.Errorf("AP_POLLER_TOKEN is required")
	}
	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")

	// Normalise + validate mode
	if cfg.Mode == "" {
		cfg.Mode = ModeHTTP
	}
	if cfg.Mode != ModeHTTP && cfg.Mode != ModeKafka {
		return nil, fmt.Errorf("invalid AP_POLLER_MODE %q (expected %q or %q)", cfg.Mode, ModeHTTP, ModeKafka)
	}

	if cfg.Mode == ModeKafka {
		if len(cfg.KafkaBrokers) == 0 {
			return nil, fmt.Errorf("AP_KAFKA_BROKERS is required when AP_POLLER_MODE=kafka")
		}
		if cfg.Region == "" {
			return nil, fmt.Errorf("AP_POLLER_REGION is required when AP_POLLER_MODE=kafka")
		}
		if cfg.KafkaAssignmentsTopic == "" {
			cfg.KafkaAssignmentsTopic = "poller.assignments." + cfg.Region
		}
		if cfg.KafkaResultsTopic == "" {
			cfg.KafkaResultsTopic = "poller.results." + cfg.Region
		}
	}

	return cfg, nil
}

// splitAndTrim splits s on sep and trims whitespace from each element,
// dropping empty entries.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
