# AlertKick Poller

On-premises poller for [AlertKick](https://www.alertkick.com) that lets you monitor private endpoints — internal APIs, intranet services, databases, and anything else not reachable from the public internet.

Deploy the poller inside your network and it connects to your AlertKick account to receive monitor assignments, execute checks locally, and report results back to your dashboard. All check results, alerts, and status pages work exactly the same as cloud-based monitoring — you just get visibility into your private infrastructure too.

**Key features:**
- Monitor private HTTP/HTTPS endpoints, DNS, TCP ports, and SSL certificates
- Runs as a single lightweight binary or Docker container
- Stateless and horizontally scalable — run multiple pollers across locations
- Zero external dependencies — built entirely on the Go standard library
- Secure: only outbound HTTPS to the AlertKick API, no inbound ports required


## How It Works

```
  Your private network
┌─────────────────────────────────────────────────────┐
│  appoller                                           │
│                                                     │
│  ┌──────────────┐    ┌────────────┐                 │
│  │ Monitor Fetch │───▶│ Scheduler  │                 │
│  │  (every 60s)  │    │ (in-memory)│                 │
│  └──────────────┘    └─────┬──────┘                  │
│                            │ due checks (every 1s)   │
│                            ▼                         │
│                     ┌─────────────┐                  │
│                     │ Worker Pool │ (50 goroutines)   │
│                     │  checker.*  │                   │
│                     └──────┬──────┘                   │
│                            │ results                  │
│                            ▼                         │
│  ┌──────────────┐   ┌─────────────┐                  │
│  │  Heartbeat   │   │   Result    │                  │
│  │ (every 30s)  │   │  Batcher    │                  │
│  └──────┬───────┘   │ (every 10s) │                  │
│         │           └──────┬──────┘                   │
│         │                  │                         │
│  ┌──────┴──────────────────┴──────┐                  │
│  │         API Client             │                  │
│  └──────────────┬─────────────────┘                  │
│                 │                                    │
│  Health server (:8089)  /ready  /metrics             │
└─────────────────┼───────────────────────────────────┘
                  │ outbound HTTPS only
                  ▼
          AlertKick Cloud
```

1. The poller registers with your AlertKick account on startup
2. It fetches the list of monitors assigned to its location
3. Checks are executed locally against your private endpoints
4. Results are batched and sent back to the AlertKick API
5. Your dashboard, alerts, and status pages update automatically


## Connecting to Your Account

1. Log in to your [AlertKick dashboard](https://www.alertkick.com)
2. Go to **Settings > Poller Locations**
3. Create a new poller location and generate a token
4. Use the token as `AP_POLLER_TOKEN` when starting the poller

The token must be stored securely — it cannot be retrieved again after generation. Each location supports dual tokens (primary and secondary) for zero-downtime rotation.


## Quick Start

### Using Docker (recommended)

```bash
docker run -d \
  -e AP_POLLER_TOKEN="your-token-here" \
  -e AP_API_URL="https://app.alertkick.com" \
  -p 8089:8089 \
  --restart unless-stopped \
  ghcr.io/alertkick/alertkick-poller:latest
```

### Using Docker Compose

```yaml
services:
  appoller:
    image: ghcr.io/alertkick/alertkick-poller:latest
    restart: unless-stopped
    ports:
      - "8089:8089"
    environment:
      - AP_POLLER_TOKEN=your-token-here
      - AP_API_URL=https://app.alertkick.com
```

### Using the binary

```bash
export AP_POLLER_TOKEN="your-token-here"
export AP_API_URL="https://app.alertkick.com"
./appoller
```

Or with a config file:

```bash
./appoller -config /etc/alertkick/poller.conf
```


## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AP_POLLER_TOKEN` | Yes | — | Token generated from your AlertKick dashboard |
| `AP_API_URL` | No | `https://app.alertkick.com` | AlertKick API URL |
| `AP_POLL_INTERVAL` | No | `60` | Seconds between monitor list fetches |
| `AP_MAX_CONCURRENCY` | No | `50` | Max concurrent check goroutines |
| `AP_BATCH_SIZE` | No | `100` | Max results per batch submission |
| `AP_BATCH_INTERVAL` | No | `10` | Seconds between batch submissions |
| `AP_HEALTH_PORT` | No | `8089` | Port for health/metrics server |
| `AP_LOG_LEVEL` | No | `info` | Log level: debug, info, warn, error |
| `AP_TLS_INSECURE` | No | `false` | Skip TLS cert verification on checks |

### Config File (JSON)

```json
{
  "poller_token": "your-token-here",
  "api_url": "https://app.alertkick.com",
  "poll_interval": 60,
  "max_concurrency": 50,
  "batch_size": 100,
  "batch_interval": 10,
  "health_port": 8089,
  "log_level": "info",
  "tls_insecure": false
}
```

Environment variables override config file values. Both override built-in defaults.


## Check Types

### HTTP / API

Performs an HTTP request and validates the response.

- Methods: GET, POST, PUT, DELETE, PATCH, HEAD (default: GET)
- Custom headers and request body
- Auth: Basic (username/password) or Bearer (token)
- Validates expected status code (default: 200)
- Validates response body contains expected substring
- Follows up to 10 redirects
- Configurable timeout (default: 30s)

### DNS

Resolves DNS records and validates results.

- Record types: A, AAAA, CNAME, MX, TXT, NS (default: A)
- Validates results contain expected host (substring match)
- Configurable timeout (default: 10s)

### TCP

Tests TCP connectivity to a host:port.

- Port from monitor config or parsed from URL
- Connection-only test (no data exchange)
- Configurable timeout (default: 10s)

### SSL

Validates SSL/TLS certificate expiry.

- Checks first certificate in chain
- Default alert threshold: 30 days before expiry
- Configurable threshold per monitor
- Reports: days remaining, expiry date, issuer
- Fails if days remaining <= threshold


## Health Endpoints

Served on port 8089 (configurable via `AP_HEALTH_PORT`). No inbound access required for normal operation — these are for your own container orchestration and debugging.

### GET /ready

Returns `200 ok` when the poller has registered and is executing checks, `503 not ready` otherwise. Use for Docker/Kubernetes health checks.

### GET /metrics

```json
{
  "uptime_seconds": 3600,
  "ready": true,
  "checks_executed": 1542,
  "checks_per_minute": 85,
  "errors": 2,
  "queue_depth": 3,
  "avg_check_duration_ms": 230
}
```


## Network Requirements

The poller only makes **outbound HTTPS requests**:

- To the AlertKick API (registration, monitor fetches, result submission, heartbeats)
- To your private endpoints being monitored

No inbound ports need to be opened. Port 8089 is optional and only used locally for health checks.


## Building from Source

```bash
# Build binary
make build

# Run tests
make test

# Build Docker image
make docker
```

### Manual Build

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o appoller ./cmd/main.go
```

## Project Structure

```
appoller/
├── cmd/
│   └── main.go              # Entry point, goroutine orchestration, shutdown
├── checker/
│   ├── checker.go           # Dispatcher, Result struct
│   ├── http.go              # HTTP/HTTPS check
│   ├── dns.go               # DNS resolution check
│   ├── tcp.go               # TCP connection check
│   └── ssl.go               # SSL certificate expiry check
├── client/
│   └── client.go            # AlertKick API client
├── config/
│   └── config.go            # Config loading from file + env vars
├── health/
│   └── health.go            # Health/readiness/metrics server
├── scheduler/
│   └── scheduler.go         # In-memory check scheduler
├── Dockerfile               # Multi-stage build (golang:1.23-alpine → alpine:3.19)
├── docker-compose.yml       # Example compose config
├── Makefile                  # Build targets
└── go.mod                   # Go 1.23, zero external dependencies
```


## License

This software is proprietary and provided under the [AlertKick Poller License](LICENSE). Use requires an active AlertKick subscription. See the LICENSE file for full terms.
