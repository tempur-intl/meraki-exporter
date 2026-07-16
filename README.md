# Meraki Prometheus Exporter

A Prometheus exporter for Cisco Meraki that collects metrics from your Meraki organization and exposes them in Prometheus format.

## Features

- **Device health**: per-device availability (`meraki_device_up`)
- **Uplink health**: connection state, packet loss, and latency per uplink
- **Appliance load**: appliance utilization
- **Client counts**: number of clients per network/location
- **VPN health**: VPN peer reachability
- **Exporter self-observability**: fetch success, scrape duration, and per-endpoint error counts

All metrics use `location` (the Meraki network name) as the standard grouping label.

## Quick Start

### Prerequisites

- Meraki API key with read access
- Meraki Organization ID

### Installation

#### From Source

```bash
git clone https://github.com/emil-lohmann/meraki-exporter.git
cd meraki-exporter
go build -o meraki-exporter .
```

#### Using Docker

```bash
docker build -t meraki-exporter .
```

### Configuration

The exporter is configured via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MERAKI_API_KEY` | Yes | - | Your Meraki Dashboard API key |
| `MERAKI_ORG_ID` | No | auto-detect | Your Meraki Organization ID. If unset, the exporter discovers it at startup: it auto-selects when the API key can reach exactly one organization, otherwise it logs the available IDs and exits so you can pick one. |
| `FETCH_INTERVAL` | No | `300` | Data fetch interval in seconds |
| `LISTEN_ADDR` | No | `:9100` | HTTP server listen address |
| `LOG_LEVEL` | No | `info` | Log level (debug, info, warn, error) |

### Getting Your API Key and Organization ID

1. **API Key**: Log into Meraki Dashboard → Profile → API Access → Generate new API key
2. **Organization ID**: Usually not needed — leave `MERAKI_ORG_ID` unset and the exporter will find
   it. If your key can reach several organizations, start the exporter once and it will list their
   IDs and names in the log. (You can also read it from the Dashboard URL: the number after `/o/`,
   e.g. `https://n123.meraki.com/o/456789/` → `456789`.)

## Metrics

### Product metrics

| Metric Name | Type | Description | Labels |
|------------|------|-------------|--------|
| `meraki_device_up` | Gauge | Device availability (1=online, 0 otherwise) | `name`, `location`, `product_type`, `status` |
| `meraki_uplink_up` | Gauge | Uplink connection state (1=active/ready, 0 otherwise) | `name`, `location`, `uplink`, `status` |
| `meraki_uplink_loss_percent` | Gauge | Uplink packet loss percentage (last 5m) | `name`, `location`, `uplink`, `ip` |
| `meraki_uplink_latency_ms` | Gauge | Uplink latency in milliseconds (last 5m) | `name`, `location`, `uplink`, `ip` |
| `meraki_appliance_utilization_percent` | Gauge | Appliance utilization percentage (last 24h) | `name`, `model`, `location` |
| `meraki_network_clients` | Gauge | Number of clients per network/location (last 24h) | `location` |
| `meraki_vpn_peer_reachability` | Gauge | VPN peer reachability (1=reachable, 0=unreachable) | `location`, `peer_location` |

> `location` is the Meraki network name. `name` is the device name; where a device has no name
> configured in the dashboard the exporter falls back to the device serial so series stay unique.
>
> **`meraki_uplink_up` matters for interpreting loss/latency.** Its `status` label distinguishes an
> unplugged port (`not connected`) from a genuine outage (`failed`). An unused WAN port reports 100%
> loss, so filter loss and latency by connection state rather than alerting on them blindly — see
> the uplink queries below.

### Exporter self-observability metrics

| Metric Name | Type | Description | Labels |
|------------|------|-------------|--------|
| `meraki_up` | Gauge | 1 if the last fetch cycle succeeded for all endpoints | - |
| `meraki_scrape_duration_seconds` | Gauge | Duration of the last fetch cycle | - |
| `meraki_last_success_timestamp_seconds` | Gauge | Unix time of the last fully successful fetch | - |
| `meraki_api_request_errors_total` | Counter | Cumulative failed API requests per endpoint | `endpoint` |

### Metrics Endpoints

- `/metrics` - Prometheus metrics endpoint
- `/health` - Health check endpoint (returns `200 OK`)
- `/` - Web UI with links to metrics and health

## Example Queries

### Device & Network Health

```promql
# Devices that are down
meraki_device_up == 0

# Number of devices down per location
count by (location) (meraki_device_up == 0)

# Devices down, broken out by what state they're actually in
count by (location, status) (meraki_device_up == 0)

# Clients per location
meraki_network_clients
```

### Uplinks

```promql
# Uplinks that are genuinely down (ignores unplugged ports)
meraki_uplink_up{status="failed"} == 0

# Packet loss > 1%, but only on uplinks that are actually connected.
# Without the join this is dominated by unused WAN ports reporting 100% loss.
meraki_uplink_loss_percent > 1
  and on (name, location, uplink) meraki_uplink_up == 1

# Latency on connected uplinks only
meraki_uplink_latency_ms
  and on (name, location, uplink) meraki_uplink_up == 1

# Average uplink latency by location
avg by (location) (meraki_uplink_latency_ms)

# How many ports are unplugged per location
count by (location) (meraki_uplink_up{status="not connected"})
```

### Appliances

```promql
# Appliances running hot
meraki_appliance_utilization_percent > 80

# Highest utilization per location
max by (location) (meraki_appliance_utilization_percent)
```

### VPN

```promql
# VPN tunnels currently down
meraki_vpn_peer_reachability == 0

# Locations with any unreachable peer
count by (location) (meraki_vpn_peer_reachability == 0) > 0
```

### Exporter Health

```promql
# Meraki API fetch is failing
meraki_up == 0

# Which endpoint is failing
increase(meraki_api_request_errors_total[15m]) > 0

# Data is stale (no successful fetch in 15 minutes)
time() - meraki_last_success_timestamp_seconds > 900

# API error rate per endpoint
rate(meraki_api_request_errors_total[15m])
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - See LICENSE file for details

## Author

Emil Lohmann ([@emil-lohmann](https://github.com/emil-lohmann))

## Acknowledgments

- Built with [Prometheus Go client library](https://github.com/prometheus/client_golang)
- Uses [Cisco Meraki Dashboard API](https://developer.cisco.com/meraki/api-v1/)
