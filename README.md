# Meraki Prometheus Exporter

A Prometheus exporter for Cisco Meraki that collects metrics from your Meraki organization and exposes them in Prometheus format.

## Features

- **Network Health Metrics**: Device availability, uplink status, latency, and packet loss
- **Client Metrics**: Bandwidth usage, client counts, and manufacturer statistics
- **VPN Metrics**: VPN peer usage and connection status
- **Usage Analytics**: Top applications, devices, SSIDs, and networks by usage
- **Alerts**: Organization-wide and network assurance alerts
- **Security**: Appliance security events monitoring
- **Energy**: Switch energy consumption tracking

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
| `MERAKI_ORG_ID` | Yes | - | Your Meraki Organization ID |
| `FETCH_INTERVAL` | No | `300` | Data fetch interval in seconds |
| `LISTEN_ADDR` | No | `:9100` | HTTP server listen address |
| `LOG_LEVEL` | No | `info` | Log level (debug, info, warn, error) |

### Getting Your API Key and Organization ID

1. **API Key**: Log into Meraki Dashboard → Profile → API Access → Generate new API key
2. **Organization ID**: In the Dashboard URL, it's the number after `/o/` (e.g., `https://n123.meraki.com/o/456789/` → Organization ID is `456789`)

## Metrics

### Available Metrics

| Metric Name | Type | Description | Labels |
|------------|------|-------------|--------|
| `meraki_alerts_count` | Gauge | Number of active alerts | `severity` |
| `meraki_assurance_alert_info` | Gauge | Assurance alert information | `network_name`, `device_serial`, `type`, `category`, `severity` |
| `meraki_clients_total` | Gauge | Total number of clients | - |
| `meraki_device_status` | Gauge | Device status (1=online, 0=offline) | `serial`, `name`, `model`, `network_name`, `status` |
| `meraki_uplink_status` | Gauge | Uplink status (1=active, 0=failed) | `serial`, `network_name`, `uplink`, `ip` |
| `meraki_uplink_loss_percent` | Gauge | Uplink packet loss percentage | `serial`, `network_name`, `uplink`, `ip` |
| `meraki_uplink_latency_ms` | Gauge | Uplink latency in milliseconds | `serial`, `network_name`, `uplink`, `ip` |
| `meraki_vpn_peer_usage_bytes` | Gauge | VPN peer usage in bytes | `peer_network`, `device_serial`, `direction` |
| `meraki_vpn_status` | Gauge | VPN connection status | `network_name`, `mode`, `peer_network` |
| `meraki_appliance_utilization` | Gauge | Top appliances by utilization percentage | `name`, `model`, `network_name` |
| `meraki_top_application_usage_bytes` | Gauge | Top applications by usage | `application`, `direction` |
| `meraki_top_application_category_usage_bytes` | Gauge | Top application categories by usage | `category`, `direction` |
| `meraki_top_client_manufacturer_usage_bytes` | Gauge | Top client manufacturers by usage | `manufacturer`, `direction` |
| `meraki_top_device_usage_bytes` | Gauge | Top devices by usage | `device_name`, `model`, `serial`, `network_name`, `direction` |
| `meraki_top_ssid_usage` | Gauge | Top SSIDs by usage in bytes | `ssid_name`, `direction` |
| `meraki_security_event_info` | Gauge | Security events | `device_serial`, `event_type`, `priority`, `protocol`, `src_ip`, `dest_ip`, `blocked` |

### Metrics Endpoints

- `/metrics` - Prometheus metrics endpoint
- `/health` - Health check endpoint (returns `200 OK`)
- `/` - Web UI with links to metrics and health

## Example Queries

### Network Health

```promql
# Devices offline
count(meraki_device_status{status="offline"} == 0)

# Average uplink latency by network
avg by (network_name) (meraki_uplink_latency_ms)

# Uplinks with packet loss > 1%
meraki_uplink_loss_percent > 1
```

### Client Usage

```promql
# Total clients across organization
sum(meraki_clients_total)

# Top 10 SSIDs by usage
topk(10, meraki_top_ssid_usage{direction="total"})

# Client bandwidth by manufacturer
sum by (manufacturer) (meraki_top_client_manufacturer_usage_bytes{direction="total"})
```

### VPN

```promql
# VPN connections down
meraki_vpn_status{status="offline"} == 0

# Total VPN bandwidth by peer
sum by (peer_network) (meraki_vpn_peer_usage_bytes{direction="total"})
```

### Alerts

```promql
# Critical alerts count
meraki_alerts_count{severity="critical"}

# Assurance alerts by category
count by (category) (meraki_assurance_alert_info)
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
