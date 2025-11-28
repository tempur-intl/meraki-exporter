package meraki

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	baseURL        = "https://api.meraki.com/api/v1"
	maxRetries     = 3
	retryDelay     = 1 * time.Second
	requestTimeout = 30 * time.Second
)

type Client struct {
	apiKey     string
	orgID      string
	httpClient *http.Client
}

func NewClient(apiKey, orgID string) *Client {
	return &Client{
		apiKey: apiKey,
		orgID:  orgID,
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
	}
}

type AlertsOverview struct {
	Counts struct {
		Total int `json:"total"`
	} `json:"counts"`
	CountsByType map[string]int `json:"countsByType"`
	CountsByNetwork []struct {
		NetworkID string `json:"networkId"`
		Counts    struct {
			Total int `json:"total"`
		} `json:"counts"`
		CountsByType map[string]int `json:"countsByType"`
	} `json:"countsByNetwork"`
}

type AssuranceAlert struct {
	ID           string    `json:"id"`
	CategoryType string    `json:"categoryType"`
	Network      struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"network"`
	StartedAt   time.Time `json:"startedAt"`
	ResolvedAt  time.Time `json:"resolvedAt"`
	DismissedAt time.Time `json:"dismissedAt"`
	DeviceType  string    `json:"deviceType"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Scope       struct {
		Devices []struct {
			Serial      string `json:"serial"`
			Name        string `json:"name"`
			ProductType string `json:"productType"`
		} `json:"devices"`
	} `json:"scope"`
}

type ClientBandwidthUsage struct {
	ClientID  string  `json:"clientId"`
	NetworkID string  `json:"networkId"`
	Name      string  `json:"name"`
	Mac       string  `json:"mac"`
	Total     float64 `json:"total"`
	Downstream float64 `json:"downstream"`
	Upstream   float64 `json:"upstream"`
}

type ClientsOverview struct {
	Counts struct {
		Total int `json:"total"`
	} `json:"counts"`
	Usage struct {
		Overall struct {
			Total      float64 `json:"total"`
			Downstream float64 `json:"downstream"`
			Upstream   float64 `json:"upstream"`
		} `json:"overall"`
		Average float64 `json:"average"`
	} `json:"usage"`
}

type DeviceAvailability struct {
	Mac         string `json:"mac"`
	Name        string `json:"name"`
	Network     struct {
		ID string `json:"id"`
	} `json:"network"`
	ProductType string `json:"productType"`
	Serial      string `json:"serial"`
	Status      string `json:"status"`
	Tags        []string `json:"tags"`
}

type UplinkLossLatency struct {
	Serial    string `json:"serial"`
	NetworkID string `json:"networkId"`
	Uplink    string `json:"uplink"`
	IP        string `json:"ip"`
	TimeSeries []struct {
		Ts           time.Time `json:"ts"`
		LossPercent  float64   `json:"lossPercent"`
		LatencyMs    float64   `json:"latencyMs"`
	} `json:"timeSeries"`
}

type TopAppliance struct {
	Name          string `json:"name"`
	Model         string `json:"model"`
	Serial        string `json:"serial"`
	Mac           string `json:"mac"`
	Network       struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"network"`
	Utilization struct {
		Average struct {
			Percentage float64 `json:"percentage"`
		} `json:"average"`
	} `json:"utilization"`
}

type TopClient struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Mac    string `json:"mac"`
	Network struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"network"`
	Usage struct {
		Total      float64 `json:"total"`
		Downstream float64 `json:"downstream"`
		Upstream   float64 `json:"upstream"`
	} `json:"usage"`
}

type Network struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organizationId"`
	Name           string   `json:"name"`
	ProductTypes   []string `json:"productTypes"`
	TimeZone       string   `json:"timeZone"`
	Tags           []string `json:"tags"`
}

type TopNetworkByStatus struct {
	NetworkID    string   `json:"networkId"`
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	Tags         []string `json:"tags"`
	Clients      struct {
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
		Usage struct {
			Upstream   float64 `json:"upstream"`
			Downstream float64 `json:"downstream"`
		} `json:"usage"`
	} `json:"clients"`
	Statuses struct {
		Overall       string `json:"overall"`
		ByProductType []struct {
			ProductType string `json:"productType"`
			Counts      struct {
				Online   int `json:"online"`
				Offline  int `json:"offline"`
				Alerting int `json:"alerting"`
				Dormant  int `json:"dormant"`
			} `json:"counts"`
		} `json:"byProductType"`
	} `json:"statuses"`
	ProductTypes []string `json:"productTypes"`
}

type ApplianceVpnStats struct {
	NetworkID    string `json:"networkId"`
	NetworkName  string `json:"networkName"`
	DeviceSerial string `json:"deviceSerial"`
	DeviceModel  string `json:"deviceModel"`
	MerakiVpnPeers []struct {
		NetworkID   string `json:"networkId"`
		NetworkName string `json:"networkName"`
		UsageSummary struct {
			ReceivedInKilobytes string `json:"receivedInKilobytes"`
			SentInKilobytes     string `json:"sentInKilobytes"`
		} `json:"usageSummary"`
	} `json:"merakiVpnPeers"`
}

type ApplianceVpnStatus struct {
	NetworkID    string `json:"networkId"`
	NetworkName  string `json:"networkName"`
	DeviceSerial string `json:"deviceSerial"`
	DeviceStatus string `json:"deviceStatus"`
	Uplinks      []struct {
		Interface string `json:"interface"`
		PublicIP  string `json:"publicIp"`
	} `json:"uplinks"`
	VpnMode         string `json:"vpnMode"`
	ExportedSubnets []struct {
		Subnet string `json:"subnet"`
	} `json:"exportedSubnets"`
	MerakiVpnPeers []struct {
		NetworkID    string `json:"networkId"`
		NetworkName  string `json:"networkName"`
		Reachability string `json:"reachability"`
	} `json:"merakiVpnPeers"`
}

type ApplianceSecurityEvent struct {
	OccurredAt   time.Time `json:"occurredAt"`
	DeviceSerial string    `json:"deviceSerial"`
	DeviceMac    string    `json:"deviceMac"`
	ClientMac    string    `json:"clientMac"`
	SrcIP        string    `json:"srcIp"`
	DestIP       string    `json:"destIp"`
	Protocol     string    `json:"protocol"`
	Type         string    `json:"type"`
	EventType    string    `json:"eventType"`
	Message      string    `json:"message"`
	Priority     string    `json:"priority"`
	Blocked      bool      `json:"blocked"`
}

type TopApplication struct {
	Name  string  `json:"name"`
	Total float64 `json:"total"`
	Downstream float64 `json:"downstream"`
	Upstream float64 `json:"upstream"`
}

type TopApplicationCategory struct {
	Category   string  `json:"category"`
	Total      float64 `json:"total"`
	Downstream float64 `json:"downstream"`
	Upstream   float64 `json:"upstream"`
	Percentage float64 `json:"percentage"`
}

type TopClientManufacturer struct {
	Manufacturer string  `json:"manufacturer"`
	Clients struct {
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
	} `json:"clients"`
	Usage struct {
		Total      float64 `json:"total"`
		Downstream float64 `json:"downstream"`
		Upstream   float64 `json:"upstream"`
	} `json:"usage"`
}

type TopDeviceByUsage struct {
	Name   string `json:"name"`
	Model  string `json:"model"`
	Serial string `json:"serial"`
	Mac    string `json:"mac"`
	Network struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"network"`
	Clients struct {
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
	} `json:"clients"`
	Usage struct {
		Total      float64 `json:"total"`
		Percentage float64 `json:"percentage"`
	} `json:"usage"`
}

type TopSsidByUsage struct {
	Name string `json:"name"`
	Clients struct {
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
	} `json:"clients"`
	Usage struct {
		Total      float64 `json:"total"`
		Downstream float64 `json:"downstream"`
		Upstream   float64 `json:"upstream"`
	} `json:"usage"`
}

type TopSwitchByEnergyUsage struct {
	Name   string `json:"name"`
	Model  string `json:"model"`
	Serial string `json:"serial"`
	Mac    string `json:"mac"`
	Network struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"network"`
	Usage struct {
		Total float64 `json:"total"`
	} `json:"usage"`
}

func (c *Client) doRequest(endpoint string) ([]byte, error) {
	url := fmt.Sprintf("%s%s", baseURL, endpoint)
	
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay * time.Duration(attempt))
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("X-Cisco-Meraki-API-Key", c.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		if resp.StatusCode == 429 {
			retryAfter := resp.Header.Get("Retry-After")
			log.Warnf("Rate limited on %s, Retry-After: %s", endpoint, retryAfter)
			time.Sleep(5 * time.Second)
			lastErr = fmt.Errorf("rate limited")
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
			
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return nil, lastErr
			}
			continue
		}

		return body, nil
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

func (c *Client) GetAlertsOverview() (*AlertsOverview, error) {
	endpoint := fmt.Sprintf("/organizations/%s/assurance/alerts/overview", c.orgID)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get alerts overview: %w", err)
	}

	var overview AlertsOverview
	if err := json.Unmarshal(body, &overview); err != nil {
		return nil, fmt.Errorf("failed to parse alerts overview: %w", err)
	}

	return &overview, nil
}

// GetAssuranceAlerts fetches individual assurance alerts for the organization
func (c *Client) GetAssuranceAlerts() ([]AssuranceAlert, error) {
	// Fetch active alerts only by default
	endpoint := fmt.Sprintf("/organizations/%s/assurance/alerts?active=true&perPage=300", c.orgID)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get assurance alerts: %w", err)
	}

	var alerts []AssuranceAlert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, fmt.Errorf("failed to parse assurance alerts: %w", err)
	}

	return alerts, nil
}

func (c *Client) GetClientsBandwidthUsage(timespan int) ([]ClientBandwidthUsage, error) {
	endpoint := fmt.Sprintf("/organizations/%s/clients/bandwidthUsageHistory?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get clients bandwidth usage: %w", err)
	}

	var usage []ClientBandwidthUsage
	if err := json.Unmarshal(body, &usage); err != nil {
		return nil, fmt.Errorf("failed to parse clients bandwidth usage: %w", err)
	}

	return usage, nil
}

func (c *Client) GetClientsOverview(timespan int) (*ClientsOverview, error) {
	endpoint := fmt.Sprintf("/organizations/%s/clients/overview?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get clients overview: %w", err)
	}

	var overview ClientsOverview
	if err := json.Unmarshal(body, &overview); err != nil {
		return nil, fmt.Errorf("failed to parse clients overview: %w", err)
	}

	return &overview, nil
}

func (c *Client) GetDevicesAvailabilities() ([]DeviceAvailability, error) {
	endpoint := fmt.Sprintf("/organizations/%s/devices/availabilities", c.orgID)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices availabilities: %w", err)
	}

	var availabilities []DeviceAvailability
	if err := json.Unmarshal(body, &availabilities); err != nil {
		return nil, fmt.Errorf("failed to parse devices availabilities: %w", err)
	}

	return availabilities, nil
}

func (c *Client) GetUplinksLossAndLatency(timespan int) ([]UplinkLossLatency, error) {
	endpoint := fmt.Sprintf("/organizations/%s/devices/uplinksLossAndLatency?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get uplinks loss and latency: %w", err)
	}

	var uplinks []UplinkLossLatency
	if err := json.Unmarshal(body, &uplinks); err != nil {
		return nil, fmt.Errorf("failed to parse uplinks loss and latency: %w", err)
	}

	return uplinks, nil
}

func (c *Client) GetTopAppliancesByUtilization(timespan int) ([]TopAppliance, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/appliances/byUtilization?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top appliances: %w", err)
	}

	var appliances []TopAppliance
	if err := json.Unmarshal(body, &appliances); err != nil {
		return nil, fmt.Errorf("failed to parse top appliances: %w", err)
	}

	return appliances, nil
}

func (c *Client) GetTopClientsByUsage(timespan int) ([]TopClient, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/clients/byUsage?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top clients: %w", err)
	}

	var clients []TopClient
	if err := json.Unmarshal(body, &clients); err != nil {
		return nil, fmt.Errorf("failed to parse top clients: %w", err)
	}

	return clients, nil
}

func (c *Client) GetNetworks() ([]Network, error) {
	endpoint := fmt.Sprintf("/organizations/%s/networks", c.orgID)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get networks: %w", err)
	}

	var networks []Network
	if err := json.Unmarshal(body, &networks); err != nil {
		return nil, fmt.Errorf("failed to parse networks: %w", err)
	}

	return networks, nil
}

func (c *Client) GetTopNetworksByStatus() ([]TopNetworkByStatus, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/networks/byStatus?perPage=50", c.orgID)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top networks by status: %w", err)
	}

	var networks []TopNetworkByStatus
	if err := json.Unmarshal(body, &networks); err != nil {
		return nil, fmt.Errorf("failed to parse top networks by status: %w", err)
	}

	return networks, nil
}

func (c *Client) GetOrganizationApplianceVpnStats(timespan int) ([]ApplianceVpnStats, error) {
	endpoint := fmt.Sprintf("/organizations/%s/appliance/vpn/stats?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get VPN stats: %w", err)
	}

	var vpnStats []ApplianceVpnStats
	if err := json.Unmarshal(body, &vpnStats); err != nil {
		return nil, fmt.Errorf("failed to parse VPN stats: %w", err)
	}

	return vpnStats, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *Client) GetOrganizationApplianceVpnStatuses() ([]ApplianceVpnStatus, error) {
	endpoint := fmt.Sprintf("/organizations/%s/appliance/vpn/statuses", c.orgID)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get VPN statuses: %w", err)
	}

	var vpnStatuses []ApplianceVpnStatus
	if err := json.Unmarshal(body, &vpnStatuses); err != nil {
		return nil, fmt.Errorf("failed to parse VPN statuses: %w", err)
	}

	return vpnStatuses, nil
}

func (c *Client) GetOrganizationApplianceSecurityEvents(timespan int) ([]ApplianceSecurityEvent, error) {
	endpoint := fmt.Sprintf("/organizations/%s/appliance/security/events?timespan=%d&perPage=1000", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}

	var events []ApplianceSecurityEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, fmt.Errorf("failed to parse security events: %w", err)
	}

	return events, nil
}

func (c *Client) GetOrganizationTopApplicationsByUsage(timespan int) ([]TopApplication, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/applications/byUsage?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top applications: %w", err)
	}

	var apps []TopApplication
	if err := json.Unmarshal(body, &apps); err != nil {
		return nil, fmt.Errorf("failed to parse top applications: %w", err)
	}

	return apps, nil
}

func (c *Client) GetOrganizationTopApplicationsCategoriesByUsage(timespan int) ([]TopApplicationCategory, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/applications/categories/byUsage?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top application categories: %w", err)
	}

	var categories []TopApplicationCategory
	if err := json.Unmarshal(body, &categories); err != nil {
		return nil, fmt.Errorf("failed to parse top application categories: %w", err)
	}

	return categories, nil
}

func (c *Client) GetOrganizationTopClientsManufacturersByUsage(timespan int) ([]TopClientManufacturer, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/clients/manufacturers/byUsage?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top client manufacturers: %w", err)
	}

	var manufacturers []TopClientManufacturer
	if err := json.Unmarshal(body, &manufacturers); err != nil {
		return nil, fmt.Errorf("failed to parse top client manufacturers: %w", err)
	}

	return manufacturers, nil
}

func (c *Client) GetOrganizationTopDevicesByUsage(timespan int) ([]TopDeviceByUsage, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/devices/byUsage?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top devices: %w", err)
	}

	var devices []TopDeviceByUsage
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, fmt.Errorf("failed to parse top devices: %w", err)
	}

	return devices, nil
}

func (c *Client) GetOrganizationTopSsidsByUsage(timespan int) ([]TopSsidByUsage, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/ssids/byUsage?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top SSIDs: %w", err)
	}

	var ssids []TopSsidByUsage
	if err := json.Unmarshal(body, &ssids); err != nil {
		return nil, fmt.Errorf("failed to parse top SSIDs: %w", err)
	}

	return ssids, nil
}

func (c *Client) GetOrganizationTopSwitchesByEnergyUsage(timespan int) ([]TopSwitchByEnergyUsage, error) {
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/switches/byEnergyUsage?timespan=%d", c.orgID, timespan)
	
	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get top switches by energy: %w", err)
	}

	var switches []TopSwitchByEnergyUsage
	if err := json.Unmarshal(body, &switches); err != nil {
		return nil, fmt.Errorf("failed to parse top switches by energy: %w", err)
	}

	return switches, nil
}
