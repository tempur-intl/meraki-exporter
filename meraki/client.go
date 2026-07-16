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

// SetOrgID sets the organization the client operates against. Used when the org
// is discovered at startup rather than supplied via configuration.
func (c *Client) SetOrgID(orgID string) {
	c.orgID = orgID
}

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Network struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organizationId"`
	Name           string   `json:"name"`
	ProductTypes   []string `json:"productTypes"`
	TimeZone       string   `json:"timeZone"`
	Tags           []string `json:"tags"`
}

type DeviceAvailability struct {
	Mac     string `json:"mac"`
	Name    string `json:"name"`
	Network struct {
		ID string `json:"id"`
	} `json:"network"`
	ProductType string   `json:"productType"`
	Serial      string   `json:"serial"`
	Status      string   `json:"status"`
	Tags        []string `json:"tags"`
}

type UplinkLossLatency struct {
	Serial     string `json:"serial"`
	NetworkID  string `json:"networkId"`
	Uplink     string `json:"uplink"`
	IP         string `json:"ip"`
	TimeSeries []struct {
		Ts          time.Time `json:"ts"`
		LossPercent float64   `json:"lossPercent"`
		LatencyMs   float64   `json:"latencyMs"`
	} `json:"timeSeries"`
}

type TopAppliance struct {
	Name    string `json:"name"`
	Model   string `json:"model"`
	Serial  string `json:"serial"`
	Mac     string `json:"mac"`
	Network struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"network"`
	Utilization struct {
		Average struct {
			Percentage float64 `json:"percentage"`
		} `json:"average"`
	} `json:"utilization"`
}

type TopNetworkByStatus struct {
	NetworkID string   `json:"networkId"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Tags      []string `json:"tags"`
	Clients   struct {
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

type ApplianceUplinkStatus struct {
	NetworkID string `json:"networkId"`
	Serial    string `json:"serial"`
	Model     string `json:"model"`
	Uplinks   []struct {
		Interface string `json:"interface"`
		// Status is one of: active, ready, failed, not connected.
		Status string `json:"status"`
	} `json:"uplinks"`
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

// GetOrganizations lists the organizations the API key can access. Unlike the
// other calls it does not require an organization ID, so it can be used to
// discover one at startup.
func (c *Client) GetOrganizations() ([]Organization, error) {
	body, err := c.doRequest("/organizations")
	if err != nil {
		return nil, fmt.Errorf("failed to get organizations: %w", err)
	}

	var orgs []Organization
	if err := json.Unmarshal(body, &orgs); err != nil {
		return nil, fmt.Errorf("failed to parse organizations: %w", err)
	}

	return orgs, nil
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

func (c *Client) GetTopNetworksByStatus() ([]TopNetworkByStatus, error) {
	// perPage=5000 is the endpoint's documented maximum; the previous value of 50
	// silently truncated the result to the first 50 networks.
	endpoint := fmt.Sprintf("/organizations/%s/summary/top/networks/byStatus?perPage=5000", c.orgID)

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

// GetOrganizationApplianceUplinkStatuses reports the connection state of each
// appliance uplink, which distinguishes an unplugged port ("not connected") from
// one that is genuinely down ("failed").
func (c *Client) GetOrganizationApplianceUplinkStatuses() ([]ApplianceUplinkStatus, error) {
	endpoint := fmt.Sprintf("/organizations/%s/appliance/uplink/statuses?perPage=1000", c.orgID)

	body, err := c.doRequest(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get appliance uplink statuses: %w", err)
	}

	var statuses []ApplianceUplinkStatus
	if err := json.Unmarshal(body, &statuses); err != nil {
		return nil, fmt.Errorf("failed to parse appliance uplink statuses: %w", err)
	}

	return statuses, nil
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
