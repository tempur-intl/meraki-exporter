package collector

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/emil-lohmann/meraki-exporter/meraki"
)

type MerakiCollector struct {
	client *meraki.Client
	mu     sync.RWMutex

	devicesAvailData   []meraki.DeviceAvailability
	uplinksData        []meraki.UplinkLossLatency
	uplinkStatusesData []meraki.ApplianceUplinkStatus
	topAppliancesData  []meraki.TopAppliance
	topNetworksData    []meraki.TopNetworkByStatus
	vpnStatusesData    []meraki.ApplianceVpnStatus
	networkNames       map[string]string
	deviceNames        map[string]string

	// exporter self-observability state
	up                   float64
	lastScrapeDuration   float64
	lastSuccessTimestamp float64
	apiErrors            map[string]float64

	// product metrics
	deviceUp             *prometheus.Desc
	uplinkUp             *prometheus.Desc
	uplinkLoss           *prometheus.Desc
	uplinkLatency        *prometheus.Desc
	applianceUtilization *prometheus.Desc
	networkClients       *prometheus.Desc
	vpnPeerReachability  *prometheus.Desc

	// meta metrics
	upDesc             *prometheus.Desc
	scrapeDurationDesc *prometheus.Desc
	lastSuccessDesc    *prometheus.Desc
	apiErrorsDesc      *prometheus.Desc
}

func NewMerakiCollector(client *meraki.Client) *MerakiCollector {
	return &MerakiCollector{
		client:    client,
		apiErrors: make(map[string]float64),

		deviceUp: prometheus.NewDesc(
			"meraki_device_up",
			"Device availability (1 if online, 0 otherwise)",
			[]string{"name", "location", "product_type", "status"},
			nil,
		),

		uplinkUp: prometheus.NewDesc(
			"meraki_uplink_up",
			"Uplink connection state (1 if active or ready, 0 otherwise). The status label "+
				"distinguishes an unplugged port (\"not connected\") from a genuine outage (\"failed\").",
			[]string{"name", "location", "uplink", "status"},
			nil,
		),

		uplinkLoss: prometheus.NewDesc(
			"meraki_uplink_loss_percent",
			"Uplink packet loss percentage (over last 5 minutes)",
			[]string{"name", "location", "uplink", "ip"},
			nil,
		),

		uplinkLatency: prometheus.NewDesc(
			"meraki_uplink_latency_ms",
			"Uplink latency in milliseconds (over last 5 minutes)",
			[]string{"name", "location", "uplink", "ip"},
			nil,
		),

		applianceUtilization: prometheus.NewDesc(
			"meraki_appliance_utilization_percent",
			"Appliance utilization percentage (over last 24 hours)",
			[]string{"name", "model", "location"},
			nil,
		),

		networkClients: prometheus.NewDesc(
			"meraki_network_clients",
			"Number of clients per network/location (over last 24 hours)",
			[]string{"location"},
			nil,
		),

		vpnPeerReachability: prometheus.NewDesc(
			"meraki_vpn_peer_reachability",
			"VPN peer reachability status (1=reachable, 0=unreachable)",
			[]string{"location", "peer_location"},
			nil,
		),

		upDesc: prometheus.NewDesc(
			"meraki_up",
			"Whether the last Meraki API fetch cycle succeeded for all endpoints (1=yes, 0=no)",
			nil,
			nil,
		),

		scrapeDurationDesc: prometheus.NewDesc(
			"meraki_scrape_duration_seconds",
			"Wall-clock duration of the last Meraki API fetch cycle in seconds",
			nil,
			nil,
		),

		lastSuccessDesc: prometheus.NewDesc(
			"meraki_last_success_timestamp_seconds",
			"Unix timestamp of the last fully successful Meraki API fetch cycle",
			nil,
			nil,
		),

		apiErrorsDesc: prometheus.NewDesc(
			"meraki_api_request_errors_total",
			"Cumulative number of failed Meraki API requests per endpoint",
			[]string{"endpoint"},
			nil,
		),
	}
}

func (c *MerakiCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.deviceUp
	ch <- c.uplinkUp
	ch <- c.uplinkLoss
	ch <- c.uplinkLatency
	ch <- c.applianceUtilization
	ch <- c.networkClients
	ch <- c.vpnPeerReachability
	ch <- c.upDesc
	ch <- c.scrapeDurationDesc
	ch <- c.lastSuccessDesc
	ch <- c.apiErrorsDesc
}

func (c *MerakiCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	c.collectDeviceAvailability(ch)
	c.collectUplinkStatuses(ch)
	c.collectUplinks(ch)
	c.collectTopAppliances(ch)
	c.collectTopNetworks(ch)
	c.collectVpnStatuses(ch)
	c.collectMeta(ch)
}

// deviceLabel returns the device name, falling back to the serial when a device has
// no name configured in the dashboard, so that unnamed devices stay distinguishable
// instead of collapsing into a single blank-labelled series.
func deviceLabel(name, serial string) string {
	if name != "" {
		return name
	}
	return serial
}

// locationName resolves a network ID to its human-readable name (the "location").
func (c *MerakiCollector) locationName(networkID string) string {
	if c.networkNames != nil {
		if name, ok := c.networkNames[networkID]; ok && name != "" {
			return name
		}
	}
	return "unknown"
}

func (c *MerakiCollector) collectDeviceAvailability(ch chan<- prometheus.Metric) {
	for _, device := range c.devicesAvailData {
		value := 0.0
		if device.Status == "online" {
			value = 1.0
		}

		ch <- prometheus.MustNewConstMetric(
			c.deviceUp,
			prometheus.GaugeValue,
			value,
			deviceLabel(device.Name, device.Serial),
			c.locationName(device.Network.ID),
			device.ProductType,
			device.Status,
		)
	}
}

func (c *MerakiCollector) collectUplinkStatuses(ch chan<- prometheus.Metric) {
	for _, appliance := range c.uplinkStatusesData {
		name := deviceLabel(c.deviceNames[appliance.Serial], appliance.Serial)
		location := c.locationName(appliance.NetworkID)

		for _, uplink := range appliance.Uplinks {
			value := 0.0
			if uplink.Status == "active" || uplink.Status == "ready" {
				value = 1.0
			}

			ch <- prometheus.MustNewConstMetric(
				c.uplinkUp,
				prometheus.GaugeValue,
				value,
				name,
				location,
				uplink.Interface,
				uplink.Status,
			)
		}
	}
}

func (c *MerakiCollector) collectUplinks(ch chan<- prometheus.Metric) {
	for _, uplink := range c.uplinksData {
		if uplink.Uplink == "" || uplink.IP == "" {
			continue
		}

		// The uplink API only reports a serial, so resolve the device name via the
		// availabilities map; deviceLabel falls back to the serial when unknown.
		name := deviceLabel(c.deviceNames[uplink.Serial], uplink.Serial)
		location := c.locationName(uplink.NetworkID)

		if len(uplink.TimeSeries) > 0 {
			latest := uplink.TimeSeries[len(uplink.TimeSeries)-1]

			ch <- prometheus.MustNewConstMetric(
				c.uplinkLoss,
				prometheus.GaugeValue,
				latest.LossPercent,
				name,
				location,
				uplink.Uplink,
				uplink.IP,
			)

			ch <- prometheus.MustNewConstMetric(
				c.uplinkLatency,
				prometheus.GaugeValue,
				latest.LatencyMs,
				name,
				location,
				uplink.Uplink,
				uplink.IP,
			)
		}
	}
}

func (c *MerakiCollector) collectTopAppliances(ch chan<- prometheus.Metric) {
	for _, appliance := range c.topAppliancesData {
		location := appliance.Network.Name
		if location == "" {
			location = "unknown"
		}

		ch <- prometheus.MustNewConstMetric(
			c.applianceUtilization,
			prometheus.GaugeValue,
			appliance.Utilization.Average.Percentage,
			deviceLabel(appliance.Name, appliance.Serial),
			appliance.Model,
			location,
		)
	}
}

func (c *MerakiCollector) collectTopNetworks(ch chan<- prometheus.Metric) {
	for _, network := range c.topNetworksData {
		location := network.Name
		if location == "" {
			location = "unknown"
		}

		ch <- prometheus.MustNewConstMetric(
			c.networkClients,
			prometheus.GaugeValue,
			float64(network.Clients.Counts.Total),
			location,
		)
	}
}

func (c *MerakiCollector) collectVpnStatuses(ch chan<- prometheus.Metric) {
	for _, vpnStatus := range c.vpnStatusesData {
		location := vpnStatus.NetworkName
		if location == "" {
			location = "unknown"
		}

		for _, peer := range vpnStatus.MerakiVpnPeers {
			peerLocation := peer.NetworkName
			if peerLocation == "" {
				peerLocation = "unknown"
			}

			reachable := 0.0
			if peer.Reachability == "reachable" {
				reachable = 1.0
			}

			ch <- prometheus.MustNewConstMetric(
				c.vpnPeerReachability,
				prometheus.GaugeValue,
				reachable,
				location,
				peerLocation,
			)
		}
	}
}

func (c *MerakiCollector) collectMeta(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.upDesc, prometheus.GaugeValue, c.up)
	ch <- prometheus.MustNewConstMetric(c.scrapeDurationDesc, prometheus.GaugeValue, c.lastScrapeDuration)
	ch <- prometheus.MustNewConstMetric(c.lastSuccessDesc, prometheus.GaugeValue, c.lastSuccessTimestamp)

	for endpoint, count := range c.apiErrors {
		ch <- prometheus.MustNewConstMetric(c.apiErrorsDesc, prometheus.CounterValue, count, endpoint)
	}
}

func (c *MerakiCollector) UpdateData() {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Info("Fetching data from Meraki API...")
	start := time.Now()
	allOK := true

	record := func(endpoint string, err error) {
		// Ensure the counter series exists even at zero, so that rate() works and
		// "no errors" is distinguishable from "endpoint never ran".
		if _, ok := c.apiErrors[endpoint]; !ok {
			c.apiErrors[endpoint] = 0
		}

		if err != nil {
			allOK = false
			c.apiErrors[endpoint]++
		}
	}

	if networks, err := c.client.GetNetworks(); err != nil {
		log.Errorf("Failed to fetch networks: %v", err)
		record("networks", err)
	} else {
		c.networkNames = make(map[string]string)
		for _, network := range networks {
			c.networkNames[network.ID] = network.Name
		}
		record("networks", nil)
	}

	if devices, err := c.client.GetDevicesAvailabilities(); err != nil {
		log.Errorf("Failed to fetch device availabilities: %v", err)
		record("devices_availabilities", err)
	} else {
		c.devicesAvailData = devices
		c.deviceNames = make(map[string]string)
		for _, device := range devices {
			if device.Serial != "" && device.Name != "" {
				c.deviceNames[device.Serial] = device.Name
			}
		}
		record("devices_availabilities", nil)
	}

	if uplinks, err := c.client.GetUplinksLossAndLatency(300); err != nil {
		log.Errorf("Failed to fetch uplinks loss and latency: %v", err)
		record("uplinks", err)
	} else {
		c.uplinksData = uplinks
		record("uplinks", nil)
	}

	if uplinkStatuses, err := c.client.GetOrganizationApplianceUplinkStatuses(); err != nil {
		log.Errorf("Failed to fetch appliance uplink statuses: %v", err)
		record("uplink_statuses", err)
	} else {
		c.uplinkStatusesData = uplinkStatuses
		record("uplink_statuses", nil)
	}

	if appliances, err := c.client.GetTopAppliancesByUtilization(86400); err != nil {
		log.Errorf("Failed to fetch top appliances: %v", err)
		record("top_appliances", err)
	} else {
		c.topAppliancesData = appliances
		record("top_appliances", nil)
	}

	if topNetworks, err := c.client.GetTopNetworksByStatus(); err != nil {
		log.Errorf("Failed to fetch top networks by status: %v", err)
		record("top_networks", err)
	} else {
		c.topNetworksData = topNetworks
		record("top_networks", nil)
	}

	if vpnStatuses, err := c.client.GetOrganizationApplianceVpnStatuses(); err != nil {
		log.Errorf("Failed to fetch VPN statuses: %v", err)
		record("vpn_statuses", err)
	} else {
		c.vpnStatusesData = vpnStatuses
		record("vpn_statuses", nil)
	}

	c.lastScrapeDuration = time.Since(start).Seconds()
	if allOK {
		c.up = 1
		c.lastSuccessTimestamp = float64(time.Now().Unix())
	} else {
		c.up = 0
	}

	log.Info("Data fetch complete")
}
