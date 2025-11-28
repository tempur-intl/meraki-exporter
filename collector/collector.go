package collector

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	
	"github.com/emil-lohmann/meraki-exporter/meraki"
)

type MerakiCollector struct {
	client   *meraki.Client
	mu       sync.RWMutex

	alertsData              	*meraki.AlertsOverview
	assuranceAlertsData     	[]meraki.AssuranceAlert
	bandwidthUsageData      	[]meraki.ClientBandwidthUsage
	clientsOverviewData     	*meraki.ClientsOverview
	devicesAvailData        	[]meraki.DeviceAvailability
	uplinksData             	[]meraki.UplinkLossLatency
	topAppliancesData       	[]meraki.TopAppliance
	topClientsData          	[]meraki.TopClient
	topNetworksData         	[]meraki.TopNetworkByStatus
	topApplicationsData     	[]meraki.TopApplication
	topAppCategoriesData    	[]meraki.TopApplicationCategory
	topClientManufacturers  	[]meraki.TopClientManufacturer
	topDevicesByUsageData   	[]meraki.TopDeviceByUsage
	topSsidsData            	[]meraki.TopSsidByUsage
	topSwitchesByEnergyData 	[]meraki.TopSwitchByEnergyUsage
	vpnStatsData            	[]meraki.ApplianceVpnStats
	vpnStatusesData         	[]meraki.ApplianceVpnStatus
	securityEventsData     		[]meraki.ApplianceSecurityEvent
	networkNames           		map[string]string

	alertsCount                *prometheus.Desc
	assuranceAlertInfo         *prometheus.Desc
	clientsBandwidthTotal      *prometheus.Desc
	clientsBandwidthDownstream *prometheus.Desc
	clientsBandwidthUpstream   *prometheus.Desc
	clientsCount               *prometheus.Desc
	clientsTotalDownstream     *prometheus.Desc
	clientsTotalUpstream       *prometheus.Desc
	clientsAverageUsage        *prometheus.Desc
	deviceStatus               *prometheus.Desc
	uplinkLoss                 *prometheus.Desc
	uplinkLatency              *prometheus.Desc
	applianceUtilization       *prometheus.Desc
	topClientUsage             *prometheus.Desc
	networkClients             *prometheus.Desc
	networkClientsUsage        *prometheus.Desc
	vpnPeerUsage               *prometheus.Desc
	vpnPeerReachability        *prometheus.Desc
	securityEventInfo          *prometheus.Desc
	topAppUsage                *prometheus.Desc
	topAppCategoryUsage        *prometheus.Desc
	topClientManufacturerUsage *prometheus.Desc
	topDeviceUsage             *prometheus.Desc
	topSsidUsage               *prometheus.Desc
	topSwitchEnergyUsage       *prometheus.Desc
}

func NewMerakiCollector(client *meraki.Client) *MerakiCollector {
	return &MerakiCollector{
		client: client,
		
		alertsCount: prometheus.NewDesc(
			"meraki_alerts_count",
			"Total alert count across the organization or per network",
			[]string{"network_name", "alert_type"},
			nil,
		),
		
		assuranceAlertInfo: prometheus.NewDesc(
			"meraki_assurance_alert",
			"Assurance alert information (1 = active alert)",
			[]string{"alert_id", "network_name", "category", "type", "severity", "device_type", "title"},
			nil,
		),
		
		clientsBandwidthTotal: prometheus.NewDesc(
			"meraki_clients_bandwidth_total",
			"Total bandwidth usage per client",
			[]string{"client_id", "network_name", "client_name"},
			nil,
		),
		
	clientsBandwidthDownstream: prometheus.NewDesc(
		"meraki_clients_bandwidth_downstream",
		"Downstream bandwidth usage per client (over last 24 hours)",
		[]string{"client_id", "network_name", "client_name"},
		nil,
	),
	
	clientsBandwidthUpstream: prometheus.NewDesc(
		"meraki_clients_bandwidth_upstream",
		"Upstream bandwidth usage per client (over last 24 hours)",
		[]string{"client_id", "network_name", "client_name"},
		nil,
	),	clientsCount: prometheus.NewDesc(
		"meraki_clients_count",
		"Total number of clients in the organization (over last 24 hours)",
		nil,
		nil,
	),
	
	clientsTotalDownstream: prometheus.NewDesc(
		"meraki_clients_total_downstream_usage",
		"Total downstream usage across all clients (over last 24 hours)",
		nil,
		nil,
	),
	
	clientsTotalUpstream: prometheus.NewDesc(
		"meraki_clients_total_upstream_usage",
		"Total upstream usage across all clients (over last 24 hours)",
		nil,
		nil,
	),
	
	clientsAverageUsage: prometheus.NewDesc(
		"meraki_clients_average_usage",
		"Average usage per client (over last 24 hours)",
		nil,
		nil,
	),		deviceStatus: prometheus.NewDesc(
			"meraki_device_status",
			"Device status (1 for current status, 0 otherwise)",
			[]string{"serial", "name", "network_name", "product_type", "status"},
			nil,
		),
		
	uplinkLoss: prometheus.NewDesc(
		"meraki_uplink_loss",
		"Uplink packet loss percentage (over last 5 minutes)",
		[]string{"serial", "network_name", "uplink", "ip"},
		nil,
	),
	
	uplinkLatency: prometheus.NewDesc(
		"meraki_uplink_latency",
	"Uplink latency in milliseconds (over last 5 minutes)",
	[]string{"serial", "network_name", "uplink", "ip"},
	nil,
),
	
	applianceUtilization: prometheus.NewDesc(
		"meraki_appliance_utilization",
		"Top appliances by utilization percentage (over last 24 hours)",
		[]string{"name", "model", "network_name"},
		nil,
	),
	
	topClientUsage: prometheus.NewDesc(
		"meraki_top_client_usage",
		"Top clients by usage (over last 24 hours)",
		[]string{"client_id", "name", "network_name", "direction"},
		nil,
	),
	
	networkClients: prometheus.NewDesc(
		"meraki_network_clients",
		"Network client counts (over last 24 hours)",
		[]string{"network_name"},
		nil,
	),
	
	networkClientsUsage: prometheus.NewDesc(
		"meraki_network_clients_usage",
		"Network client usage in bytes (over last 24 hours)",
		[]string{"network_name", "direction"},
		nil,
	),
	
	vpnPeerUsage: prometheus.NewDesc(
		"meraki_vpn_peer_usage_bytes",
		"VPN peer usage in bytes (over last 24 hours)",
		[]string{"network_name", "device_serial", "peer_network_name", "direction"},
		nil,
	),
	
	vpnPeerReachability: prometheus.NewDesc(
		"meraki_vpn_peer_reachability",
		"VPN peer reachability status (1=reachable, 0=unreachable)",
		[]string{"network_name", "device_serial", "peer_network_name"},
		nil,
	),
	
	securityEventInfo: prometheus.NewDesc(
		"meraki_security_event",
		"Security event information",
		[]string{"device_serial", "event_type", "priority", "protocol", "src_ip", "dest_ip", "blocked"},
		nil,
	),
	
	topAppUsage: prometheus.NewDesc(
		"meraki_top_application_usage_bytes",
		"Top applications by usage in bytes (over last 24 hours)",
		[]string{"application", "direction"},
		nil,
	),
	
topAppCategoryUsage: prometheus.NewDesc(
	"meraki_top_application_category_usage_bytes",
	"Top application categories by usage in bytes (over last 24 hours)",
	[]string{"category", "direction"},
	nil,
),

topClientManufacturerUsage: prometheus.NewDesc(
	"meraki_top_client_manufacturer_usage_bytes",
	"Top client manufacturers by usage in bytes (over last 24 hours)",
	[]string{"manufacturer", "direction"},
	nil,
),

topDeviceUsage: prometheus.NewDesc(
	"meraki_top_device_usage_bytes",
	"Top devices by usage in bytes (over last 24 hours)",
	[]string{"device_name", "model", "serial", "network_name", "direction"},
	nil,
),		topSsidUsage: prometheus.NewDesc(
			"meraki_top_ssid_usage",
			"Top SSIDs by usage in bytes (over last 24 hours)",
			[]string{"ssid_name", "direction"},
			nil,
		),
		
		topSwitchEnergyUsage: prometheus.NewDesc(
			"meraki_top_switch_energy_usage",
			"Top switches by energy usage",
			[]string{"switch_name", "model", "serial", "network_name"},
			nil,
		),
	}
}

func (c *MerakiCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.alertsCount
	ch <- c.assuranceAlertInfo
	ch <- c.clientsBandwidthTotal
	ch <- c.clientsBandwidthDownstream
	ch <- c.clientsBandwidthUpstream
	ch <- c.clientsCount
	ch <- c.clientsTotalDownstream
	ch <- c.clientsTotalUpstream
	ch <- c.clientsAverageUsage
	ch <- c.deviceStatus
	ch <- c.uplinkLoss
	ch <- c.uplinkLatency
	ch <- c.applianceUtilization
	ch <- c.topClientUsage
	ch <- c.networkClients
	ch <- c.networkClientsUsage
	ch <- c.vpnPeerUsage
	ch <- c.vpnPeerReachability
	ch <- c.securityEventInfo
	ch <- c.topAppUsage
	ch <- c.topAppCategoryUsage
	ch <- c.topClientManufacturerUsage
	ch <- c.topDeviceUsage
	ch <- c.topSsidUsage
	ch <- c.topSwitchEnergyUsage
}

func (c *MerakiCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s
	c.collectAlerts(ch)
	c.collectAssuranceAlerts(ch)
	c.collectBandwidthUsage(ch)
	c.collectClientsOverview(ch)
	c.collectDeviceAvailability(ch)
	c.collectUplinks(ch)
	c.collectTopAppliances(ch)
	c.collectTopClients(ch)
	c.collectTopNetworks(ch)
	c.collectVpnStats(ch)
	c.collectVpnStatuses(ch)
	c.collectSecurityEvents(ch)
	c.collectTopApplications(ch)
	c.collectTopApplicationCategories(ch)
	c.collectTopClientManufacturers(ch)
	c.collectTopDevicesByUsage(ch)
	c.collectTopSsids(ch)
	c.collectTopSwitchesByEnergy(ch)
}

func (c *MerakiCollector) collectAlerts(ch chan<- prometheus.Metric) {
	if c.alertsData == nil {
		return
	}
	
	for alertType, count := range c.alertsData.CountsByType {
		ch <- prometheus.MustNewConstMetric(
			c.alertsCount,
			prometheus.GaugeValue,
			float64(count),
			"",
			alertType,
		)
	}
	
	for _, network := range c.alertsData.CountsByNetwork {
		networkName := "unknown"
		if c.networkNames != nil {
			if name, ok := c.networkNames[network.NetworkID]; ok {
				networkName = name
			}
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.alertsCount,
			prometheus.GaugeValue,
			float64(network.Counts.Total),
			networkName,
			"total",
		)
		
		for alertType, count := range network.CountsByType {
			ch <- prometheus.MustNewConstMetric(
				c.alertsCount,
				prometheus.GaugeValue,
				float64(count),
				networkName,
				alertType,
			)
		}
	}
}

func (c *MerakiCollector) collectAssuranceAlerts(ch chan<- prometheus.Metric) {
	if c.assuranceAlertsData == nil {
		return
	}
	
	for _, alert := range c.assuranceAlertsData {
		networkName := "unknown"
		if alert.Network.Name != "" {
			networkName = alert.Network.Name
		}
		
		category := alert.CategoryType
		if category == "" {
			category = "unknown"
		}
		
		alertType := alert.Type
		if alertType == "" {
			alertType = "unknown"
		}
		
		severity := alert.Severity
		if severity == "" {
			severity = "unknown"
		}
		
		deviceType := alert.DeviceType
		if deviceType == "" {
			deviceType = "unknown"
		}
		
		title := alert.Title
		if title == "" {
			title = "unknown"
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.assuranceAlertInfo,
			prometheus.GaugeValue,
			1.0,
			alert.ID,
			networkName,
			category,
			alertType,
			severity,
			deviceType,
			title,
		)
	}
}

func (c *MerakiCollector) collectBandwidthUsage(ch chan<- prometheus.Metric) {
	if c.bandwidthUsageData == nil {
		return
	}
	
	for _, usage := range c.bandwidthUsageData {
		if usage.Mac == "" && usage.ClientID == "" {
			continue
		}
		
		clientID := usage.ClientID
		if clientID == "" {
			clientID = usage.Mac
		}
		
		clientName := usage.Name
		if clientName == "" {
			clientName = "unknown"
		}
		
		mac := usage.Mac
		if mac == "" {
			mac = "unknown"
		}
		
		networkID := usage.NetworkID
		if networkID == "" {
			networkID = "unknown"
		}
		
		networkName := "unknown"
		if c.networkNames != nil {
			if name, ok := c.networkNames[networkID]; ok {
				networkName = name
			}
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.clientsBandwidthTotal,
			prometheus.GaugeValue,
			usage.Total,
			clientID,
			networkName,
			clientName,
		)
		
		ch <- prometheus.MustNewConstMetric(
			c.clientsBandwidthDownstream,
			prometheus.GaugeValue,
			usage.Downstream,
			clientID,
			networkName,
			clientName,
		)
		
		ch <- prometheus.MustNewConstMetric(
			c.clientsBandwidthUpstream,
			prometheus.GaugeValue,
			usage.Upstream,
			clientID,
			networkName,
			clientName,
		)
	}
}

func (c *MerakiCollector) collectClientsOverview(ch chan<- prometheus.Metric) {
	if c.clientsOverviewData == nil {
		return
	}
	
	ch <- prometheus.MustNewConstMetric(
		c.clientsCount,
		prometheus.GaugeValue,
		float64(c.clientsOverviewData.Counts.Total),
	)
	
	ch <- prometheus.MustNewConstMetric(
		c.clientsTotalDownstream,
		prometheus.GaugeValue,
		c.clientsOverviewData.Usage.Overall.Downstream,
	)
	
	ch <- prometheus.MustNewConstMetric(
		c.clientsTotalUpstream,
		prometheus.GaugeValue,
		c.clientsOverviewData.Usage.Overall.Upstream,
	)
	
	ch <- prometheus.MustNewConstMetric(
		c.clientsAverageUsage,
		prometheus.GaugeValue,
		c.clientsOverviewData.Usage.Average,
	)
}

func (c *MerakiCollector) collectDeviceAvailability(ch chan<- prometheus.Metric) {
	if c.devicesAvailData == nil {
		return
	}
	
	statuses := []string{"online", "offline", "alerting", "dormant"}
	
	for _, device := range c.devicesAvailData {
		networkName := "unknown"
		if c.networkNames != nil {
			if name, ok := c.networkNames[device.Network.ID]; ok {
				networkName = name
			}
		}
		
		for _, status := range statuses {
			value := 0.0
			if device.Status == status {
				value = 1.0
			}
			
			ch <- prometheus.MustNewConstMetric(
				c.deviceStatus,
				prometheus.GaugeValue,
				value,
				device.Serial,
				device.Name,
				networkName,
				device.ProductType,
				status,
			)
		}
	}
}

func (c *MerakiCollector) collectUplinks(ch chan<- prometheus.Metric) {
	if c.uplinksData == nil {
		return
	}
	
	for _, uplink := range c.uplinksData {
		if uplink.Uplink == "" || uplink.IP == "" {
			continue
		}
		
		networkName := "unknown"
		if c.networkNames != nil {
			if name, ok := c.networkNames[uplink.NetworkID]; ok {
				networkName = name
			}
		}
		
		if len(uplink.TimeSeries) > 0 {
			latest := uplink.TimeSeries[len(uplink.TimeSeries)-1]
			
			ch <- prometheus.MustNewConstMetric(
				c.uplinkLoss,
				prometheus.GaugeValue,
				latest.LossPercent,
				uplink.Serial,
				networkName,
				uplink.Uplink,
				uplink.IP,
			)
			
			ch <- prometheus.MustNewConstMetric(
				c.uplinkLatency,
				prometheus.GaugeValue,
				latest.LatencyMs,
				uplink.Serial,
				networkName,
				uplink.Uplink,
				uplink.IP,
			)
		}
	}
}

func (c *MerakiCollector) collectTopAppliances(ch chan<- prometheus.Metric) {
	if c.topAppliancesData == nil {
		return
	}
	
	for _, appliance := range c.topAppliancesData {
		ch <- prometheus.MustNewConstMetric(
			c.applianceUtilization,
			prometheus.GaugeValue,
			appliance.Utilization.Average.Percentage,
			appliance.Name,
			appliance.Model,
			appliance.Network.Name,
		)
	}
}

func (c *MerakiCollector) collectTopClients(ch chan<- prometheus.Metric) {
	if c.topClientsData == nil {
		return
	}
	
	for _, client := range c.topClientsData {
		ch <- prometheus.MustNewConstMetric(
			c.topClientUsage,
			prometheus.GaugeValue,
			client.Usage.Total,
			client.ID,
			client.Name,
			client.Network.Name,
			"total",
		)
		
		ch <- prometheus.MustNewConstMetric(
			c.topClientUsage,
			prometheus.GaugeValue,
			client.Usage.Downstream,
			client.ID,
			client.Name,
			client.Network.Name,
			"downstream",
		)
		
		ch <- prometheus.MustNewConstMetric(
			c.topClientUsage,
			prometheus.GaugeValue,
			client.Usage.Upstream,
			client.ID,
			client.Name,
			client.Network.Name,
			"upstream",
		)
	}
}

func (c *MerakiCollector) collectTopNetworks(ch chan<- prometheus.Metric) {
	if c.topNetworksData == nil {
		return
	}
	
	for _, network := range c.topNetworksData {
		networkName := network.Name
		if networkName == "" {
			networkName = "unknown"
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.networkClients,
			prometheus.GaugeValue,
			float64(network.Clients.Counts.Total),
			networkName,
		)
		
		ch <- prometheus.MustNewConstMetric(
			c.networkClientsUsage,
			prometheus.GaugeValue,
			network.Clients.Usage.Upstream,
			networkName,
			"upstream",
		)

		ch <- prometheus.MustNewConstMetric(
			c.networkClientsUsage,
			prometheus.GaugeValue,
			network.Clients.Usage.Downstream,
			networkName,
			"downstream",
		)
		
	}
}

func (c *MerakiCollector) collectVpnStats(ch chan<- prometheus.Metric) {
	if c.vpnStatsData == nil {
		return
	}
	
	networkToSerial := make(map[string]string)
	if c.vpnStatusesData != nil {
		for _, status := range c.vpnStatusesData {
			if status.NetworkID != "" && status.DeviceSerial != "" {
				networkToSerial[status.NetworkID] = status.DeviceSerial
			}
		}
	}
	
	for _, vpnStat := range c.vpnStatsData {
		networkName := vpnStat.NetworkName
		if networkName == "" {
			networkName = "unknown"
		}
		
		deviceSerial := vpnStat.DeviceSerial
		if deviceSerial == "" && vpnStat.NetworkID != "" {
			if serial, ok := networkToSerial[vpnStat.NetworkID]; ok {
				deviceSerial = serial
			}
		}
		
		for j, peer := range vpnStat.MerakiVpnPeers {
			peerNetworkName := peer.NetworkName
			if peerNetworkName == "" {
				peerNetworkName = "unknown"
			}
			
			var sentBytes, receivedBytes float64
			if peer.UsageSummary.SentInKilobytes != "" {
				if val, err := strconv.ParseFloat(peer.UsageSummary.SentInKilobytes, 64); err == nil {
					sentBytes = val * 1024
				}
			}
			if peer.UsageSummary.ReceivedInKilobytes != "" {
				if val, err := strconv.ParseFloat(peer.UsageSummary.ReceivedInKilobytes, 64); err == nil {
					receivedBytes = val * 1024
				}
			}
			
			ch <- prometheus.MustNewConstMetric(
				c.vpnPeerUsage,
				prometheus.GaugeValue,
				sentBytes,
				networkName,
				deviceSerial,
				peerNetworkName,
				"sent",
			)
			
			ch <- prometheus.MustNewConstMetric(
				c.vpnPeerUsage,
				prometheus.GaugeValue,
				receivedBytes,
				networkName,
				deviceSerial,
				peerNetworkName,
				"received",
			)
		}
	}
}

func (c *MerakiCollector) collectVpnStatuses(ch chan<- prometheus.Metric) {
	if c.vpnStatusesData == nil {
		return
	}
	
	for _, vpnStatus := range c.vpnStatusesData {
		networkName := vpnStatus.NetworkName
		if networkName == "" {
			networkName = "unknown"
		}
		
		for _, peer := range vpnStatus.MerakiVpnPeers {
			peerNetworkName := peer.NetworkName
			if peerNetworkName == "" {
				peerNetworkName = "unknown"
			}
			
			reachable := 0.0
			if peer.Reachability == "reachable" {
				reachable = 1.0
			}
			
			ch <- prometheus.MustNewConstMetric(
				c.vpnPeerReachability,
				prometheus.GaugeValue,
				reachable,
				networkName,
				vpnStatus.DeviceSerial,
				peerNetworkName,
			)
		}
	}
}

func (c *MerakiCollector) collectSecurityEvents(ch chan<- prometheus.Metric) {
	if c.securityEventsData == nil {
		return
	}
	
	eventCounts := make(map[string]int)
	
	for _, event := range c.securityEventsData {
		blockedStr := "false"
		if event.Blocked {
			blockedStr = "true"
		}
		
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			event.DeviceSerial,
			event.EventType,
			event.Priority,
			event.Protocol,
			event.SrcIP,
			event.DestIP,
			blockedStr)
		
		eventCounts[key]++
	}
	
	for key, count := range eventCounts {
		parts := strings.Split(key, "|")
		if len(parts) != 7 {
			continue
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.securityEventInfo,
			prometheus.GaugeValue,
			float64(count),
			parts[0], // device_serial
			parts[1], // event_type
			parts[2], // priority
			parts[3], // protocol
			parts[4], // src_ip
			parts[5], // dest_ip
			parts[6], // blocked
		)
	}
}

func (c *MerakiCollector) collectTopApplications(ch chan<- prometheus.Metric) {
	if c.topApplicationsData == nil {
		return
	}
	
	appUsage := make(map[string]float64)
	
	for _, app := range c.topApplicationsData {
		appName := app.Name
		if appName == "" || appName == "unknown" {
			continue
		}
		
		appUsage[appName] += app.Total
	}
	
	for appName, totalUsage := range appUsage {
		ch <- prometheus.MustNewConstMetric(
			c.topAppUsage,
			prometheus.GaugeValue,
			totalUsage*1024,
			appName,
			"total",
		)
	}
}

func (c *MerakiCollector) collectTopApplicationCategories(ch chan<- prometheus.Metric) {
	if c.topAppCategoriesData == nil {
		return
	}
	
	catUsage := make(map[string]float64)
	
	for _, category := range c.topAppCategoriesData {
		categoryName := category.Category
		if categoryName == "" || categoryName == "unknown" {
			continue
		}
		
		catUsage[categoryName] += category.Total
	}
	
	for categoryName, totalUsage := range catUsage {
		ch <- prometheus.MustNewConstMetric(
			c.topAppCategoryUsage,
			prometheus.GaugeValue,
			totalUsage*1024,
			categoryName,
			"total",
		)
	}
}

func (c *MerakiCollector) collectTopClientManufacturers(ch chan<- prometheus.Metric) {
	if c.topClientManufacturers == nil {
		return
	}
	
	mfgUsage := make(map[string]float64)
	
	for _, manufacturer := range c.topClientManufacturers {
		mfgName := manufacturer.Manufacturer
		if mfgName == "" || mfgName == "unknown" {
			continue
		}
		
		mfgUsage[mfgName] += manufacturer.Usage.Total
	}
	
	for mfgName, totalUsage := range mfgUsage {
		ch <- prometheus.MustNewConstMetric(
			c.topClientManufacturerUsage,
			prometheus.GaugeValue,
			totalUsage*1024,
			mfgName,
			"total",
		)
	}
}

func (c *MerakiCollector) collectTopDevicesByUsage(ch chan<- prometheus.Metric) {
	if c.topDevicesByUsageData == nil {
		return
	}
	
	for _, device := range c.topDevicesByUsageData {
		deviceName := device.Name

		if deviceName == "" || deviceName == "unknown" {
			continue
		}
		
		networkName := device.Network.Name
		if networkName == "" {
			networkName = "unknown"
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.topDeviceUsage,
			prometheus.GaugeValue,
			device.Usage.Total*1024,
			deviceName,
			device.Model,
			device.Serial,
			networkName,
			"total",
		)
	}
}

func (c *MerakiCollector) collectTopSsids(ch chan<- prometheus.Metric) {
	if c.topSsidsData == nil {
		return
	}
	
	for _, ssid := range c.topSsidsData {
		ssidName := ssid.Name
		if ssidName == "" {
			ssidName = "unknown"
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.topSsidUsage,
			prometheus.GaugeValue,
			ssid.Usage.Total*1024,
			ssidName,
			"total",
		)
	}
}

func (c *MerakiCollector) collectTopSwitchesByEnergy(ch chan<- prometheus.Metric) {
	if c.topSwitchesByEnergyData == nil {
		return
	}
	
	for _, switchDevice := range c.topSwitchesByEnergyData {
		switchName := switchDevice.Name
		if switchName == "" {
			switchName = "unknown"
		}
		
		networkName := switchDevice.Network.Name
		if networkName == "" {
			networkName = "unknown"
		}
		
		ch <- prometheus.MustNewConstMetric(
			c.topSwitchEnergyUsage,
			prometheus.GaugeValue,
			switchDevice.Usage.Total,
			switchName,
			switchDevice.Model,
			switchDevice.Serial,
			networkName,
		)
	}
}

func (c *MerakiCollector) UpdateData() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	log.Info("Fetching data from Meraki API...")
	
	if networks, err := c.client.GetNetworks(); err != nil {
		log.Errorf("Failed to fetch networks: %v", err)
	} else {
		c.networkNames = make(map[string]string)
		for _, network := range networks {
			c.networkNames[network.ID] = network.Name
		}
	}
	
	if alerts, err := c.client.GetAlertsOverview(); err != nil {
		log.Errorf("Failed to fetch alerts overview: %v", err)
	} else {
		c.alertsData = alerts
	}
	
	if assuranceAlerts, err := c.client.GetAssuranceAlerts(); err != nil {
		log.Errorf("Failed to fetch assurance alerts: %v", err)
	} else {
		c.assuranceAlertsData = assuranceAlerts
	}
	
	if bandwidth, err := c.client.GetClientsBandwidthUsage(86400); err != nil {
		log.Errorf("Failed to fetch bandwidth usage: %v", err)
	} else {
		c.bandwidthUsageData = bandwidth
	}
	
	if overview, err := c.client.GetClientsOverview(86400); err != nil {
		log.Errorf("Failed to fetch clients overview: %v", err)
	} else {
		c.clientsOverviewData = overview
	}
	
	if devices, err := c.client.GetDevicesAvailabilities(); err != nil {
		log.Errorf("Failed to fetch device availabilities: %v", err)
	} else {
		c.devicesAvailData = devices
	}
	
	if uplinks, err := c.client.GetUplinksLossAndLatency(300); err != nil {
		log.Errorf("Failed to fetch uplinks loss and latency: %v", err)
	} else {
		c.uplinksData = uplinks
	}
	
	if appliances, err := c.client.GetTopAppliancesByUtilization(86400); err != nil {
		log.Errorf("Failed to fetch top appliances: %v", err)
	} else {
		c.topAppliancesData = appliances
	}
	
	if clients, err := c.client.GetTopClientsByUsage(86400); err != nil {
		log.Errorf("Failed to fetch top clients: %v", err)
	} else {
		c.topClientsData = clients
	}
	
	if topNetworks, err := c.client.GetTopNetworksByStatus(); err != nil {
		log.Errorf("Failed to fetch top networks by status: %v", err)
	} else {
		c.topNetworksData = topNetworks
	}
	
	if vpnStatuses, err := c.client.GetOrganizationApplianceVpnStatuses(); err != nil {
		log.Errorf("Failed to fetch VPN statuses: %v", err)
	} else {
		c.vpnStatusesData = vpnStatuses
	}
	
	if vpnStats, err := c.client.GetOrganizationApplianceVpnStats(86400); err != nil {
		log.Errorf("Failed to fetch VPN stats: %v", err)
	} else {
		c.vpnStatsData = vpnStats
	}
	
	if securityEvents, err := c.client.GetOrganizationApplianceSecurityEvents(86400); err != nil {
		log.Errorf("Failed to fetch security events: %v", err)
	} else {
		c.securityEventsData = securityEvents
	}
	
	if apps, err := c.client.GetOrganizationTopApplicationsByUsage(86400); err != nil {
		log.Errorf("Failed to fetch top applications: %v", err)
	} else {
		c.topApplicationsData = apps
	}
	
	if categories, err := c.client.GetOrganizationTopApplicationsCategoriesByUsage(86400); err != nil {
		log.Errorf("Failed to fetch top application categories: %v", err)
	} else {
		c.topAppCategoriesData = categories
	}
	
	if manufacturers, err := c.client.GetOrganizationTopClientsManufacturersByUsage(86400); err != nil {
		log.Errorf("Failed to fetch top client manufacturers: %v", err)
	} else {
		c.topClientManufacturers = manufacturers
	}
	
	if devices, err := c.client.GetOrganizationTopDevicesByUsage(86400); err != nil {
		log.Errorf("Failed to fetch top devices by usage: %v", err)
	} else {
		c.topDevicesByUsageData = devices
	}
	
	if ssids, err := c.client.GetOrganizationTopSsidsByUsage(86400); err != nil {
		log.Errorf("Failed to fetch top SSIDs: %v", err)
	} else {
		c.topSsidsData = ssids
	}
	
	if switches, err := c.client.GetOrganizationTopSwitchesByEnergyUsage(86400); err != nil {
		log.Errorf("Failed to fetch top switches by energy: %v", err)
	} else {
		c.topSwitchesByEnergyData = switches
	}
	
	log.Info("Data fetch complete")
}
