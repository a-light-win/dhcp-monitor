package dhcp

type DhcpMonitorConfig struct {
	WebhookURL string   `validate:"required" help:"URL to send DHCP events to"`
	IfaceNames []string `help:"Network interfaces to monitor DHCP traffic on"`
}
