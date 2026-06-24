package version

import "fmt"

const ServiceName = "AgentShield-eBPF"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("%s version=%s commit=%s date=%s", ServiceName, Version, Commit, Date)
}
