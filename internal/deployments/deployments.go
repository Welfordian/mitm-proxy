package deployments

import "time"

type Current struct {
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	ConfigPath  string    `json:"config_path,omitempty"`
	ListenAddr  string    `json:"listen_addr"`
	MITMEnabled bool      `json:"mitm_enabled"`
}

type Profile struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

func DefaultProfiles() []Profile {
	return []Profile{
		{Name: "local", Kind: "local", Description: "Single developer workstation with localhost admin access."},
		{Name: "LAN test", Kind: "lan", Description: "Controlled lab network with explicit client consent and a configured admin token."},
		{Name: "Docker", Kind: "docker", Description: "Containerized proxy with mounted config, cache, and CA storage."},
		{Name: "systemd", Kind: "systemd", Description: "Linux service managed by systemd with file-based configuration reloads."},
	}
}
