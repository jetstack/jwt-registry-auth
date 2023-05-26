package server

import (
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// Config configures the auth server
type Config struct {
	Server    ServerConfig     `yaml:"server"`
	Token     TokenConfig      `yaml:"token"`
	Providers []ProviderConfig `yaml:"providers"`
}

// LoadConfigFromFile loads configuration from a file
func LoadConfigFromFile(filePath string) (*Config, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	return LoadConfig(f)
}

// LoadConfig loads configuration from an io.Reader
func LoadConfig(r io.Reader) (*Config, error) {
	d := yaml.NewDecoder(r)
	d.SetStrict(true)

	cfg := &Config{
		Server: ServerConfig{
			ListenAddress: ":5000",
			TokenPath:     "/auth/token",
		},
		Token: TokenConfig{
			Duration: 15 * time.Minute,
		},
	}
	if err := d.Decode(cfg); err != nil {
		return nil, fmt.Errorf("could not parse config: %s", err)
	}

	return cfg, nil
}

// ServerConfig configures the server
type ServerConfig struct {
	ListenAddress string `yaml:"listenAddress"`
	TokenPath     string `yaml:"tokenPath"`
}

// TokenConfig configures the tokens issed by the server
type TokenConfig struct {
	CertFile string        `yaml:"certificate"`
	Issuer   string        `yaml:"issuer"`
	KeyFile  string        `yaml:"key"`
	Duration time.Duration `yaml:"duration"`
}

// ProviderConfig configures an authentication provider
type ProviderConfig struct {
	Name             string               `yaml:"name"`
	OIDCDiscoveryURL string               `yaml:"oidcDiscoveryURL"`
	StaticKeys       []StaticKeyConfig    `yaml:"staticKeys"`
	Authentication   AuthenticationConfig `yaml:"authn"`
	Authorization    AuthorizationConfig  `yaml:"authz"`
}

// StaticKeyConfig
type StaticKeyConfig struct {
	Key string `yaml:"key"`
}

// AuthenticationConfig
type AuthenticationConfig struct {
	Condition string
}

// AuthorizationConfig
type AuthorizationConfig struct {
	Condition string
}
