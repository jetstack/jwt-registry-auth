package proxy

import "github.com/distribution/distribution/v3/registry/auth"

// Option is a functional option that configures the proxy
type Option func(p *registryProxy)

// WithAccessController is a functional option that confgiures the access
// controller on the proxy
func WithAccessController(ac auth.AccessController) Option {
	return func(p *registryProxy) {
		p.ac = ac
	}
}
