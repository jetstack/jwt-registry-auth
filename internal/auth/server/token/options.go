package token

import "time"

// Option is a functional option that configures an issuer
type Option func(*Issuer)

// WithTokenDuration sets the duration of tokens issued by the issuer
func WithTokenDuration(tokenDuration time.Duration) Option {
	return func(i *Issuer) {
		i.tokenDuration = tokenDuration
	}
}
