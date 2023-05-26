package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/docker/distribution/registry/auth"
	"github.com/google/cel-go/cel"
	"github.com/hashicorp/cap/jwt"
)

// ErrUnauthorized is returned when a request can't be authorized
var ErrUnauthorized = fmt.Errorf("unauthorized")

// Provider authorizes tokens
type Provider interface {
	// Authorize a request and return the subset of requested actions it is permitted to
	// perform
	Authorize(ctx context.Context, req AuthRequest) ([]auth.Access, error)
}

type provider struct {
	oidcDiscoveryURL string
	staticKeys       []crypto.PublicKey
	authnCondition   cel.Program
	authzCondition   cel.Program
}

// NewProvider returns a new provider
func NewProvider(ctx context.Context, cfg ProviderConfig) (Provider, error) {
	if cfg.OIDCDiscoveryURL != "" && len(cfg.StaticKeys) > 0 {
		return nil, fmt.Errorf("only one of oidcDiscoveryURL or staticKeys must be provided")
	}

	p := &provider{}

	switch {
	case cfg.OIDCDiscoveryURL != "":
		if _, err := jwt.NewOIDCDiscoveryKeySet(ctx, cfg.OIDCDiscoveryURL, ""); err != nil {
			return nil, fmt.Errorf("validating oidcDiscoveryURL: %w", err)
		}

		p.oidcDiscoveryURL = cfg.OIDCDiscoveryURL
	case len(cfg.StaticKeys) > 0:
		var staticKeys []crypto.PublicKey
		for _, k := range cfg.StaticKeys {
			key, err := parsePublicKeyPEM([]byte(k.Key))
			if err != nil {
				return nil, fmt.Errorf("parsing static key: %w", err)
			}

			staticKeys = append(staticKeys, key)
		}

		if _, err := jwt.NewStaticKeySet(staticKeys); err != nil {
			return nil, fmt.Errorf("validating staticKeys: %w", err)
		}

		p.staticKeys = staticKeys
	default:
		return nil, fmt.Errorf("must configure oidcDiscoveryURL or staticKeys option")
	}

	if cfg.Authentication.Condition != "" {
		env, err := cel.NewEnv(
			cel.Variable("service", cel.StringType),
			cel.Variable("claims", cel.MapType(cel.StringType, cel.AnyType)),
		)

		ast, issues := env.Compile(cfg.Authentication.Condition)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("type checking authn condition: %w", issues.Err())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("constructing authn condition program: %w", err)
		}

		// TODO: validate condition returns boolean

		p.authnCondition = prg
	}

	if cfg.Authorization.Condition != "" {
		env, err := cel.NewEnv(
			cel.Variable("service", cel.StringType),
			cel.Variable("claims", cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("scope", cel.MapType(cel.StringType, cel.StringType)),
		)

		ast, issues := env.Compile(cfg.Authorization.Condition)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("type checking authz condition: %w", issues.Err())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("constructing authz condition program: %w", err)
		}

		// TODO: validate condition returns boolean

		p.authzCondition = prg
	}

	return p, nil
}

// Authorize a token and return the subset of requested actions it is permitted to
// perform
func (p *provider) Authorize(ctx context.Context, req AuthRequest) ([]auth.Access, error) {
	var (
		keySet jwt.KeySet
		err    error
	)

	switch {
	case p.oidcDiscoveryURL != "":
		keySet, err = jwt.NewOIDCDiscoveryKeySet(ctx, p.oidcDiscoveryURL, "")
		if err != nil {
			return nil, fmt.Errorf("creating OIDC discovery keyset: %w", err)
		}
	case len(p.staticKeys) > 0:
		keySet, err = jwt.NewStaticKeySet(p.staticKeys)
		if err != nil {
			return nil, fmt.Errorf("creating keyset from static keys: %w", err)
		}
	default:
		return nil, fmt.Errorf("no validator configured")
	}

	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		return nil, fmt.Errorf("configuring JWT validator: %w", err)
	}

	claims, err := validator.Validate(ctx, req.Password, jwt.Expected{})
	if err != nil {
		// TODO: make a distinction between an invalid token and an
		// unauthorized one
		return nil, ErrUnauthorized
	}

	// Apply authentication condition to the claims
	if p.authnCondition != nil {
		out, _, err := p.authnCondition.Eval(map[string]interface{}{
			"service": req.Service,
			"claims":  claims,
		})
		if err != nil {
			return nil, fmt.Errorf("evaluating auth condition: %w", err)
		}

		allowed, ok := out.Value().(bool)
		if !ok {
			return nil, fmt.Errorf("response from auth condition is not a bool: %w", err)
		}
		if !allowed {
			return nil, ErrUnauthorized
		}
	}

	// If an authz conditon isn't set then just return the full set of
	// requested access
	if p.authzCondition == nil {
		return req.Access, nil
	}

	// Filter access based on the authz condition
	var allowedAccess []auth.Access
	for _, accessRecord := range req.Access {
		scope := map[string]string{
			"type":   accessRecord.Type,
			"name":   accessRecord.Name,
			"action": accessRecord.Action,
			"class":  accessRecord.Class,
		}
		out, _, err := p.authzCondition.Eval(map[string]interface{}{
			"service": req.Service,
			"claims":  claims,
			"scope":   scope,
		})
		if err != nil {
			return nil, fmt.Errorf("evaluating authz condition: %w", err)
		}

		allowed, ok := out.Value().(bool)
		if !ok {
			return nil, fmt.Errorf("response from authz condition is not a bool: %w", err)
		}
		if !allowed {
			continue
		}

		allowedAccess = append(allowedAccess, accessRecord)
	}

	return allowedAccess, nil
}

func parsePublicKeyPEM(data []byte) (interface{}, error) {
	block, data := pem.Decode(data)
	if block != nil {
		if len(bytes.TrimSpace(data)) > 0 {
			return nil, fmt.Errorf("unexpected trailing data after parsed PEM block")
		}
		var rawKey interface{}
		var err error
		if rawKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				rawKey = cert.PublicKey
			} else {
				return nil, err
			}
		}

		switch key := rawKey.(type) {
		case *rsa.PublicKey:
			return key, nil
		case *ecdsa.PublicKey:
			return key, nil
		case ed25519.PublicKey:
			return key, nil
		}
	}
	return nil, fmt.Errorf("data does not contain any valid public keys")
}
