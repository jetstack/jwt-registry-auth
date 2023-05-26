package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/docker/distribution/registry/auth"
	"github.com/jetstack/jwt-registry-auth/internal/auth/server/token"

	dcontext "github.com/distribution/distribution/v3/context"
)

// Server handles authentication and authorization for registry requests
type Server struct {
	issuer        *token.Issuer
	listenAddress string
	providers     map[string]Provider
	tokenPath     string
}

// NewServer returns a new token server
func NewServer(ctx context.Context, cfg *Config) (*Server, error) {
	s := &Server{
		listenAddress: cfg.Server.ListenAddress,
		tokenPath:     cfg.Server.TokenPath,
	}

	dcontext.GetLogger(ctx).Info("Creating token issuer")
	issuer, err := token.NewIssuer(
		cfg.Token.Issuer,
		cfg.Token.CertFile,
		cfg.Token.KeyFile,
		token.WithTokenDuration(cfg.Token.Duration),
	)
	if err != nil {
		return nil, fmt.Errorf("creating token issuer: %w", err)
	}
	s.issuer = issuer

	dcontext.GetLogger(ctx).Info("Creating providers")
	providers := map[string]Provider{}
	for _, cfg := range cfg.Providers {
		if _, ok := providers[cfg.Name]; ok {
			return nil, fmt.Errorf("duplicate provider already registered: %s", cfg.Name)
		}

		dcontext.GetLogger(ctx).Infof("Creating provider: %s", cfg.Name)
		p, err := NewProvider(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("creating provider %q: %w", cfg.Name, err)
		}

		providers[cfg.Name] = p
	}
	s.providers = providers

	return s, nil
}

// ListenAndServe runs the http server
func (h *Server) ListenAndServe() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(h.tokenPath, h.tokenHandler)

	return http.ListenAndServe(h.listenAddress, mux)
}

func (h *Server) tokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := dcontext.WithRequest(dcontext.Background(), r)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	req := getRequest(r)

	// Authenticate the request with the requested provider
	p, ok := h.providers[req.Username]
	if !ok {
		dcontext.GetLogger(ctx).Infof("requested provider not registered: %s", req.Username)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	accessRecords, err := p.Authorize(ctx, req)
	if errors.Is(err, ErrUnauthorized) {
		dcontext.GetLogger(ctx).Infof("unauthorized request with provider %q: %s", req.Username, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		dcontext.GetLogger(ctx).Infof("bad request with provider %q: %s", req.Username, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Create a token with the permitted access
	jwt, err := h.issuer.CreateToken(req.Service, req.Username, accessRecords)
	if err != nil {
		dcontext.GetLogger(ctx).WithError(err).Error("creating token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return the token
	if err := json.NewEncoder(w).Encode(&map[string]string{"access_token": jwt, "token": jwt}); err != nil {
		dcontext.GetLogger(ctx).WithError(err).Error("encoding response to json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
}

func getRequest(r *http.Request) AuthRequest {
	username, password, ok := r.BasicAuth()
	if !ok {
		user := r.FormValue("username")
		if user != "" {
			username = user
		}
		// password could be part of form data
		pass := r.FormValue("password")
		if pass != "" {
			password = pass
		}
	}

	q := r.URL.Query()

	return AuthRequest{
		Username: username,
		Password: password,
		Service:  q.Get("service"),
		Access:   scopesToAccessList(q["scope"]),
	}
}

func scopesToAccessList(scopeSpecs []string) []auth.Access {
	requestedAccessSet := make(map[auth.Access]struct{}, 2*len(scopeSpecs))

	for _, scopeSpecifier := range scopeSpecs {
		// There should be 3 parts, separated by a `:` character.
		parts := strings.SplitN(scopeSpecifier, ":", 3)

		if len(parts) != 3 {
			continue
		}

		resourceType, resourceName, actions := parts[0], parts[1], parts[2]

		resourceType, resourceClass := splitResourceClass(resourceType)
		if resourceType == "" {
			continue
		}

		// Actions should be a comma-separated list of actions.
		for _, action := range strings.Split(actions, ",") {
			requestedAccess := auth.Access{
				Resource: auth.Resource{
					Type:  resourceType,
					Class: resourceClass,
					Name:  resourceName,
				},
				Action: action,
			}

			// Add this access to the requested access set.
			requestedAccessSet[requestedAccess] = struct{}{}
		}
	}

	requestedAccessList := make([]auth.Access, 0, len(requestedAccessSet))
	for requestedAccess := range requestedAccessSet {
		requestedAccessList = append(requestedAccessList, requestedAccess)
	}

	return requestedAccessList
}

var typeRegexp = regexp.MustCompile(`^([a-z0-9]+)(\([a-z0-9]+\))?$`)

func splitResourceClass(t string) (string, string) {
	matches := typeRegexp.FindStringSubmatch(t)
	if len(matches) < 2 {
		return "", ""
	}
	if len(matches) == 2 || len(matches[2]) < 2 {
		return matches[1], ""
	}
	return matches[1], matches[2][1 : len(matches[2])-1]
}
