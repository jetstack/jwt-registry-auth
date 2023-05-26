package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/auth"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

var (
	amazonKeychain authn.Keychain = authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard)))
	azureKeychain  authn.Keychain = authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper())
)

type registryProxy struct {
	ac        auth.AccessController
	registry  name.Registry
	remoteURL *url.URL
}

// NewRegistryProxy returns a new reverse proxy for a registry
func NewRegistryProxy(registry name.Registry, opts ...Option) (http.Handler, error) {
	remoteURL, err := url.Parse(fmt.Sprintf("%s://%s", registry.Scheme(), registry.Name()))
	if err != nil {
		return nil, fmt.Errorf("parsing remote url from registry: %w", err)
	}
	proxy := &registryProxy{
		registry:  registry,
		remoteURL: remoteURL,
	}
	for _, o := range opts {
		o(proxy)
	}

	return proxy, nil
}

// ServeHTTP proxies requests to the upstream registry
func (p *registryProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := dcontext.WithRequest(dcontext.Background(), r)
	ctx = dcontext.WithLogger(ctx, dcontext.GetRequestLogger(ctx))

	// Serve 200 from the root without authentication
	if r.URL.Path == "/" {
		dcontext.GetLogger(ctx).Info("Serving request")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Authorize the required access with the configured access controller
	if p.ac != nil {
		// Figure out the access required from the request
		accessRecords, err := requiredAccess(r)
		if err != nil {
			dcontext.GetLogger(ctx).Errorf("getting access records: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		dcontext.GetLogger(ctx).Infof("Authorizing access records: %v", accessRecords)
		ctx, err = p.ac.Authorized(ctx, accessRecords...)
		if err != nil {
			switch err := err.(type) {
			case auth.Challenge:
				// Add the appropriate WWW-Auth header
				err.SetHeaders(r, w)
				w.WriteHeader(http.StatusUnauthorized)
			default:
				dcontext.GetLogger(ctx).Errorf("authorizing request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
			}
			return
		}
	}

	// Handle /v2/ ourselves
	if r.URL.Path == "/v2/" {
		dcontext.GetLogger(ctx).Info("Serving request")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Create the reverse proxy handler
	proxy, err := p.newReverseProxy(ctx, r)
	if err != nil {
		dcontext.GetLogger(ctx).WithError(err).Error("creating reverse proxy")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Proxy the request
	dcontext.GetLogger(ctx).Info("Proxying request")
	proxy.ServeHTTP(w, r)
}

func (p *registryProxy) newReverseProxy(ctx context.Context, r *http.Request) (http.Handler, error) {
	// Get the required scopes from the request
	accessRecords, err := requiredAccess(r)
	if err != nil {
		return nil, fmt.Errorf("getting required access: %w", err)
	}
	var scopes []string
	for _, access := range accessRecords {
		scopes = append(scopes, fmt.Sprintf("%s:%s:%s", access.Type, access.Name, access.Action))
	}

	// Create an authenticator for the upstream registry that uses credentials
	// from the default keychain and ambient credential providers
	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		github.Keychain,
		amazonKeychain,
		azureKeychain,
	)
	authenticator, err := keychain.Resolve(p.registry)
	if err != nil {
		return nil, fmt.Errorf("resolving keychain: %w", err)
	}

	// Build a transport that wraps the default transport with the authenticator
	tr, err := transport.NewWithContext(
		ctx,
		p.registry,
		authenticator,
		http.DefaultTransport,
		scopes,
	)
	if err != nil {
		return nil, fmt.Errorf("creating transport: %w", err)
	}

	// Create the proxy
	proxy := httputil.NewSingleHostReverseProxy(p.remoteURL)

	// Add the custom transport
	proxy.Transport = tr

	// Customize the proxy director to add X-Forwarded headers and ensure
	// the host value matches the upstream registry
	proxy.Director = func(req *http.Request) {
		// Support TLS upstream from HTTP connections
		req.URL.Host = p.remoteURL.Host
		req.URL.Scheme = p.remoteURL.Scheme
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
		req.Host = p.remoteURL.Host
	}

	// Modify the response before returning it to the client
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Rewrite any Location headers that specify the upstream
		// registry so that they point back at the proxy.
		location, err := resp.Location()
		if err == nil {
			if location.Host == p.remoteURL.Host {
				location.Host = r.Host
				resp.Header.Set("Location", location.String())
			}
		}

		return nil
	}

	return proxy, nil
}

func repoName(path string) string {
	components := strings.Split(path, "/")

	if len(components) < 4 {
		return ""
	}

	index := -1
	for i, comp := range components {
		if comp == "manifests" || comp == "blobs" || comp == "tags" {
			index = i
		}
	}

	if index == -1 {
		return ""
	}

	return strings.Join(components[2:index], "/")
}

func requiredAccess(r *http.Request) ([]auth.Access, error) {
	repo := repoName(r.URL.Path)

	var accessRecords []auth.Access
	if repo != "" {
		accessRecords = appendAccessRecords(accessRecords, r.Method, repo)
		if fromRepo := r.FormValue("from"); fromRepo != "" {
			// mounting a blob from one repository to another requires pull (GET)
			// access to the source repository.
			accessRecords = appendAccessRecords(accessRecords, http.MethodGet, fromRepo)
		}
	} else {
		switch r.URL.Path {
		case "/v2/":
		case "/v2/_catalog":
			accessRecords = append(accessRecords,
				auth.Access{
					Resource: auth.Resource{
						Type: "registry",
						Name: "catalog",
					},
					Action: "*",
				})
		default:
			return nil, fmt.Errorf("forbidden: no repository name")
		}
	}

	return accessRecords, nil
}

func appendAccessRecords(records []auth.Access, method string, repo string) []auth.Access {
	resource := auth.Resource{
		Type: "repository",
		Name: repo,
	}

	switch method {
	case http.MethodGet, http.MethodHead:
		records = append(records,
			auth.Access{
				Resource: resource,
				Action:   "pull",
			})
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		records = append(records,
			auth.Access{
				Resource: resource,
				Action:   "pull",
			},
			auth.Access{
				Resource: resource,
				Action:   "push",
			})
	case http.MethodDelete:
		records = append(records,
			auth.Access{
				Resource: resource,
				Action:   "delete",
			})
	}
	return records
}
