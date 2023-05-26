package main

import (
	"fmt"
	"net/http"

	"github.com/distribution/distribution/v3/registry/auth"
	_ "github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/jetstack/jwt-registry-auth/internal/auth/proxy"
	"github.com/spf13/cobra"
)

type options struct {
	ListenAddress string
	Registry      registryOptions
	Token         tokenOptions
}

type registryOptions struct {
	Insecure bool
}

type tokenOptions struct {
	AutoRedirect   bool
	Realm          string
	Service        string
	Issuer         string
	RootCertBundle string
}

func main() {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "registry-auth-proxy",
		Short: "A reverse proxy for a container registry that offloads authentication to a Token Authentication server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected exactly one argument")
			}

			// Create the access controller
			accessController, err := auth.GetAccessController("token", map[string]interface{}{
				"autoredirect":   opts.Token.AutoRedirect,
				"realm":          opts.Token.Realm,
				"service":        opts.Token.Service,
				"issuer":         opts.Token.Issuer,
				"rootcertbundle": opts.Token.RootCertBundle,
			})
			if err != nil {
				return fmt.Errorf("creating access controller: %w", err)
			}

			// Parse the registry host
			var nOpts []name.Option
			if opts.Registry.Insecure {
				nOpts = append(nOpts, name.Insecure)
			}
			registry, err := name.NewRegistry(args[0], nOpts...)
			if err != nil {
				return fmt.Errorf("parsing registry host: %w", err)
			}

			// Create the proxy
			pr, err := proxy.NewRegistryProxy(registry, proxy.WithAccessController(accessController))
			if err != nil {
				return fmt.Errorf("creating registry proxy: %w", err)
			}

			http.Handle("/", pr)

			return http.ListenAndServe(opts.ListenAddress, nil)
		},
	}

	cmd.Flags().StringVar(
		&opts.ListenAddress,
		"listen-address",
		":5000",
		"Listen address.",
	)
	cmd.Flags().BoolVar(
		&opts.Registry.Insecure,
		"registry-insecure",
		false,
		"Connect to the remote registry via HTTP.",
	)
	cmd.Flags().BoolVar(
		&opts.Token.AutoRedirect,
		"token-auto-redirect",
		false,
		"When set to true, realm will automatically be set using the Host header of the request as the domain and a path of /auth/token",
	)
	cmd.Flags().StringVar(
		&opts.Token.Realm,
		"token-realm",
		"",
		"The realm in which the registry server authenticates. This is the URL which the client is directed to.",
	)
	cmd.Flags().StringVar(
		&opts.Token.Service,
		"token-service",
		"",
		"The service being authenticated. Typically the hostname of the proxy.",
	)
	cmd.Flags().StringVar(
		&opts.Token.Issuer,
		"token-issuer",
		"",
		"The name of the token issuer. The issuer inserts this into the token so it must match the value configured for the issuer.",
	)
	cmd.Flags().StringVar(
		&opts.Token.RootCertBundle,
		"token-root-cert-bundle",
		"",
		"The absolute path to the root certificate bundle. This bundle contains the public part of the certificates used to sign authentication tokens.",
	)

	cmd.MarkFlagRequired("token-issuer")
	cmd.MarkFlagRequired("token-service")
	cmd.MarkFlagRequired("token-root-cert-bundle")

	cmd.Execute()
}
