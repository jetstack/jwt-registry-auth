package main

import (
	"fmt"

	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/jetstack/jwt-registry-auth/internal/auth/server"
	"github.com/spf13/cobra"
)

type options struct {
	ConfigFile string
}

func main() {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "token-server",
		Short: "Provides token-based authentication and authorization for a container registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := dcontext.Background()

			cfg, err := server.LoadConfigFromFile(opts.ConfigFile)
			if err != nil {
				return fmt.Errorf("loading config file: %w", err)
			}

			s, err := server.NewServer(ctx, cfg)
			if err != nil {
				return fmt.Errorf("creating new server: %w", err)
			}

			return s.ListenAndServe()
		},
	}

	cmd.Flags().StringVar(
		&opts.ConfigFile,
		"config-file",
		"config.yaml",
		"Config file path",
	)

	cmd.MarkFlagRequired("config-file")

	cmd.Execute()
}
