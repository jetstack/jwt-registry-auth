package main

import (
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/jetstack/jwt-registry-auth/internal/controllers"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type options struct {
	RegistryHost     string
	RegistryUsername string
	TokenDuration    time.Duration
}

func main() {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "kube-controller",
		Short: "A Kubernetes controller that enables contaier registry auth with service account tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{})))

			scheme := runtime.NewScheme()

			_ = clientgoscheme.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)

			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:         scheme,
				LeaderElection: false,
			})
			if err != nil {
				return fmt.Errorf("creating new manager: %w", err)
			}

			reg, err := name.NewRegistry(opts.RegistryHost)
			if err != nil {
				return fmt.Errorf("parsing registry: %s: %w", opts.RegistryHost, err)
			}

			serviceAccountController := &controllers.ServiceAccountController{
				Client:        mgr.GetClient(),
				TokenDuration: opts.TokenDuration,
				Registry:      reg,
				Username:      opts.RegistryUsername,
			}
			if err := serviceAccountController.SetupWithManager(mgr); err != nil {
				return fmt.Errorf("setting controller up with manager: %w", err)
			}

			return mgr.Start(ctrl.SetupSignalHandler())
		},
	}

	cmd.Flags().StringVar(
		&opts.RegistryHost,
		"registry-host",
		"",
		"Registry host",
	)
	cmd.Flags().StringVar(
		&opts.RegistryUsername,
		"registry-username",
		"",
		"Registry username",
	)
	cmd.Flags().DurationVar(
		&opts.TokenDuration,
		"token-duration",
		10*time.Minute,
		"Token duration",
	)

	cmd.MarkFlagRequired("registry-host")
	cmd.MarkFlagRequired("registry-username")

	cmd.Execute()
}
