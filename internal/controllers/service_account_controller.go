package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ServiceAccountController manages pull secrets for ServiceAccounts
type ServiceAccountController struct {
	client.Client
	Username      string
	Registry      name.Registry
	TokenDuration time.Duration
}

// SetupWithManager adds the controller to a manager
func (c *ServiceAccountController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}).
		Complete(c)
}

// Reconcile ensures that there is an image pull secret for the given service
// account
func (c *ServiceAccountController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.LoggerFrom(ctx).WithName("serviceaccount-controller").WithValues("serviceaccount", req)

	logger.Info("Reconciling service account")

	// The name of the secret we create is deterministic
	// TODO: think about putting something bettwen SA name and 'pull-secret'
	// here to make it more unique and reduce the potential for clashes
	// TODO: think about name length limits and truncation?
	secretName := fmt.Sprintf("%s-pull-secret", req.Name)

	// The secret we will create/update/delete
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: req.Namespace,
		},
	}

	// Get the existing service account
	serviceAccount := &corev1.ServiceAccount{}
	if err := c.Get(ctx, req.NamespacedName, serviceAccount); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, err
		}
		// If the service account doesn't exist, then clean up the pull
		// secret
		return ctrl.Result{}, client.IgnoreNotFound(c.Delete(ctx, secret))
	}

	// Create token for service account
	exp := int64(c.TokenDuration.Seconds())
	logger.Info("Creating token for service account")
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{
				fmt.Sprintf("%s://%s", c.Registry.Scheme(), c.Registry.String()),
			},
			ExpirationSeconds: &exp,
		},
	}
	if err := c.SubResource("token").Create(ctx, serviceAccount, tokenRequest); err != nil {
		return ctrl.Result{}, fmt.Errorf("creating token: %w", err)
	}

	// Create docker config with token
	cfg := struct {
		Auths map[string]authn.AuthConfig `json:"auths,omitempty"`
	}{
		Auths: map[string]authn.AuthConfig{
			c.Registry.String(): {
				Username: c.Username,
				Password: tokenRequest.Status.Token,
			},
		},
	}
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("marshaling config to json: %w", err)
	}

	// Create/Update pull secret
	logger.Info("Creating/updating pull secret for serviceaccount")
	if _, err := controllerutil.CreateOrUpdate(ctx, c, secret, func() error {
		secret.Type = corev1.SecretTypeDockerConfigJson
		secret.Data = map[string][]byte{
			corev1.DockerConfigJsonKey: cfgData,
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("Creating/updating pull secret for %s: %w", req, err)
	}

	// If the service account is already associated with the pull secret
	// then we don't need to update it
	var update bool
	if !hasSecret(secretName, serviceAccount) {
		serviceAccount.Secrets = append(serviceAccount.Secrets, corev1.ObjectReference{Name: secretName, Namespace: req.Namespace})
		update = true
	}
	if !hasPullSecret(secretName, serviceAccount) {
		serviceAccount.ImagePullSecrets = append(serviceAccount.ImagePullSecrets, corev1.LocalObjectReference{Name: secretName})
		update = true
	}
	if update {
		// Update service account with pull secret
		logger.Info("Adding pull secret to service account")
		if err := c.Update(ctx, serviceAccount); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating service account pull secrets: %w", err)
		}
	}

	// We want to make sure the token is rotated in good time, so requeue
	// rotation for 1/3 of the time until it expires. Add a jitter so that
	// the rotation is smoothed out a bit between different service
	// accounts.
	requeueAfter := requeueJitter(tokenRequest.Status.ExpirationTimestamp.Sub(time.Now()))

	logger.Info("Finished reconciling", "requeueAfter", fmt.Sprintf("%s", requeueAfter))

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

func hasSecret(secretName string, serviceAccount *corev1.ServiceAccount) bool {
	for _, s := range serviceAccount.Secrets {
		if s.Name == secretName {
			return true
		}
	}

	return false
}

func hasPullSecret(secretName string, serviceAccount *corev1.ServiceAccount) bool {
	for _, s := range serviceAccount.ImagePullSecrets {
		if s.Name == secretName {
			return true
		}
	}

	return false
}

func requeueJitter(d time.Duration) time.Duration {
	return time.Duration((float64(d.Nanoseconds()) * 1 / 3) * (rand.Float64() + 1.50) / 2)
}
