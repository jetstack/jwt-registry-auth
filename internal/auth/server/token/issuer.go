package token

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/docker/distribution/registry/auth"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
)

// Issuer issues tokens
type Issuer struct {
	issuer        string
	tokenDuration time.Duration
	pubKey        libtrust.PublicKey
	privKey       libtrust.PrivateKey
	sigAlg        string
}

// NewIssuer creates a new issuer
func NewIssuer(issuer, certFile, keyFile string, opts ...Option) (*Issuer, error) {
	pubKey, privKey, err := loadCertAndKey(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading certificate and key file: %w", err)
	}

	// Figure out the signing algorithm by signing some dummy data
	// TODO: there must be a better way to do this
	_, sigAlg, err := privKey.Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to sign dummy data: %w", err)
	}

	i := &Issuer{
		issuer:  issuer,
		pubKey:  pubKey,
		privKey: privKey,
		sigAlg:  sigAlg,
	}
	for _, opt := range opts {
		opt(i)
	}

	return i, nil
}

// CreateToken issues a new token
func (i *Issuer) CreateToken(audience, subject string, accessList []auth.Access) (string, error) {
	now := time.Now()

	header := token.Header{
		Type:       "JWT",
		SigningAlg: i.sigAlg,
		KeyID:      i.pubKey.KeyID(),
	}

	claims := token.ClaimSet{
		Issuer:     i.issuer,
		Subject:    subject,
		Audience:   audience,
		NotBefore:  now.Add(-10 * time.Second).Unix(),
		IssuedAt:   now.Unix(),
		Expiration: now.Add(i.tokenDuration).Unix(),
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     accessListToResourceActions(accessList),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %s", err)
	}
	payload := fmt.Sprintf("%s%s%s", joseBase64UrlEncode(headerJSON), token.TokenSeparator, joseBase64UrlEncode(claimsJSON))

	sig, _, err := i.privKey.Sign(strings.NewReader(payload), 0)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, joseBase64UrlEncode(sig)), nil
}

func loadCertAndKey(certFile string, keyFile string) (pk libtrust.PublicKey, prk libtrust.PrivateKey, err error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	pk, err = libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return
	}
	prk, err = libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	return
}

func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func accessListToResourceActions(grantedAccessList []auth.Access) []*token.ResourceActions {
	resourceActionSets := make(map[auth.Resource]map[string]struct{}, len(grantedAccessList))
	for _, access := range grantedAccessList {
		actionSet, exists := resourceActionSets[access.Resource]
		if !exists {
			actionSet = map[string]struct{}{}
			resourceActionSets[access.Resource] = actionSet
		}
		actionSet[access.Action] = struct{}{}
	}

	accessEntries := make([]*token.ResourceActions, 0, len(resourceActionSets))
	for resource, actionSet := range resourceActionSets {
		actions := make([]string, 0, len(actionSet))
		for action := range actionSet {
			actions = append(actions, action)
		}

		accessEntries = append(accessEntries, &token.ResourceActions{
			Type:    resource.Type,
			Class:   resource.Class,
			Name:    resource.Name,
			Actions: actions,
		})
	}

	return accessEntries
}
