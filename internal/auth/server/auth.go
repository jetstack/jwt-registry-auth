package server

import (
	"net/http"

	"github.com/docker/distribution/registry/auth"
)

// AuthRequest is an authorization request
type AuthRequest struct {
	Service  string
	Username string
	Password string
	Access   []auth.Access
}

func newAuthRequest(r *http.Request) AuthRequest {
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
