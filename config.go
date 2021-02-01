package oidcauth

import (
	"errors"
	"log"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Config represents available options for oidcauth.
type Config struct {
	// ClientID is the OAUTH2 Client ID
	// Default value is: (read from OS ENV: OAUTH2_CLIENT_ID)
	ClientID string

	// ClientSecret is the OAUTH2 Client Secret
	// Default value is: (read from OS ENV: OAUTH2_CLIENT_SECRET)
	ClientSecret string

	// IssuerURL is the root URL to theIdentity Provider
	// Default value is: "https://accounts.google.com"
	IssuerURL string

	// RedirectURL is the path that the Identity Provider will redirect clients to
	// Default value is: "http://127.0.0.1:5556/auth/google/callback"
	RedirectURL string

	// Scopes is a list of OIDC Scopes to request.
	// Default value is: []string{oidc.ScopeOpenID, "profile", "email"}
	Scopes []string
}

// DefaultConfig will create a new config object with defaults
// NOTE: This matches the examples on https://github.com/coreos/go-oidc/tree/v3/example
func DefaultConfig() (c *Config) {
	c = &Config{
		ClientID:     os.Getenv("GOOGLE_OAUTH2_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_OAUTH2_CLIENT_SECRET"),
		IssuerURL:    "https://accounts.google.com",
		RedirectURL:  "http://127.0.0.1:5556/auth/google/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return
}

// Validate will validate the Config
func (c Config) Validate() (err error) {

	if c.ClientID == "" {
		err = errors.New("ClientID Is required")
		return
	}

	if c.ClientSecret == "" {
		err = errors.New("ClientSecret Is required")
		return
	}

	if c.IssuerURL == "" { // TODO: Validate that its a properly formed URL
		err = errors.New("IssuerURL Is required")
		return
	}

	if c.RedirectURL == "" { // TODO: Validate that its a properly formed URL
		err = errors.New("RedirectURL Is required")
		return
	}

	return
}

// GetOidcAuth returns the configured OIDC authentication controller?
func (c *Config) GetOidcAuth() (o *OidcAuth, err error) {
	err = c.Validate()
	if err != nil {
		log.Fatal(err)
	}
	return newOidcAuth(c)
}
