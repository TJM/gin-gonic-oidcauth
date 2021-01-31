package oidcauth

import (
	"errors"
	"log"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
)

const (
	defaultKey  = "github.com/TJM/gin-gonic-oidc-auth"
	errorFormat = "[oidcauth] ERROR! %s\n"
)

// Config represents all available options for oidc middleware.
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

	// State is a string that is passed to the authentication provider, and returned to validate we sent the reqest.
	// 	 Opaque value used to maintain state between the request and the callback.
	//   Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie.
	// Default value is: "DEPRECATED: we should be setting this here."
	State string

	// Nonce String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	//   The value is passed through unmodified from the Authentication Request to the ID Token.
	// Default value is: "I am not sure we should be setting this here."
	Nonce string

	// Scopes is a list of OIDC Scopes to request.
	// Default value is: []string{oidc.ScopeOpenID, "profile", "email"}
	Scopes []string
}

// DefaultConfig will create a new config object with defaults
func DefaultConfig() (c *Config) {
	c = &Config{
		ClientID:     os.Getenv("OAUTH2_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH2_CLIENT_SECRET"),
		IssuerURL:    "https://accounts.google.com",
		RedirectURL:  "http://127.0.0.1:5556/auth/google/callback",
		State:        "I am not sure we should be setting this here.",
		Nonce:        "some super secret nonce",
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

	if c.RedirectURL == "" { // TODO: Validate that its a properly formed URL
		err = errors.New("RedirectURL Is required")
		return
	}

	if c.State == "" {
		err = errors.New("State Is required")
		return
	}

	return
}

// Default returns the oidcauth middleware with default configuration.
func Default() gin.HandlerFunc {
	config := DefaultConfig()
	return New(config)
}

// New returns the oidcauth middleware with user-defined custom configuration.
func New(c *Config) gin.HandlerFunc {
	// oidcauth := newOidcAuth(c)
	return func(c *gin.Context) {
		panic("Not Yet Implemented")
		// oidcauth.doSomething(c)
	}
}

// GetOidcAuth returns the configured OIDC authentication controller?
func (c *Config) GetOidcAuth() (o *OidcAuth, err error) {
	err = c.Validate()
	if err != nil {
		log.Fatal(err)
	}
	return newOidcAuth(c)
}
