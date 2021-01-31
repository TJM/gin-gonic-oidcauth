package oidcauth

import (
	"encoding/json"
	"errors"
	log "log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	ctx context.Context = context.Background() // Can this be defined globally?
)

// OidcAuth handles the authentication?
type OidcAuth struct {
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	Oauth2Config *oauth2.Config
	Config       *Config
}

// newOidcAuth returns the oidcAuth struct, expects config to have been validated
func newOidcAuth(c *Config) (o *OidcAuth, err error) {
	o = new(OidcAuth)
	o.Config = c // Being lazy

	o.Provider, err = oidc.NewProvider(ctx, c.IssuerURL)
	if err != nil {
		log.Fatal(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: c.ClientID,
	}
	// Use the nonce source to create a custom ID Token verifier.
	o.Verifier = o.Provider.Verifier(oidcConfig)

	o.Oauth2Config = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     o.Provider.Endpoint(),
		RedirectURL:  c.RedirectURL,
		Scopes:       c.Scopes,
	}

	return
}

// AuthLoginHandler will redirect the user to the authentication provider
func (o *OidcAuth) AuthLoginHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, o.Oauth2Config.AuthCodeURL(o.Config.State, oidc.Nonce(o.Config.Nonce)))
}

// AuthCallbackHandler will handle the authentication callback (redirect) from the Identity Provider
// example: /auth/oidc/callback
func (o *OidcAuth) AuthCallbackHandler(c *gin.Context) {
	if c.Query("state") != o.Config.State {
		log.Print("state: ", c.Query("state"))
		c.AbortWithError(http.StatusBadRequest, errors.New("[oidcauth] state did not match"))
		return
	}

	oauth2Token, err := o.Oauth2Config.Exchange(ctx, c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Failed to exchange token: "+err.Error()))
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] No id_token field in oauth2 token"))
		return
	}

	// Verify the ID Token signature and nonce.
	idToken, err := o.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Failed to verify ID Token: "+err.Error()))
		return
	}
	if idToken.Nonce != o.Config.Nonce {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Invalid ID Token nonce"))
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Failed retrieve claims: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, resp) // Temporary
}
