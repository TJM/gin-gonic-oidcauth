package oidcauth

import (
	"errors"
	log "log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/nonce"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const (
	oidcStateSessionKey   string = "oidc-auth-state"
	previousURLSessionKey string = "oidc-auth-PreviousURL"
)

// OidcAuth handles the authentication?
type OidcAuth struct {
	ctx          context.Context
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	Oauth2Config *oauth2.Config
	NonceService *nonce.NonceService
}

// newOidcAuth returns the oidcAuth struct, expects config to have been validated
func newOidcAuth(c *Config) (o *OidcAuth, err error) {
	o = new(OidcAuth)

	o.ctx = context.Background()

	provider, err := oidc.NewProvider(o.ctx, c.IssuerURL)
	if err != nil {
		log.Fatal(err)
	}
	o.Provider = provider

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

	ns, err := nonce.NewNonceService(metrics.NoopRegisterer, 0, "oidc")
	if err != nil {
		log.Fatal(err)
	}
	o.NonceService = ns

	return
}

// AuthLoginHandler will redirect the user to the authentication provider
func (o *OidcAuth) AuthLoginHandler(c *gin.Context) {
	state := o.generateState(c)
	session := sessions.Default(c)
	session.Set(previousURLSessionKey, "/") // TODO GET "previous" URL (Safely?)
	session.Set(oidcStateSessionKey, state)
	err := session.Save()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("Error saving session: "+err.Error()))
		return
	}
	nonce := o.getNonce(c)
	c.Redirect(http.StatusFound, o.Oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)))
}

// AuthCallbackHandler will handle the authentication callback (redirect) from the Identity Provider
// example: /auth/oidc/callback
func (o *OidcAuth) AuthCallbackHandler(c *gin.Context) {
	if c.Query("state") != o.getState(c) {
		log.Print("state: ", c.Query("state"))
		c.AbortWithError(http.StatusBadRequest, errors.New("[oidcauth] state did not match"))
		return
	}

	oauth2Token, err := o.Oauth2Config.Exchange(o.ctx, c.Query("code"))
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
	idToken, err := o.Verifier.Verify(o.ctx, rawIDToken)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Failed to verify ID Token: "+err.Error()))
		return
	}
	if !o.NonceService.Valid(idToken.Nonce) {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Invalid ID Token nonce"))
		return
	}

	// IDTokenClaims := new(json.RawMessage) // ID Token payload is just JSON.
	claims := make(map[string]interface{})
	if err := idToken.Claims(&claims); err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Failed retrieve claims: "+err.Error()))
		return
	}

	session := sessions.Default(c)
	session.AddFlash("Authentication Successful!")

	// Process Results - just dump everything into the session for now (probably not a good idea)
	session.Set("AccessToken", oauth2Token.AccessToken)
	session.Set("TokenType", oauth2Token.TokenType)
	// session.Set("Expiry", oauth2Token.Expiry)
	for claim, val := range claims {
		if claim != "nonce" { // skip saving nonce
			session.Set(claim, val)
		}
	}

	redirectURL := "/"
	u := session.Get(previousURLSessionKey)
	if u != nil {
		redirectURL = u.(string)
	}
	session.Delete(previousURLSessionKey)

	err = session.Save()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("Error saving session: "+err.Error()))
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// getState will return the state string from the session
// NOTE: state is a string that is passed to the authentication provider, and returned to validate we sent the reqest.

func (o *OidcAuth) getState(c *gin.Context) string {
	session := sessions.Default(c)
	state := session.Get(oidcStateSessionKey)
	session.Delete(oidcStateSessionKey)
	session.Save()
	if state == nil {
		return o.generateState(c) // return a new state (which should not match)
	}
	if !o.NonceService.Valid(state.(string)) {
		return o.generateState(c) // return a new state (which should not match)
	}
	return state.(string)

}

// generateState will generate the random string to be used for "state" in the oidc requests
// 	 Opaque value used to maintain state between the request and the callback.
//   Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically
//   binding the value of this parameter with a browser cookie.
func (o *OidcAuth) generateState(c *gin.Context) (state string) {
	return o.getNonce(c) // just use a nonce for now
}

// getNonce will generate a nonce (one time use, random string), aborts on error
func (o *OidcAuth) getNonce(c *gin.Context) (nonce string) {
	nonce, err := o.NonceService.Nonce()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("Error getting nonce: "+err.Error()))
	}
	return
}
