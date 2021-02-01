package oidcauth

import (
	"errors"
	"log"
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
	// oidcStateSessionKey is used to validate callback from client, see: https://auth0.com/docs/protocols/state-parameters
	oidcStateSessionKey string = "oidcauth:state"

	// previousURLSessionKey will temporarily hold the URL path that the user was at before authentication started
	previousURLSessionKey string = "oidcauth:PreviousURL"

	// accessTokenSessionKey is the session key to hold the oauth access token
	accessTokenSessionKey string = "oidcauth:AccessToken"

	// loginSessionKey is the session key to hold the "login" (username)
	loginSessionKey string = "oidcauth:login"

	// AuthUserKey stores the authenticated user's login (username or email) in this context key
	AuthUserKey string = "user"
)

// OidcAuth handles OIDC Authentication
type OidcAuth struct {
	ctx          context.Context
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	nonceService *nonce.NonceService
	config       *Config
	Debug        bool // DUMP oidc paramters as JSON instead of redirecting
}

// newOidcAuth returns the oidcAuth struct, expects config to have been validated
func newOidcAuth(c *Config) (o *OidcAuth, err error) {
	o = new(OidcAuth)

	o.ctx = context.Background()

	provider, err := oidc.NewProvider(o.ctx, c.IssuerURL)
	if err != nil {
		log.Fatal(err)
	}
	o.provider = provider

	oidcConfig := &oidc.Config{
		ClientID: c.ClientID,
	}
	// Use the nonce source to create a custom ID Token verifier.
	o.verifier = o.provider.Verifier(oidcConfig)

	o.oauth2Config = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.RedirectURL,
		Scopes:       c.Scopes,
	}

	ns, err := nonce.NewNonceService(metrics.NoopRegisterer, 0, "oidc")
	if err != nil {
		log.Fatal(err)
	}
	o.nonceService = ns

	o.config = c // Save Config
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
	c.Redirect(http.StatusFound, o.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)))
}

// AuthCallbackHandler will handle the authentication callback (redirect) from the Identity Provider
// example: /auth/oidc/callback
func (o *OidcAuth) AuthCallbackHandler(c *gin.Context) {
	if c.Query("state") != o.getState(c) {
		log.Print("state: ", c.Query("state"))
		c.AbortWithError(http.StatusBadRequest, errors.New("[oidcauth] state did not match"))
		return
	}

	oauth2Token, err := o.oauth2Config.Exchange(o.ctx, c.Query("code"))
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
	idToken, err := o.verifier.Verify(o.ctx, rawIDToken)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Failed to verify ID Token: "+err.Error()))
		return
	}
	if !o.nonceService.Valid(idToken.Nonce) {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Invalid ID Token nonce"))
		return
	}

	// IDTokenClaims := new(json.RawMessage) // ID Token payload is just JSON.
	claims := make(map[string]interface{})
	if err := idToken.Claims(&claims); err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("[oidcauth] Failed retrieve claims: "+err.Error()))
		return
	}

	// Save to session
	session := sessions.Default(c)
	session.AddFlash("Authentication Successful!")

	// Process Results - just dump everything into the session for now (probably not a good idea)
	session.Set(accessTokenSessionKey, oauth2Token.AccessToken)
	// session.Set("TokenType", oauth2Token.TokenType) // Not Needed?
	// session.Set("Expiry", oauth2Token.Expiry) // sessions doesn't like time.Time
	delete(claims, "nonce") // No longer useful

	// Set All Claims in Session (temporary)
	// TODO: allow user to specify which claims to remove (or include?) in session
	for claim, val := range claims {
		session.Set(claim, val)
	}

	// Set login in session
	if login, ok := claims[o.config.LoginClaim]; ok {
		session.Set(loginSessionKey, login)
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

	if o.Debug {
		c.JSON(http.StatusOK, gin.H{
			"redirectURL": redirectURL,
			"rawIDToken":  rawIDToken,
			"idToken":     idToken,
			"oauth2Token": oauth2Token,
			"claims":      claims,
		})
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
	if !o.nonceService.Valid(state.(string)) {
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
	nonce, err := o.nonceService.Nonce()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("Error getting nonce: "+err.Error()))
	}
	return
}
