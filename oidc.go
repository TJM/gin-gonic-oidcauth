package oidcauth

import (
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus"

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
		log.Error("Error getting oidc provider: " + err.Error())
		return nil, err
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
		log.Error("Error creating NonceService: " + err.Error())
		return nil, err
	}
	o.nonceService = ns

	o.config = c // Save Config
	return
}

// AuthRequired middleware requires OIDC authentication
// BE CAREFUL Adding this to / (or the top level router)
func (o *OidcAuth) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		token := session.Get(accessTokenSessionKey)
		if token == nil {
			o.doAuthentication(c)
			c.Abort()
			return
		}
		// TODO: Valdate Token / Expiration? / Extension?
		l := session.Get(loginSessionKey)
		if l == nil {
			o.doAuthentication(c)
			c.Abort()
			return
		}
		login := l.(string)
		// The user credentials was found, set user's id to key AuthUserKey in this context, the user's id can be read later using
		// c.MustGet(oidcauth.AuthUserKey).
		c.Set(AuthUserKey, login)
		c.Next()
	}
}

// Login will setup the appropriate state and redirect the user to the authentication provider
func (o *OidcAuth) Login(c *gin.Context) {
	state := o.generateState(c)
	nonce := o.generateNonce(c)
	session := sessions.Default(c)
	session.Set(oidcStateSessionKey, state)
	err := session.Save()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("Error saving session: "+err.Error()))
		return
	}
	c.Redirect(http.StatusFound, o.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)))
}

// Logout will clear the session
// NOTE: It will not invalidate the OIDC session (Not SSO)
func (o *OidcAuth) Logout(c *gin.Context) {
	session := sessions.Default(c)
	// These Sets will mark the session as "written" and clear the values (jic)
	session.Set(accessTokenSessionKey, nil)
	session.Set(loginSessionKey, nil)
	session.Clear()
	session.Options(sessions.Options{Path: "/", MaxAge: -1}) // this sets the cookie as expired
	session.Save()
	c.Redirect(http.StatusTemporaryRedirect, o.config.LogoutURL)
}

// AuthCallback will handle the authentication callback (redirect) from the Identity Provider
//   This is the part that actually "does" the authentication.
func (o *OidcAuth) AuthCallback(c *gin.Context) {
	sessionState, err := o.getState(c)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, errors.New("[oidcauth] unable to retrieve state: "+err.Error()))
		return
	}
	if c.Query("state") != sessionState {
		log.Print("  queryState: ", c.Query("state"))
		log.Print("sessionState: ", sessionState)
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

	// Add claims to session
	if len(o.config.SessionClaims) > 0 {
		if o.config.SessionClaims[0] == "*" { // Set All Claims in Session
			for claim, val := range claims {
				sessionKey := o.config.SessionPrefix + claim
				session.Set(sessionKey, val)
			}
		} else {
			for _, sessionClaim := range o.config.SessionClaims {
				if val, ok := claims[sessionClaim]; ok {
					sessionKey := o.config.SessionPrefix + sessionClaim
					session.Set(sessionKey, val)
				}
			}
		}
	}

	// Set login in session
	if login, ok := claims[o.config.LoginClaim]; ok {
		session.Set(loginSessionKey, login)
	}

	redirectURL := o.config.DefaultAuthenticatedURL
	u := session.Get(previousURLSessionKey)
	if u != nil {
		redirectURL = u.(string)
		session.Delete(previousURLSessionKey)
	}

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

// getState will return the state string (and/or err) from the session
// NOTE: state is a string that is passed to the authentication provider, and returned to validate we sent the reqest.
func (o *OidcAuth) getState(c *gin.Context) (state string, err error) {
	session := sessions.Default(c)
	s := session.Get(oidcStateSessionKey)
	session.Delete(oidcStateSessionKey)
	session.Save()
	if s == nil {
		err = errors.New("state was not found in session")
		log.Error(err)
		return
	}
	if !o.nonceService.Valid(s.(string)) {
		err = errors.New("state was not a valid nonce")
		log.Error(err)
		return
	}
	state = s.(string)
	return

}

// generateState will generate the random string to be used for "state" in the oidc requests
// 	 Opaque value used to maintain state between the request and the callback.
//   Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically
//   binding the value of this parameter with a browser cookie.
func (o *OidcAuth) generateState(c *gin.Context) (state string) {
	return o.generateNonce(c) // just use a nonce for now
}

// generateNonce will generate a nonce (one time use, random string), aborts on error
func (o *OidcAuth) generateNonce(c *gin.Context) (nonce string) {
	nonce, err := o.nonceService.Nonce()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("Error getting nonce: "+err.Error()))
	}
	return
}

// doAuthentication is designed to be called from middleware when it determines
//  that the user is not authenticated. It will attempt to return the user to
//  the path they were requesting when authentication was required.
func (o *OidcAuth) doAuthentication(c *gin.Context) {
	session := sessions.Default(c)
	previousURL := c.Request.RequestURI // Current URL
	if previousURL == "" {
		previousURL = o.config.DefaultAuthenticatedURL
	}
	session.Set(previousURLSessionKey, c.Request.RequestURI)
	err := session.Save()
	if err != nil {
		log.Error("Error Saving Session: " + err.Error())
		c.AbortWithError(http.StatusInternalServerError, err)
	}

	o.Login(c)
	return
}
