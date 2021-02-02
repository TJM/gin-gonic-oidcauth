# `oidcauth` - OIDC Client Authentication for Gin-Gonic

[![Build Status](https://travis-ci.org/TJM/gin-gonic-oidcauth.svg)](https://travis-ci.org/TJM/gin-gonic-oidcauth)
[![codecov](https://codecov.io/gh/TJM/gin-gonic-oidcauth/branch/master/graph/badge.svg)](https://codecov.io/gh/TJM/gin-gonic-oidcauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/TJM/gin-gonic-oidcauth)](https://goreportcard.com/report/github.com/TJM/gin-gonic-oidcauth)
[![GoDoc](https://godoc.org/github.com/TJM/gin-gonic-oidcauth?status.svg)](https://godoc.org/github.com/TJM/gin-gonic-oidcauth)
<!-- [![Join the chat at https://gitter.im/gin-gonic/gin](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/gin-gonic/gin) -->

## Usage

Download and install it:

```sh
go get github.com/TJM/gin-gonic-oidcauth
```

Import it in your code:

```go
import oidcauth "github.com/TJM/gin-gonic-oidcauth"
```

## Example

Prerequisites:

* Oauth2 Identity Provider (IdP) service that supports [OIDC](https://en.wikipedia.org/wiki/OpenID_Connect)
  * You can use something like [DEX](https://github.com/dexidp/dex) to test with.
  * Alternatively, you could also use something like:
    * [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect)
    * [GitHub](https://plugins.miniorange.com/oauth-openid-login-using-github)
    * etc
 
The examples below will use Google Accounts. See: [go-oidc examples readme](https://github.com/coreos/go-oidc/tree/v3/example)

* Sessions example: [example/main.go](example/main.go)

```go
package main

import (
	"fmt"
	"net/http"
	"os"

	oidcauth "github.com/TJM/gin-gonic-oidcauth"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Session Config (Basic cookies)
	store := cookie.NewStore([]byte("secret"), nil) // Do not use "secret", nil in production. This sets the keypairs for auth, encryption of the cookies.
	r.Use(sessions.Sessions("mysession", store))    // Sessions must be Use(d) before oidcauth, as oidcauth requires sessions

	// NOTE: DefaultConfig uses Google Accounts
	// - See https://github.com/coreos/go-oidc/blob/v3/example/README.md
	auth, err := oidcauth.GetOidcAuth(oidcauth.DefaultConfig())
	if err != nil {
		panic("auth setup failed")
	}
	if os.Getenv("DEBUG") != "" {
		auth.Debug = true
	}

	r.GET("/login", auth.Login) // Unnecessary, as requesting a "AuthRequired" resource will initiate login, but potentially convenient
	r.GET("/auth/google/callback", auth.AuthCallback)
	r.GET("/logout", auth.Logout)

	// Allow access to / for unauthenticated users, but authenticated users will be greated by name.
	r.GET("/", func(c *gin.Context) {
		session := sessions.Default(c)
		name := "world"
		n := session.Get("name")
		if n != nil {
			name = n.(string)
		}
		// session.Save() // if it has been changed, which it has not
		c.String(http.StatusOK, fmt.Sprintf("Hello, %s.", name))
	})

	private := r.Group("/private", auth.AuthRequired())
	{
		private.GET("", func(c *gin.Context) {
			var name, email, out string
			login := c.GetString(oidcauth.AuthUserKey)
			session := sessions.Default(c)
			n := session.Get("name")
			if n == nil {
				name = "Someone without a name?"
			} else {
				name = n.(string)
			}
			e := session.Get("email")
			if e != nil {
				email = e.(string)
			}
			out = fmt.Sprintf("Hello, %s <%s>.\nLogin: %s\n", name, email, login)
			// session.Save() // if it has been changed, which it has not
			c.String(http.StatusOK, out)
			return
		})
	}

	r.Run(":5556")
}
```

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
