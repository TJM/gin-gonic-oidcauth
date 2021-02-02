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

Use it: (see complete [examples](example))

```go
  // NOTE: oidcauth *requires* sessions *before* oidcauth
  // SEE Examples to see how.

	// Authentication Config
	auth, err := oidcauth.GetOidcAuth(oidcauth.DefaultConfig())
	if err != nil {
		panic("auth setup failed")
	}
	router.GET("/login", auth.Login) // Unnecessary, as requesting a "AuthRequired" resource will initiate login, but potentially convenient
	router.GET("/callback", auth.AuthCallback)
  router.GET("/logout", auth.Logout)

  // Private Route Group...
	private := r.Group("/private", auth.AuthRequired())
	{
		private.GET("", func(c *gin.Context) {
      c.String(http.StatusOK, "Private!")
    }
    // ...
  }
```

## Examples

Prerequisites:

* Oauth2 Identity Provider (IdP) service that supports [OIDC](https://en.wikipedia.org/wiki/OpenID_Connect)
  * You can use something like [DEX](https://github.com/dexidp/dex) to test with.
  * Alternatively, you could also use something like:
    * [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect)
    * [GitHub](https://plugins.miniorange.com/oauth-openid-login-using-github)
    * etc

### DEX Identity Provider

The example below will use [DEX IdP](https://dexidp.io/). Please clone their repo and start DEX in a separate window.

* Start DEX IdP:

```console
./bin/dex serve examples/config-dev.yaml
```

* Start [DEX ExampleApp(example/dex/main.go)]:

```console
go run example/dex/main.go
```

* Visit: <http://127.0.0.1:5555/>
  * Attempt to access something "private" <http://127.0.0.1:5555/private>
  * Login: <http://127.0.0.1:5555/login>
  * Logout: <http://127.0.0.1:5555/logout>

### Google Accounts Identity Provider

The example below will use Google Accounts. See: [go-oidc examples readme](https://github.com/coreos/go-oidc/tree/v3/example).

NOTE: This example used port `5556` to be compatible with the other go-oidc examples, but it will clash with "dex" which runs on the same port by default.

* Setup Google

  1. Visit your [Google Developer Console][google-developer-console].
  2. Click "Credentials" on the left column.
  3. Click the "Create credentials" button followed by "OAuth client ID".
  4. Select "Web application" and add "http://127.0.0.1:5556/auth/google/callback" as an authorized redirect URI.
  5. Click create and add the printed client ID and secret to your environment using the following variables:

  ```bash
  export GOOGLE_OAUTH2_CLIENT_ID=
  export GOOGLE_OAUTH2_CLIENT_SECRET=
  ```

* Start Google Example [example/google/main.go](example/google/main.go):

```console
go run example/google/main.go
```

* Visit: <http://127.0.0.1:5556/>
  * Attempt to access something "private" <http://127.0.0.1:5556/private>
  * Login: <http://127.0.0.1:5556/login>
  * Logout: <http://127.0.0.1:5556/logout>

[google-developer-console]: https://console.developers.google.com/apis/dashboard

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
