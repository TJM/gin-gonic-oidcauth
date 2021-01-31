# `oidcauth` - OIDC Client Authentication middleware for Gin-Gonic

oidcauth is [gin-gonic](https://https://gin-gonic.com/) middleware to enable `oidc` client authentication support.

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

* Identity Provider (IdP) Server that supports OIDC - You can use something like [DEX](github.com/dexidp/dex) to test with. Alternatively, you could also use Google Accounts, GitHub accounts, etc. The examples below will use Google Accounts. See: [go-oidc examples readme](https://github.com/coreos/go-oidc/tree/v3/example)

* Basic Example: [example/basic/main.go](example/basic/main.go)

```go
package main

import (
	"net/http"

	oidcauth "github.com/TJM/gin-gonic-oidcauth"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// NOTE: DefaultConfig uses Google Accounts - See https://github.com/coreos/go-oidc/blob/v3/example/README.md
	authConfig := oidcauth.DefaultConfig()
	auth, err := authConfig.GetOidcAuth()
	if err != nil {
		panic("auth setup failed")
	}

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello, world.")
	})
	r.GET("/auth/google/login", auth.AuthLoginHandler)
	r.GET("/auth/google/callback", auth.AuthCallbackHandler)

	r.Run(":5556")
}
```

* Sessions example: [example/sessions/main.go](example/sessions/main.go)

```go
package main

// TOODO
```

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
