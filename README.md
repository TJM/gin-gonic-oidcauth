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
import "github.com/TJM/gin-gonic-oidcauth"
```

## Example

Prerequisites:

* Identity Provider (IdP) Server that supports OIDC - You can use something like [DEX](github.com/dexidp/dex) to test with. Alternatively, you could also use Google Accounts, GitHub accounts, etc.

See: [example/main.go](example/main.go)

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
