package main

import (
	"fmt"
	"net/http"

	oidcauth "github.com/TJM/gin-gonic-oidcauth"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
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

	// Session Config (Basic cookies)
	store := cookie.NewStore([]byte("secret"), nil) // Do not use "secret", nil in production
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/", func(c *gin.Context) {

		session := sessions.Default(c)
		var name string

		n := session.Get("name")
		if n == nil {
			name = "world"
		} else {
			name = n.(string)
		}

		session.Save()
		out := fmt.Sprintf("Hello, %s.\n", name)
		c.String(http.StatusOK, out)
	})
	r.GET("/auth/google/login", auth.AuthLoginHandler)
	r.GET("/auth/google/callback", auth.AuthCallbackHandler)

	r.Run(":5556")
}
