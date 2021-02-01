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

	// NOTE: DefaultConfig uses Google Accounts - See https://github.com/coreos/go-oidc/blob/v3/example/README.md
	authConfig := oidcauth.DefaultConfig()
	auth, err := authConfig.GetOidcAuth()
	if err != nil {
		panic("auth setup failed")
	}
	if os.Getenv("DEBUG") != "" {
		auth.Debug = true
	}

	// Session Config (Basic cookies)
	store := cookie.NewStore([]byte("secret"), nil) // Do not use "secret", nil in production
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/", func(c *gin.Context) {
		var name, email, out string
		session := sessions.Default(c)
		n := session.Get("name")
		if n == nil {
			name = "world"
		} else {
			name = n.(string)
		}
		e := session.Get("email")
		if n == nil {
			email = ""
			out = fmt.Sprintf("Hello, %s.\n", name)
		} else {
			email = e.(string)
			out = fmt.Sprintf("Hello, %s <%s>.\n", name, email)
		}
		// session.Save()
		c.String(http.StatusOK, out)
	})
	r.GET("/auth/google/login", auth.AuthLoginHandler)
	r.GET("/auth/google/callback", auth.AuthCallbackHandler)

	r.Run(":5556")
}
