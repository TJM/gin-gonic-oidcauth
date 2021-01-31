package main

import (
	"net/http"

	oidcauth "github.com/TJM/gin-gonic-oidcauth"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

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
