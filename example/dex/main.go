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

	// Session Config (Basic cookies)
	store := cookie.NewStore([]byte("secret"), nil)     // Do not use "secret", nil in production. This sets the keypairs for auth, encryption of the cookies.
	r.Use(sessions.Sessions("oidcauth-example", store)) // Sessions must be Use(d) before oidcauth, as oidcauth requires sessions

	// Authentication Config - Uses example dex config
	// - https://dexidp.io/docs/getting-started/
	auth, err := oidcauth.GetOidcAuth(oidcauth.ExampleConfigDex())
	if err != nil {
		panic("auth setup failed")
	}
	r.GET("/login", auth.Login) // Unnecessary, as requesting a "AuthRequired" resource will initiate login, but potentially convenient
	r.GET("/callback", auth.AuthCallback)
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

	r.Run(":5555")
}
