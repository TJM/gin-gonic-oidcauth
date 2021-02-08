package oidcauth

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	goblin "github.com/franela/goblin"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	. "github.com/onsi/gomega"
)

func TestOidc(t *testing.T) {
	g := goblin.Goblin(t)
	var cookies []*http.Cookie

	//special hook for gomega
	RegisterFailHandler(func(m string, _ ...int) { g.Fail(m) })

	g.Describe("TestOidc", func() {
		// ts := new(testIdpServer)
		// url := ts.run(t)
		// config := ExampleConfigDex()
		// config.IssuerURL = url

		g.Describe("newOidcAuth with invalid url", func() {
			config := ExampleConfigDex()
			config.IssuerURL = "http://localhost:12345" // NOTE: this port should be unused, or maybe we could creat a server that just 404s?
			auth, err := config.GetOidcAuth()

			g.It("should error when trying to connect", func() {
				Expect(auth).To(BeNil())
				Expect(err).NotTo(BeNil())
			})
		})

		g.Describe("get private url - protected by AuthRequired", func() {
			req, _ := http.NewRequest("GET", "/private", nil)
			r := newServer(t)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			cookies = w.Result().Cookies()
			redirect, err := w.Result().Location()
			if err != nil {
				panic(err)
			}

			for i, c := range cookies {
				fmt.Println("Cookie", i, c.Value)
			}
			fmt.Println("Number of cookies: ", len(cookies))

			g.It("should have sent us only one cookie", func() {
				fmt.Println("Number of cookies: ", len(cookies))
				Expect(len(cookies)).To(BeNumerically("==", 1))
			})
			g.It("should return a redirect", func() {
				Expect(w.Code).To(Equal(http.StatusFound))
				Expect(redirect.String()).NotTo(BeEmpty())
			})

			g.Describe("authenticate", func() {
				client := new(http.Client)
				req, _ := http.NewRequest("GET", redirect.String(), nil)
				// TODO Make request against something that will auth
				resp, err := client.Do(req)

				g.It("should return a login screen?", func() {
					Expect(resp.Status).To(Equal(http.StatusOK))
					Expect(err).NotTo(BeNil())
				})

				g.Describe("callback without session cookie", func() {
					state := redirect.Query().Get("state")
					code := "somethingCompletelyInvalid"
					callbackURL := fmt.Sprintf("/callback?state=%s&code=%s", state, code)
					req, _ := http.NewRequest("GET", callbackURL, nil)
					w := httptest.NewRecorder()
					r.ServeHTTP(w, req)
					resp := w.Result()
					body, _ := ioutil.ReadAll(resp.Body)
					fmt.Printf("Body: %s\n", string(body))

					g.It("should return error", func() {
						Expect(w.Result().StatusCode).To(BeEquivalentTo(400))
					})
					// g.It("should be an error about state not found", func() {
					// 	Expect(string(body)).To(ContainSubstring("state was not found in session"))
					// })
				})

				g.Describe("callback with non matching state", func() {
					// this should be a redirect from auth above
					state := "somethingCompletelyInvalid"
					code := "somethingCompletelyInvalid"
					callbackURL := fmt.Sprintf("/callback?state=%s&code=%s", state, code)
					req, _ := http.NewRequest("GET", callbackURL, nil)
					req.AddCookie(cookies[0])
					fmt.Println(cookies[0])
					fmt.Println(cookies[1])

					w := httptest.NewRecorder()
					r.ServeHTTP(w, req)

					g.It("should return error", func() {
						Expect(w.Result().StatusCode).To(BeEquivalentTo(400))
					})
				})

				g.Describe("callback after auth", func() {
					// this should be a redirect from auth above
					state := redirect.Query().Get("state")
					code := "somethingCompletelyInvalid"
					callbackURL := fmt.Sprintf("/callback?state=%s&code=%s", state, code)
					req, _ := http.NewRequest("GET", callbackURL, nil)
					req.AddCookie(cookies[0])
					w := httptest.NewRecorder()
					r.ServeHTTP(w, req)

					cookies = w.Result().Cookies()
					// redirect, err := w.Result().Location()
					// if err != nil {
					// 	panic(err)
					// }

					g.It("should have sent us cookies", func() {
						Expect(len(cookies)).To(BeNumerically(">", 0))
					})
					g.It("should return a redirect", func() {
						Expect(w.Code).To(Equal(http.StatusFound))
						Expect(redirect.String()).To(ContainSubstring("/private"))
					})
				})
			})

		})

	})
}

func newServer(t *testing.T) *gin.Engine {
	// Test Identity Provider (IdP)
	idp := new(testIdpServer)
	issuerURL := idp.run(t)

	// Test Gin Server
	router := gin.New()
	// Session Config (Basic cookies)
	store := cookie.NewStore([]byte("secret"), nil)
	router.Use(sessions.Sessions("oidcauth-example", store))
	authConfig := ExampleConfigDex()
	authConfig.IssuerURL = issuerURL
	auth, err := GetOidcAuth(authConfig)
	if err != nil {
		panic("auth setup failed")
	}
	router.GET("/login", auth.Login) // Unnecessary, as requesting a "AuthRequired" resource will initiate login, but potentially convenient
	router.GET("/callback", auth.AuthCallback)
	router.GET("/logout", auth.Logout)
	router.GET("/", func(c *gin.Context) {
		c.String(200, "Hello, world.")
	})
	router.GET("/private", auth.AuthRequired(), func(c *gin.Context) {
		c.String(200, "PRIVATE")
	})
	return router
}

type testIdpServer struct {
	contentType string
	userInfo    string
}

func (ts *testIdpServer) run(t *testing.T) string {
	newMux := http.NewServeMux()
	server := httptest.NewServer(newMux)

	// generated using mkjwk.org
	jwks := `{
		"keys": [
			{
				"kty": "RSA",
				"e": "AQAB",
				"use": "sig",
				"kid": "test",
				"alg": "RS256",
				"n": "ilhCmTGFjjIPVN7Lfdn_fvpXOlzxa3eWnQGZ_eRa2ibFB1mnqoWxZJ8fkWIVFOQpsn66bIfWjBo_OI3sE6LhhRF8xhsMxlSeRKhpsWg0klYnMBeTWYET69YEAX_rGxy0MCZlFZ5tpr56EVZ-3QLfNiR4hcviqj9F2qE6jopfywsnlulJgyMi3N3kugit_JCNBJ0yz4ndZrMozVOtGqt35HhggUgYROzX6SWHUJdPXSmbAZU-SVLlesQhPfHS8LLq0sACb9OmdcwrpEFdbGCSTUPlHGkN5h6Zy8CS4s_bCdXKkjD20jv37M3GjRQkjE8vyMxFlo_qT8F8VZlSgXYTFw"
			}
		]
	}`

	wellKnown := fmt.Sprintf(`{
		"issuer": "%[1]s",
		"authorization_endpoint": "%[1]s/auth",
		"token_endpoint": "%[1]s/token",
		"jwks_uri": "%[1]s/keys",
		"userinfo_endpoint": "%[1]s/userinfo",
		"id_token_signing_alg_values_supported": ["RS256"]
	}`, server.URL)

	newMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, wellKnown)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	newMux.HandleFunc("/keys", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.WriteString(w, jwks)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	newMux.HandleFunc("/userinfo", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", ts.contentType)
		_, err := io.WriteString(w, ts.userInfo)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	t.Cleanup(server.Close)
	return server.URL
}
