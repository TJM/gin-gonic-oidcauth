package oidcauth

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	goblin "github.com/franela/goblin"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	g := goblin.Goblin(t)

	//special hook for gomega
	RegisterFailHandler(func(m string, _ ...int) { g.Fail(m) })

	g.Describe("TestConfig", func() {

		g.Describe("DefaultConfig", func() {
			os.Setenv("OIDC_CLIENT_ID", "client-id")
			os.Setenv("OIDC_CLIENT_SECRET", "client-secret")
			os.Setenv("OIDC_ISSUER_URL", "issuer-url")
			os.Setenv("OIDC_REDIRECT_URL", "redirect-url")
			c := DefaultConfig()

			g.It("should retrieve values from env", func() {
				Expect(c.ClientID).To(BeEquivalentTo("client-id"))
				Expect(c.ClientSecret).To(BeEquivalentTo("client-secret"))
				Expect(c.IssuerURL).To(BeEquivalentTo("issuer-url"))
				Expect(c.RedirectURL).To(BeEquivalentTo("redirect-url"))
			})
		})

		g.Describe("ExampleConfigDex", func() {
			c := ExampleConfigDex()

			g.It("should match dex example-app config", func() {
				Expect(c.ClientID).To(BeEquivalentTo("example-app"))
				Expect(c.ClientSecret).To(BeEquivalentTo("ZXhhbXBsZS1hcHAtc2VjcmV0"))
				Expect(c.IssuerURL).To(BeEquivalentTo("http://127.0.0.1:5556/dex"))
				Expect(c.RedirectURL).To(BeEquivalentTo("http://127.0.0.1:5555/callback"))
			})
		})

		g.Describe("ExampleConfigGoogle", func() {
			os.Setenv("GOOGLE_OAUTH2_CLIENT_ID", "client-id")
			os.Setenv("GOOGLE_OAUTH2_CLIENT_SECRET", "client-secret")
			c := ExampleConfigGoogle()

			g.It("should match example google config", func() {
				Expect(c.ClientID).To(BeEquivalentTo("client-id"))
				Expect(c.ClientSecret).To(BeEquivalentTo("client-secret"))
				Expect(c.IssuerURL).To(BeEquivalentTo("https://accounts.google.com"))
				Expect(c.RedirectURL).To(BeEquivalentTo("http://127.0.0.1:5556/auth/google/callback"))
			})
		})

		g.Describe("Validate", func() {
			g.Describe("- empty clientID", func() {
				c := ExampleConfigDex()
				c.ClientID = ""
				g.It("should error on empty ClientID", func() {
					Expect(c.Validate()).ToNot(BeNil())
				})
			})

			g.Describe("- empty ClientSecret", func() {
				c := ExampleConfigDex()
				c.ClientSecret = ""
				g.It("should error on empty ClientSecret", func() {
					Expect(c.Validate()).ToNot(BeNil())
				})
			})

			g.Describe("- empty IssuerURL", func() {
				c := ExampleConfigDex()
				c.IssuerURL = ""
				g.It("should error on empty IssuerURL", func() {
					Expect(c.Validate()).ToNot(BeNil())
				})
			})

			g.Describe("- empty RedirectURL", func() {
				c := ExampleConfigDex()
				c.RedirectURL = ""
				g.It("should error on empty RedirectURL", func() {
					Expect(c.Validate()).ToNot(BeNil())
				})
			})
		})

		g.Describe("GetOidcAuth", func() {
			ts := new(testServer)
			url := ts.run(t)
			config := ExampleConfigDex()
			config.IssuerURL = url
			auth, err := GetOidcAuth(config)

			g.It("should work", func() {
				Expect(auth).NotTo(BeNil())
				Expect(err).To(BeNil())
			})
		})

		g.Describe("config.GetOidcAuth", func() {
			ts := new(testServer)
			url := ts.run(t)
			config := ExampleConfigDex()
			config.IssuerURL = url
			auth, err := config.GetOidcAuth()

			g.It("should work", func() {
				Expect(auth).NotTo(BeNil())
				Expect(err).To(BeNil())
			})
		})

		g.Describe("config.GetOidcAuth with bad config", func() {
			config := ExampleConfigDex()
			config.IssuerURL = ""
			auth, err := config.GetOidcAuth()

			g.It("should fail", func() {
				Expect(auth).To(BeNil())
				Expect(err).NotTo(BeNil())
			})
		})

	})
}

type testServer struct {
	contentType string
	userInfo    string
}

func (ts *testServer) run(t *testing.T) string {
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
