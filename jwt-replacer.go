package jwtReplacer

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/wisdom-oss/common-go/v2/middleware"
)

type JWTReplacer struct {
	next            http.Handler
	name            string
	issuer          string
	jwtValidator    middleware.JWTValidator
	generatorConfig struct {
		Issuer             string        `json:"issuer"`
		Ttl                time.Duration `json:"ttl"`
		CopyScopes         bool          `json:"copyScopes"`
		UseOriginalSubject bool          `json:"useOriginalSubject"`
	}
}

func (m JWTReplacer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.jwtValidator.Handler(func() http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			permissions, permissionsSet := r.Context().Value("permissions").([]string)
			if !permissionsSet {
				panic("no permissions set, but validator passed")
			}
			isAdmin, _ := r.Context().Value("administrator").(bool)

			tokenBuilder := jwt.NewBuilder()
			tokenBuilder.Issuer("api-gateway")
			tokenBuilder.IssuedAt(time.Now())
			tokenBuilder.Expiration(time.Now().Add(1 * time.Minute))
			tokenBuilder.Subject("wisdom-authenticated-user")
			tokenBuilder.Claim("groups", permissions)
			tokenBuilder.Claim("staff", isAdmin)

			token, _ := tokenBuilder.Build()
			serializer := jwt.NewSerializer()
			serializedToken, _ := serializer.Serialize(token)

			r.Header.Set("Authorization", `Bearer `+string(serializedToken))
			r.Header.Set("X-WISdoM-User", "authenticated-user")
			r.Header.Set("X-Authenticated-User", "authenticated-user")
			r.Header.Set("X-WISdoM-Groups", strings.Join(permissions, " "))
			r.Header.Set("X-Authenticated-Groups", strings.Join(permissions, " "))
			r.Header.Set("X-Is-Staff", fmt.Sprintf("%t", isAdmin))
			r.Header.Set("X-Superuser", fmt.Sprintf("%t", isAdmin))
		}
		return http.HandlerFunc(fn)
	}())
}
