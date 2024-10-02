package jwtReplacer

import "time"

type Config struct {
	OriginalJWT struct {
		Issuer       string `json:"issuer"`
		AutoDiscover bool   `json:"autoDiscover"`
		JwksUri      string `json:"jwksUri`
	} `json:"originalJWT"`
	GeneratedJWT struct {
		Issuer             string        `json:"issuer"`
		Ttl                time.Duration `json:"ttl"`
		CopyScopes         bool          `json:"copyScopes"`
		UseOriginalSubject bool          `json:"useOriginalSubject"`
	} `json:"generatedJWT"`
}

func CreateConfig() *Config {
	return &Config{
		GeneratedJWT: struct {
			Issuer             string        `json:"issuer"`
			Ttl                time.Duration `json:"ttl"`
			CopyScopes         bool          `json:"copyScopes"`
			UseOriginalSubject bool          `json:"useOriginalSubject"`
		}{
			Issuer:             "api-gateway",
			Ttl:                1 * time.Minute,
			CopyScopes:         true,
			UseOriginalSubject: true,
		},
	}
}
