package jwtReplacer

import (
	"context"
	"net/http"
	"strings"

	"github.com/wisdom-oss/common-go/v2/middleware"
)

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var err error
	var validator middleware.JWTValidator
	if config.OriginalJWT.AutoDiscover {
		err = validator.DiscoverAndConfigure(config.OriginalJWT.Issuer)
	} else {
		err = validator.Configure(config.OriginalJWT.Issuer, config.OriginalJWT.JwksUri, true)
	}

	if err != nil {
		return nil, err
	}

	return &JWTReplacer{
		issuer: strings.TrimSpace(config.OriginalJWT.Issuer),

		generatorConfig: config.GeneratedJWT,
		name:            name,
		next:            next,
	}, nil

}
