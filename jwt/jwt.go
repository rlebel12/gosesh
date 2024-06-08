package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rlebel12/gosesh"
)

func New(secret string, opts ...NewOpt) *JWT {
	jwt := &JWT{
		key: []byte(secret),
	}
	for _, opt := range opts {
		opt(jwt)
	}
	return jwt
}

func WithSigningMethod(method jwt.SigningMethod) NewOpt {
	return func(j *JWT) {
		j.signingMethod = method
	}
}

type (
	JWT struct {
		key           []byte
		signingMethod jwt.SigningMethod
	}

	NewOpt func(*JWT)
)

func (j *JWT) SessionToken(identifier gosesh.Identifier) (string, error) {
	return j.signedToken()
}

func (j *JWT) signedToken() (string, error) {
	token := jwt.NewWithClaims(j.signingMethod, jwt.MapClaims{
		"sub": "foo",
		"exp": time.Now().Add(time.Minute * 30).Unix(),
	})
	return token.SignedString(j.key)
}
