package jwtauth

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// ServerAuth is used to authenticate clients. It can generate token from Claims and
// regenerate Claims from token
type ServerAuth struct {
	privateKey    *rsa.PrivateKey
	publicKID     string
	algorithm     string
	signingMethod jwt.SigningMethod
	parser        *jwt.Parser
}

// NewServerAuth Create ServerAuth with given configurations
func NewServerAuth(privateKey *rsa.PrivateKey, publicKID string, alg string) (*ServerAuth, error) {
	if privateKey == nil {
		return nil, errors.New("privateKey can not be nil")
	}
	if publicKID == "" {
		return nil, errors.New("publicKID can not be empty")
	}
	if err := jwt.GetSigningMethod(alg); err == nil {
		return nil, errors.New("invalid algorithm")
	}

	parser := jwt.Parser{
		ValidMethods: []string{alg},
	}

	serverAuth := ServerAuth{
		privateKey:    privateKey,
		publicKID:     publicKID,
		algorithm:     alg,
		signingMethod: jwt.GetSigningMethod(alg),
		parser:        &parser,
	}

	return &serverAuth, nil
}

// GenerateToken generate new token with provided signing method
// generatedToken will then be signed using private key of ServerAuth
func (a *ServerAuth) GenerateToken(c Claims) (string, error) {
	// generating token with signing method
	token := jwt.NewWithClaims(a.signingMethod, c)

	// adding kid to token header so that we can use multiple keys for authentication.
	token.Header["kid"] = a.publicKID

	// finally signing token with our private key
	accessToken, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", errors.Wrap(err, "generating token")
	}

	return accessToken, nil
}
