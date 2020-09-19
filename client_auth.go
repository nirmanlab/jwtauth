package jwtauth

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// ClientAuth represents client side authentication and authorization functionalities
type ClientAuth struct {
	signingMethod jwt.SigningMethod
	publicKey     *rsa.PublicKey
	publicKID     string
}

// NewClientAuth create new ClientAuth
func NewClientAuth(alg string, publicKey *rsa.PublicKey, publicKID string) (*ClientAuth, error) {
	if err := jwt.GetSigningMethod(alg); err == nil {
		return nil, errors.New("invalid algorithm")
	}
	if publicKey == nil {
		return nil, errors.New("pubKeyLookupFunc can not be nil")
	}

	cAuth := ClientAuth{
		signingMethod: jwt.GetSigningMethod(alg),
		publicKey:     publicKey,
		publicKID:     publicKID,
	}

	return &cAuth, nil
}

// keyLookupFunction is used while validating token
func (c *ClientAuth) keyLookupFunction(token *jwt.Token) (interface{}, error) {
	// if method in token supplied is not the method we're expecting, return error
	if token.Method != c.signingMethod {
		return nil, errors.New(fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]))
	}

	kid, ok := token.Header["kid"]
	if !ok {
		return nil, errors.New("kid not found in token")
	}

	if kid == c.publicKID {
		return c.publicKey, nil
	} else {
		return nil, errors.New("publicKID does not match")
	}
}

// Validate parse, and validate token. if successful it returns Claims recreated from token
func (c *ClientAuth) Validate(tokenStr string) (Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, c.keyLookupFunction)
	if err != nil {
		return Claims{}, errors.Wrap(err, "parsing token with claims")
	}

	if token.Valid {
		return claims, nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return Claims{}, errors.New("token is not valid")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			return Claims{}, errors.New("token is either expired or not active yet")
		} else {
			return Claims{}, errors.New(fmt.Sprintf("Couldn't handle this token: %v", err))
		}
	} else {
		return Claims{}, errors.New(fmt.Sprintf("Couldn't handle this token: %v", err))
	}
}
