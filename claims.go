package jwtauth

import (
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

const ClaimsKey = "claims"

// Claims represents claims made by token
type Claims struct {
	jwt.StandardClaims
	Roles []string `json:"roles"`
}

// Valid checks claims against standard validations
func (c Claims) Valid() error {
	if err := c.StandardClaims.Valid(); err != nil {
		return errors.Wrap(err, "validating standard claims")
	}

	return nil
}

// HasRole checks if claim contains provided in argument
func (c Claims) HasRole(roles ...string) bool {
	for _, has := range roles {
		for _, want := range c.Roles {
			if has == want {
				return true
			}
		}
	}

	return false
}
