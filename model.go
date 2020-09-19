package jwtauth

import "crypto/rsa"

type KeyLookupFunc func(publicKID string) (*rsa.PublicKey, error)

// Token represents data which can be used for authorization
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"-"`
}
