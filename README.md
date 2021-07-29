# JwtAuth 

this is not a library to create jwt token but a nice wrapper around existing "github.com/golang-jwt/jwt" to provide syntax sugar to it's users. 

It provides two types.

1. ServerAuth and,
2. ClientAuth


our internal auth light server uses *ServerAuth* construct to generate new tokens. It also uses "ClientAuth" to validate and parse generated tokens. 

ClientAuth needs publicKey and kid of signed token's private key to properly validate token. 