package kitchy

import (
	"github.com/golang-jwt/jwt"
)

type authMiddleware struct {
	accesskey  string
	refreshkey string
}

type NewUserPayload struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type SigninPayload struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type AuthClaims struct {
	jwt.StandardClaims
	TokenType string
	UserID    string
}

type AccessToken struct {
	Token     string
	ExpiresAt int64
}

type ContextKey string
