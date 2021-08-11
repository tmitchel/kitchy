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

type NewPantryPayload struct {
	Name string `json:"name"`
}

type SigninPayload struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type AuthClaims struct {
	jwt.StandardClaims
	TokenType string
	UserID    string
	UserInfo  User
}

type AccessToken struct {
	Token     string
	ExpiresAt int64
}

type ContextKey string
