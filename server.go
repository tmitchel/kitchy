package kitchy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
)

type Server struct {
	Server *http.Server
	DB     *Database
	auth   authMiddleware
}

func NewServer(db *Database) (*Server, error) {
	router := mux.NewRouter().StrictSlash(true)
	router.Use(mux.CORSMethodMiddleware(router))

	apiRouter := router.PathPrefix("/api").Subrouter()
	authMid := authMiddleware{refreshkey: "secret", accesskey: "access"}
	apiRouter.Use(authMid.Middleware)

	server := &Server{
		Server: &http.Server{
			Handler:      router,
			Addr:         "127.0.0.1:8000",
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		},
		DB:   db,
		auth: authMid,
	}

	router.HandleFunc("/signin", server.SigninHandler).Methods("POST")
	router.HandleFunc("/signup", server.NewUserHandler).Methods("POST")
	router.HandleFunc("/refresh", server.RefreshHandler).Methods("POST")

	apiRouter.HandleFunc("/user", server.GetUserHandler).Methods("GET")
	apiRouter.HandleFunc("/users", server.GetUsersHandler).Methods("GET")

	http.Handle("/", router)

	return server, nil
}

type authMiddleware struct {
	accesskey  string
	refreshkey string
}

func (a authMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authentication"), "Bearer ")
		if len(authHeader) != 2 {
			err := fmt.Errorf("malformed token")
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			jwtToken := authHeader[1]
			token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(a.accesskey), nil
			})

			if claims, ok := token.Claims.(*AuthClaims); ok && token.Valid {
				ctx := context.WithValue(r.Context(), "props", claims.UserID)
				// Access context values in handlers like this
				// props, _ := r.Context().Value("props").(jwt.MapClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				fmt.Println(err)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
			}
		}
	})
}

func (s Server) createAccessToken(user_id string, expTime time.Time) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Claims = &AuthClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expTime.Unix(),
		},
		TokenType: "access",
		UserID:    user_id,
	}

	return t.SignedString(s.auth.accesskey)
}

func (s Server) createRefreshToken(user_id string, expTime time.Time) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Claims = &AuthClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expTime.Unix(),
		},
		TokenType: "refresh",
		UserID:    user_id,
	}

	return t.SignedString(s.auth.refreshkey)
}
