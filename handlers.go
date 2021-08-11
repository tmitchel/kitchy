package kitchy

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
)

func (s Server) SigninHandler(w http.ResponseWriter, r *http.Request) {
	var user SigninPayload
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		errString := fmt.Errorf("error decoding signup form: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusBadRequest)
		return
	}

	userInDB, err := GetUserByName(user.Name, s.DB)
	if err != nil {
		errString := fmt.Errorf("error finding user: %v", err)
		log.Print(errString)
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}

	if userInDB.Password != user.Password {
		errString := fmt.Errorf("cannot find user id or password")
		log.Print(errString)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	refreshExpireTime := time.Now().Add(5 * time.Minute)
	refreshToken, err := s.createRefreshToken(userInDB.ID, refreshExpireTime)
	if err != nil {
		errString := fmt.Errorf("error creating new token: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusInternalServerError)
		return
	}

	accessExpireTime := time.Now().Add(5 * 24 * time.Hour)
	accessToken, err := s.createAccessToken(userInDB.ID, accessExpireTime)
	if err != nil {
		errString := fmt.Errorf("error creating new token: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh-token",
		Value:    refreshToken,
		Expires:  refreshExpireTime,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AccessToken{Token: accessToken, ExpiresAt: accessExpireTime.Unix()})
}

func (s Server) NewUserHandler(w http.ResponseWriter, r *http.Request) {
	var newUser NewUserPayload
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		errString := fmt.Errorf("error decoding signup form: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusBadRequest)
		return
	}

	user, err := NewUser(newUser.Name, newUser.Password, s.DB)
	if err != nil {
		errString := fmt.Errorf("error creating new user: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusInternalServerError)
		return
	}

	refreshExpireTime := time.Now().Add(5 * time.Minute)
	refreshToken, err := s.createRefreshToken(user.ID, refreshExpireTime)
	if err != nil {
		errString := fmt.Errorf("error creating new token: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusInternalServerError)
		return
	}

	accessExpireTime := time.Now().Add(5 * 24 * time.Hour)
	accessToken, err := s.createAccessToken(user.ID, accessExpireTime)
	if err != nil {
		errString := fmt.Errorf("error creating new token: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh-token",
		Value:    refreshToken,
		Expires:  refreshExpireTime,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AccessToken{Token: accessToken, ExpiresAt: accessExpireTime.Unix()})
}

func (s Server) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	jwtToken := r.Header.Get("refresh-token")

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.auth.refreshkey), nil
	})

	if claims, ok := token.Claims.(*AuthClaims); ok && token.Valid {
		// check refresh token and create new access token if needed
		if claims.TokenType != "refresh" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		accessExpireTime := time.Now().Add(5 * 24 * time.Hour)
		accessToken, err := s.createAccessToken(claims.UserID, accessExpireTime)
		if err != nil {
			errString := fmt.Errorf("error creating new token: %v", err)
			log.Print(errString)
			http.Error(w, errString.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AccessToken{Token: accessToken, ExpiresAt: accessExpireTime.Unix()})
		return
	} else {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}
}

func (s Server) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ContextKey("props")).(string)
	if !ok {
		errString := fmt.Errorf("`UserID` field not found in token")
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUser(userID, s.DB)
	if err != nil {
		errString := fmt.Errorf("error finding user: %v", err)
		log.Print(errString)
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (s Server) GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := GetUsers(s.DB)
	if err != nil {
		errString := fmt.Errorf("error finding getting users: %v", err)
		log.Print(errString)
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (s Server) NewPantryHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ContextKey("props")).(string)
	if !ok {
		errString := fmt.Errorf("`UserID` field not found in token")
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusBadRequest)
		return
	}

	var newPantry NewPantryPayload
	if err := json.NewDecoder(r.Body).Decode(&newPantry); err != nil {
		errString := fmt.Errorf("error decoding new pantry form: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusBadRequest)
		return
	}

	pantry, err := NewPantry(newPantry.Name, userID, s.DB)
	if err != nil {
		errString := fmt.Errorf("error creating new pantry: %v", err)
		log.Print(errString)
		http.Error(w, errString.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(*pantry)
}

func (s Server) GetPantryHandler(w http.ResponseWriter, r *http.Request) {
	pantryID := mux.Vars(r)["pantry"]
	// userID, ok := r.Context().Value(ContextKey("props")).(string)
	// if !ok {
	// 	errString := fmt.Errorf("`UserID` field not found in token")
	// 	log.Print(errString)
	// 	http.Error(w, errString.Error(), http.StatusBadRequest)
	// 	return
	// }

	pantry, err := GetPantry(pantryID, s.DB)
	if err != nil {
		errString := fmt.Errorf("error finding pantry: %v", err)
		log.Print(errString)
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pantry)
}

func (s Server) GetPantriesHandler(w http.ResponseWriter, r *http.Request) {
	pantries, err := GetPantries(s.DB)
	if err != nil {
		errString := fmt.Errorf("error finding getting pantries: %v", err)
		log.Print(errString)
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pantries)
}
