package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var jwtKey = []byte("my_secret_key")

// In-memory store for refresh tokens
var refreshTokensStore = struct {
	sync.RWMutex
	tokens map[string]string // refreshToken -> username
}{tokens: make(map[string]string)}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Location struct {
	Latitude         float64 `json:"latitude"`
	Longitude        float64 `json:"longitude"`
	PlaceID          string  `json:"placeID"`
	FormattedAddress string  `json:"formattedAddress,omitempty"`
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/refresh", Refresh).Methods("POST")

	protected := router.PathPrefix("/").Subrouter()
	protected.Use(withJWTAuth)
	protected.HandleFunc("/locations", Locations).Methods("GET")

	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if creds.Username != "user" || creds.Password != "password" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	now := time.Now()

	// Create Access Token
	accessTokenExpiry := now.Add(15 * time.Minute)
	accessClaims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiry),
			Issuer:    "REACT-DEV-TEST_APP",
			Audience:  []string{"REACT-DEV-TEST_CLIENT"},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create access token", http.StatusInternalServerError)
		return
	}

	// Create Refresh Token
	refreshTokenExpiry := now.Add(7 * 24 * time.Hour)
	refreshClaims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshTokenExpiry),
			Issuer:    "REACT-DEV-TEST_APP",
			Audience:  []string{"REACT-DEV-TEST_CLIENT"},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create refresh token", http.StatusInternalServerError)
		return
	}

	// Store Refresh Token
	refreshTokensStore.Lock()
	refreshTokensStore.tokens[refreshTokenString] = creds.Username
	refreshTokensStore.Unlock()

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
	})
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	refreshTokenString := req.RefreshToken
	if refreshTokenString == "" {
		http.Error(w, "Refresh token required", http.StatusBadRequest)
		return
	}

	// Validate Refresh Token
	refreshClaims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenString, refreshClaims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Check if refresh token is in store
	refreshTokensStore.RLock()
	username, exists := refreshTokensStore.tokens[refreshTokenString]
	refreshTokensStore.RUnlock()

	if !exists || username != refreshClaims.Username {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	now := time.Now()

	// Create new Access Token
	accessTokenExpiry := now.Add(15 * time.Minute)
	accessClaims := &Claims{
		Username: refreshClaims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiry),
			Issuer:    "REACT-DEV-TEST_APP",
			Audience:  []string{"REACT-DEV-TEST_CLIENT"},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create access token", http.StatusInternalServerError)
		return
	}

	// Rotate Refresh Token
	newRefreshToken := uuid.NewString()
	refreshClaims.ID = newRefreshToken
	refreshClaims.ExpiresAt = jwt.NewNumericDate(now.Add(7 * 24 * time.Hour))

	newRefreshTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	newRefreshTokenString, err := newRefreshTokenJWT.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create refresh token", http.StatusInternalServerError)
		return
	}

	// Update Refresh Token Store
	refreshTokensStore.Lock()
	delete(refreshTokensStore.tokens, refreshTokenString)
	refreshTokensStore.tokens[newRefreshTokenString] = refreshClaims.Username
	refreshTokensStore.Unlock()

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessTokenString,
		"refresh_token": newRefreshTokenString,
	})
}

func withJWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Error(w, "Invalid token signature", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Token is not valid", http.StatusUnauthorized)
			return
		}

		if claims.Issuer != "REACT-DEV-TEST_APP" {
			http.Error(w, "Invalid token issuer", http.StatusUnauthorized)
			return
		}

		if len(claims.Audience) == 0 || claims.Audience[0] != "REACT-DEV-TEST_CLIENT" {
			http.Error(w, "Invalid token audience", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// Locations handler returns a list of locations, requires valid access token
func Locations(w http.ResponseWriter, r *http.Request) {
	locations := []Location{
		{
			Latitude:         37.9766618,
			Longitude:        -122.8476458,
			FormattedAddress: "1111 California St, San Francisco, CA 94108, United States",
		},
		{
			Latitude:         37.791507,
			Longitude:        -122.413124,
			FormattedAddress: "999 California St San Francisco, CA 94108",
		},
		{
			PlaceID: "ChIJf17NcIyAhYARmPyoC3oxN-4",
		},
		{
			PlaceID: "EjdDYWxpZm9ybmlhIFN0ICYgVGF5bG9yIFN0LCBTYW4gRnJhbmNpc2NvLCBDQSA5NDEwOCwgVVNBImYiZAoUChIJLR9yY42AhYARnc9XXJCCVX8SFAoSCS0fcmONgIWAEZ3PV1yQglV_GhQKEgmX5ReazICFgBHsUM0jqtIEcBoUChIJyaqQge2AhYARoBu9KRbcoTIiCg3ni4YWFW5WCbc",
		},
		{
			Latitude:         37.7906552,
			Longitude:        -122.419436,
			PlaceID:          "ChIJid5uXpOAhYAR7qzkSXdhKh4",
			FormattedAddress: "1095 Hyde St, San Francisco, CA 94109, USA",
		},
		{
			PlaceID: "",
		},
	}

	json.NewEncoder(w).Encode(locations)
}
