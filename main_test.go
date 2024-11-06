package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func setupRouter() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/refresh", Refresh).Methods("POST")

	protected := router.PathPrefix("/").Subrouter()
	protected.Use(withJWTAuth)
	protected.HandleFunc("/locations", Locations).Methods("GET")

	return router
}

func resetRefreshTokensStore() {
	refreshTokensStore.Lock()
	defer refreshTokensStore.Unlock()
	refreshTokensStore.tokens = make(map[string]string)
}

func TestLogin(t *testing.T) {
	router := setupRouter()

	tests := []struct {
		name           string
		payload        Credentials
		expectedStatus int
	}{
		{
			name: "Successful Login",
			payload: Credentials{
				Username: "user",
				Password: "password",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid Credentials",
			payload: Credentials{
				Username: "user",
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Bad Request",
			payload:        Credentials{},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if rr.Code == http.StatusOK {
				var resp map[string]string
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				if err != nil {
					t.Errorf("could not parse response: %v", err)
				}
				if _, ok := resp["access_token"]; !ok {
					t.Error("access_token not found in response")
				}
				if _, ok := resp["refresh_token"]; !ok {
					t.Error("refresh_token not found in response")
				}
			}
		})
	}
}

func TestRefresh(t *testing.T) {
	router := setupRouter()
	resetRefreshTokensStore()

	loginPayload := Credentials{
		Username: "user",
		Password: "password",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginReq, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	router.ServeHTTP(loginRR, loginReq)

	if loginRR.Code != http.StatusOK {
		t.Fatalf("failed to login, status code: %d", loginRR.Code)
	}

	var loginResp map[string]string
	err := json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if err != nil {
		t.Fatalf("could not parse login response: %v", err)
	}

	refreshToken, ok := loginResp["refresh_token"]
	if !ok {
		t.Fatal("refresh_token not found in login response")
	}

	tests := []struct {
		name           string
		payload        map[string]string
		expectedStatus int
	}{
		{
			name: "Successful Refresh",
			payload: map[string]string{
				"refresh_token": refreshToken,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid Refresh Token",
			payload: map[string]string{
				"refresh_token": "invalidtoken",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Bad Request",
			payload:        map[string]string{},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req, err := http.NewRequest("POST", "/refresh", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if rr.Code == http.StatusOK {
				var resp map[string]string
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				if err != nil {
					t.Errorf("could not parse response: %v", err)
				}
				if _, ok := resp["access_token"]; !ok {
					t.Error("access_token not found in response")
				}
				if _, ok := resp["refresh_token"]; !ok {
					t.Error("refresh_token not found in response")
				}
			}
		})
	}
}

func TestLocations(t *testing.T) {
	router := setupRouter()
	resetRefreshTokensStore()

	loginPayload := Credentials{
		Username: "user",
		Password: "password",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginReq, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	router.ServeHTTP(loginRR, loginReq)

	if loginRR.Code != http.StatusOK {
		t.Fatalf("failed to login, status code: %d", loginRR.Code)
	}

	var loginResp map[string]string
	err := json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if err != nil {
		t.Fatalf("could not parse login response: %v", err)
	}

	accessToken, ok := loginResp["access_token"]
	if !ok {
		t.Fatal("access_token not found in login response")
	}

	validAuthHeader := "Bearer " + accessToken
	invalidAuthHeader := "Bearer invalidtoken"

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "Access Locations with Valid Token",
			authHeader:     validAuthHeader,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Access Locations with Invalid Token",
			authHeader:     invalidAuthHeader,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Access Locations without Token",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/locations", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if rr.Code == http.StatusOK {
				var locations []Location
				err := json.Unmarshal(rr.Body.Bytes(), &locations)
				if err != nil {
					t.Errorf("could not parse locations response: %v", err)
				}
				if len(locations) != 6 {
					t.Errorf("expected 6 locations, got %d", len(locations))
				}
			}
		})
	}
}

func TestTokenValidation(t *testing.T) {
	router := setupRouter()
	resetRefreshTokensStore()

	now := time.Now()
	claims := &Claims{
		Username: "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			Issuer:    "REACT-DEV-TEST_APP",
			Audience:  []string{"REACT-DEV-TEST_CLIENT"},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		t.Fatalf("could not sign token: %v", err)
	}

	invalidIssuerClaims := &Claims{
		Username: "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			Issuer:    "invalid-issuer",
			Audience:  []string{"REACT-DEV-TEST_CLIENT"},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	invalidIssuerToken := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidIssuerClaims)
	invalidIssuerTokenString, err := invalidIssuerToken.SignedString(jwtKey)
	if err != nil {
		t.Fatalf("could not sign token: %v", err)
	}

	invalidAudienceClaims := &Claims{
		Username: "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			Issuer:    "REACT-DEV-TEST_APP",
			Audience:  []string{"invalid-audience"},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	invalidAudienceToken := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidAudienceClaims)
	invalidAudienceTokenString, err := invalidAudienceToken.SignedString(jwtKey)
	if err != nil {
		t.Fatalf("could not sign token: %v", err)
	}

	expiredClaims := &Claims{
		Username: "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(-15 * time.Minute)),
			Issuer:    "REACT-DEV-TEST_APP",
			Audience:  []string{"REACT-DEV-TEST_CLIENT"},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Minute)),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString(jwtKey)
	if err != nil {
		t.Fatalf("could not sign token: %v", err)
	}

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "Valid Token",
			authHeader:     "Bearer " + tokenString,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid Issuer",
			authHeader:     "Bearer " + invalidIssuerTokenString,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Audience",
			authHeader:     "Bearer " + invalidAudienceTokenString,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Expired Token",
			authHeader:     "Bearer " + expiredTokenString,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Malformed Token",
			authHeader:     "Bearer malformed.token.here",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Missing Bearer",
			authHeader:     tokenString,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Empty Token",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/locations", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestMainHandler(t *testing.T) {
	router := setupRouter()
	resetRefreshTokensStore()

	loginPayload := Credentials{
		Username: "user",
		Password: "password",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginReq, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	router.ServeHTTP(loginRR, loginReq)

	if loginRR.Code != http.StatusOK {
		t.Fatalf("failed to login, status code: %d", loginRR.Code)
	}

	var loginResp map[string]string
	err := json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	if err != nil {
		t.Fatalf("could not parse login response: %v", err)
	}

	_, ok := loginResp["access_token"]
	if !ok {
		t.Fatal("access_token not found in login response")
	}

	refreshToken, ok := loginResp["refresh_token"]
	if !ok {
		t.Fatal("refresh_token not found in login response")
	}

	refreshPayload := map[string]string{
		"refresh_token": refreshToken,
	}
	refreshBody, _ := json.Marshal(refreshPayload)
	refreshReq, _ := http.NewRequest("POST", "/refresh", bytes.NewBuffer(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshRR := httptest.NewRecorder()
	router.ServeHTTP(refreshRR, refreshReq)

	if refreshRR.Code != http.StatusOK {
		t.Fatalf("failed to refresh token, status code: %d", refreshRR.Code)
	}

	var refreshResp map[string]string
	err = json.Unmarshal(refreshRR.Body.Bytes(), &refreshResp)
	if err != nil {
		t.Fatalf("could not parse refresh response: %v", err)
	}

	newAccessToken, ok := refreshResp["access_token"]
	if !ok {
		t.Fatal("access_token not found in refresh response")
	}

	_, ok = refreshResp["refresh_token"]
	if !ok {
		t.Fatal("refresh_token not found in refresh response")
	}

	req, err := http.NewRequest("GET", "/locations", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+newAccessToken)
	locationsRR := httptest.NewRecorder()
	router.ServeHTTP(locationsRR, req)

	if locationsRR.Code != http.StatusOK {
		t.Fatalf("failed to access locations, status code: %d", locationsRR.Code)
	}

	var locations []Location
	err = json.Unmarshal(locationsRR.Body.Bytes(), &locations)
	if err != nil {
		t.Fatalf("could not parse locations response: %v", err)
	}

	if len(locations) != 6 {
		t.Errorf("expected 6 locations, got %d", len(locations))
	}

	oldRefreshPayload := map[string]string{
		"refresh_token": refreshToken,
	}
	oldRefreshBody, _ := json.Marshal(oldRefreshPayload)
	oldRefreshReq, _ := http.NewRequest("POST", "/refresh", bytes.NewBuffer(oldRefreshBody))
	oldRefreshReq.Header.Set("Content-Type", "application/json")
	oldRefreshRR := httptest.NewRecorder()
	router.ServeHTTP(oldRefreshRR, oldRefreshReq)

	if oldRefreshRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for old refresh token, got status code: %d", oldRefreshRR.Code)
	}
}
