package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Dallin-Cawley/public-api-auth/input"
	"github.com/Dallin-Cawley/public-api-auth/output"
	"github.com/stretchr/testify/suite"
)

type AuthTestSuite struct {
	suite.Suite
}

func (testSuite *AuthTestSuite) TestSetConfig() {
	baseURL := "https://api.example.com"
	SetConfig(baseURL)

	testSuite.NotNil(theConfig)
	testSuite.Equal(baseURL, theConfig.BaseURL)
}

func (testSuite *AuthTestSuite) TestSetLogger() {
	newLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	SetLogger(newLogger)

	testSuite.Equal(newLogger, logger)
}

func (testSuite *AuthTestSuite) TestGetToken_Success() {
	expectedResponse := &output.CreateTokenOutputBody{
		AccessToken:   "test-token",
		AccessExpires: "2026-07-01T23:00:00Z",
		TokenType:     "Bearer",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testSuite.Equal(http.MethodPost, r.Method)
		testSuite.Equal("/token", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	}))
	defer server.Close()

	SetConfig(server.URL)

	inputBody := input.NewCreateTokenInputBody(new("client-id"), new("client-secret"))

	resp, err := GetToken(inputBody)

	testSuite.NoError(err)
	testSuite.Equal(expectedResponse.AccessToken, resp.AccessToken)
	testSuite.Equal(expectedResponse.AccessExpires, resp.AccessExpires)
	testSuite.Equal(expectedResponse.TokenType, resp.TokenType)
}

func (testSuite *AuthTestSuite) TestGetToken_Failure() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "internal server error")
	}))
	defer server.Close()

	SetConfig(server.URL)

	inputBody := input.NewCreateTokenInputBody(new("client-id"), new("client-secret"))

	_, err := GetToken(inputBody)

	testSuite.ErrorContains(err, "http request failed with status code")
}

func (testSuite *AuthTestSuite) TestGetToken_RequestFailure() {
	SetConfig(" http://invalid") // Leading space makes it invalid for NewRequest

	inputBody := input.NewCreateTokenInputBody(new("client-id"), new("client-secret"))

	_, err := GetToken(inputBody)

	testSuite.ErrorContains(err, "failed to create request")
}

func (testSuite *AuthTestSuite) TestVerifyToken_Success() {
	expectedResponse := &output.ValidateOutputBody{
		Subject:   "user-123",
		IssuedAt:  "1234567890",
		ExpiresAt: "1234567891",
		JWTID:     "jti-123",
		Scopes:    []string{"read", "write"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testSuite.Equal(http.MethodPost, r.Method)
		testSuite.Equal("/validate", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	}))
	defer server.Close()

	SetConfig(server.URL)

	inputBody := input.NewValidateTokenInputBody("test-token")

	resp, err := VerifyToken(inputBody)

	testSuite.NoError(err)
	testSuite.Equal(expectedResponse.Subject, resp.Subject)
	testSuite.Equal(expectedResponse.Scopes, resp.Scopes)
}

func (testSuite *AuthTestSuite) TestVerifyToken_Failure() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, "unauthorized")
	}))
	defer server.Close()

	SetConfig(server.URL)

	inputBody := input.NewValidateTokenInputBody("invalid-token")

	_, err := VerifyToken(inputBody)

	testSuite.ErrorContains(err, "http request failed with status code")
}

func (testSuite *AuthTestSuite) TestDo_MarshalFailure() {
	_, err := do[any]("path", "METHOD", make(chan int))
	testSuite.ErrorContains(err, "failed to marshal request body")
}

func Test_RunAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
