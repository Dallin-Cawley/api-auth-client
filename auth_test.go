package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Dallin-Cawley/public-api-auth/output"
	"github.com/stretchr/testify/suite"
)

type AuthTestSuite struct {
	suite.Suite
}

func (testSuite *AuthTestSuite) TestInit() {
	baseURL := "https://api.example.com"
	creds := NewCredentials("id", "secret")
	loader := &mockLoader{creds: creds}
	err := Init(WithBaseURL(baseURL), WithLoader(loader))

	testSuite.NoError(err)
	testSuite.NotNil(theConfig)
	testSuite.Equal(baseURL, theConfig.BaseURL)
	testSuite.Equal(creds, theConfig.Credentials)
}

func (testSuite *AuthTestSuite) TestInit_WithLogger() {
	newLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	err := Init(WithBaseURL("https://api.example.com"), WithLoader(loader), WithLogger(newLogger))

	testSuite.NoError(err)
	testSuite.Equal(newLogger, theConfig.Logger)
}

func (testSuite *AuthTestSuite) TestInit_MissingBaseURL() {
	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	err := Init(WithLoader(loader))

	var missingConfigErr *ErrMissingRequiredConfig
	testSuite.ErrorAs(err, &missingConfigErr)
	testSuite.Equal("BaseURL", missingConfigErr.Field)
	testSuite.Equal("missing required configuration: BaseURL", err.Error())
}

func (testSuite *AuthTestSuite) TestInit_MissingLoader() {
	err := Init(WithBaseURL("https://api.example.com"))

	var missingConfigErr *ErrMissingRequiredConfig
	testSuite.ErrorAs(err, &missingConfigErr)
	testSuite.Equal("Loader", missingConfigErr.Field)
}

func (testSuite *AuthTestSuite) TestInit_LoadFailure() {
	baseURL := "https://api.example.com"
	loader := &mockLoader{err: fmt.Errorf("load error")}
	err := Init(WithBaseURL(baseURL), WithLoader(loader))

	testSuite.ErrorContains(err, "failed to load credentials: load error")
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

	loader := &mockLoader{creds: NewCredentials("client-id", "client-secret")}
	_ = Init(WithBaseURL(server.URL), WithLoader(loader))

	resp, err := GetToken()

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

	loader := &mockLoader{creds: NewCredentials("client-id", "client-secret")}
	_ = Init(WithBaseURL(server.URL), WithLoader(loader))

	_, err := GetToken()

	testSuite.ErrorContains(err, "http request failed with status code")
}

func (testSuite *AuthTestSuite) TestGetToken_RequestFailure() {
	loader := &mockLoader{creds: NewCredentials("client-id", "client-secret")}
	_ = Init(WithBaseURL(" http://invalid"), WithLoader(loader)) // Leading space makes it invalid for NewRequest

	_, err := GetToken()

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

	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	_ = Init(WithBaseURL(server.URL), WithLoader(loader))

	resp, err := VerifyToken("test-token")

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

	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	_ = Init(WithBaseURL(server.URL), WithLoader(loader))

	_, err := VerifyToken("invalid-token")

	testSuite.ErrorContains(err, "http request failed with status code")
}

func (testSuite *AuthTestSuite) TestDo_MarshalFailure() {
	_, err := do[any]("path", "METHOD", make(chan int))
	testSuite.ErrorContains(err, "failed to marshal request body")
}

type mockLoader struct {
	creds *Credentials
	err   error
}

func (m *mockLoader) Load() (*Credentials, error) {
	return m.creds, m.err
}

func (testSuite *AuthTestSuite) TestLoadCredentials_Success() {
	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	_ = Init(WithBaseURL("http://api.example.com"), WithLoader(loader))
	expectedCreds := NewCredentials("new-id", "new-secret")
	newLoader := &mockLoader{creds: expectedCreds}

	err := LoadCredentials(newLoader)

	testSuite.NoError(err)
	testSuite.Equal(expectedCreds, theConfig.Credentials)
}

func (testSuite *AuthTestSuite) TestLoadCredentials_Failure() {
	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	_ = Init(WithBaseURL("http://api.example.com"), WithLoader(loader))
	expectedErr := fmt.Errorf("load error")
	newLoader := &mockLoader{err: expectedErr}

	err := LoadCredentials(newLoader)

	testSuite.ErrorContains(err, "failed to load credentials: load error")
}

func Test_RunAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
