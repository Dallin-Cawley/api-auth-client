package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/Dallin-Cawley/httpw"
	"github.com/Dallin-Cawley/public-api-auth/input"
	"github.com/Dallin-Cawley/public-api-auth/output"
)

var (
	theConfig = &Config{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
)

type Config struct {
	BaseURL     string
	Credentials *Credentials
	Logger      *slog.Logger
	CredLoader  Loader
}

// Option defines a functional option for configuring the auth package.
type Option func(*Config)

// WithBaseURL sets the base URL for the api-auth server.
func WithBaseURL(url string) Option {
	return func(config *Config) {
		config.BaseURL = url
	}
}

// WithLogger sets the logger to be used by the package.
func WithLogger(logger *slog.Logger) Option {
	return func(config *Config) {
		config.Logger = logger
	}
}

// WithLoader sets the loader to be used for loading credentials.
func WithLoader(l Loader) Option {
	return func(config *Config) {
		config.CredLoader = l
	}
}

// Init initializes the global configuration for the auth package with the provided options.
func Init(opts ...Option) error {
	newConfig := &Config{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	for _, opt := range opts {
		opt(newConfig)
	}

	if newConfig.BaseURL == "" {
		return &ErrMissingRequiredConfig{Field: "BaseURL"}
	}
	if newConfig.CredLoader == nil {
		return &ErrMissingRequiredConfig{Field: "Loader"}
	}

	theConfig = newConfig

	if err := LoadCredentials(theConfig.CredLoader); err != nil {
		return err
	}

	return nil
}

// LoadCredentials initializes the global configuration with credentials loaded from the provided loader.
func LoadCredentials(loader Loader) error {
	credentials, err := loader.Load()
	if err != nil {
		return fmt.Errorf("failed to load credentials: %w", err)
	}

	theConfig.Credentials = credentials
	return nil
}

// GetToken requests a new access token from the api-auth server using the provided credentials.
func GetToken() (*output.CreateTokenOutputBody, error) {
	return do[*output.CreateTokenOutputBody](
		"token",
		http.MethodPost,
		input.NewCreateTokenInputBody(&theConfig.Credentials.ClientID, &theConfig.Credentials.ClientSecret),
	)
}

// VerifyToken validates an access token with the api-auth server.
func VerifyToken(token string) (*output.ValidateOutputBody, error) {
	return do[*output.ValidateOutputBody](
		"validate",
		http.MethodPost,
		input.NewValidateTokenInputBody(token),
	)
}

// do is a generic helper that performs an HTTP request to the api-auth server and decodes the response.
func do[T any](path, method string, inputBody any) (T, error) {
	requestBodyBytes, err := json.Marshal(inputBody)
	if err != nil {
		return *new(T), fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/%s", theConfig.BaseURL, path)
	request, err := http.NewRequest(method, url, bytes.NewReader(requestBodyBytes))
	if err != nil {
		return *new(T), fmt.Errorf("failed to create request: %w", err)
	}

	return httpw.Do[T](
		request,
		&http.Client{},
		theConfig.Logger,
	)
}
