package auth

import "fmt"

// ErrMissingRequiredConfig is returned when a required configuration field is missing during initialization.
type ErrMissingRequiredConfig struct {
	Field string
}

func (err *ErrMissingRequiredConfig) Error() string {
	return fmt.Sprintf("missing required configuration: %s", err.Field)
}
