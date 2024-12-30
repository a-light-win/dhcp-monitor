package logger

import "github.com/rs/zerolog"

// AlreadyLoggedError is a type of error that has already been logged.
type AlreadyLoggedError struct {
	error
	Level zerolog.Level
}

func NewAlreadyLoggedError(err error, level zerolog.Level) *AlreadyLoggedError {
	return &AlreadyLoggedError{error: err, Level: level}
}

func (e *AlreadyLoggedError) Unwrap() error {
	return e.error
}
