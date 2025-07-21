package iam

import "fmt"

type IAMError struct {
	Message string    `json:"message"`
	Code    ErrorCode `json:"error_code"`
}

func (e IAMError) Error() string {
	return fmt.Sprintf("[ERR-%d]: %s", e.Code, e.Message)
}

type ErrorCode int

const (
	AlreadyExistsErr ErrorCode = iota + 100000
	NotFoundErr
	CouldNotGenerateErr
	ProviderErr
	WeakPasswordErr
	BadRequestErr
	UnknownErr
)
