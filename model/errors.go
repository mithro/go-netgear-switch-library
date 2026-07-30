package model

import (
	"errors"
	"fmt"
)

// Sentinel errors mirroring the Python exception hierarchy; wrap with
// fmt.Errorf("...: %w", Err...) and match with errors.Is.
var (
	ErrUnsupportedCapability = errors.New("unsupported capability")
	ErrProtectedPort         = errors.New("protected port")
	// ErrKnownUnimplemented mirrors Python NotImplementedError uses:
	// a capability the device has but this library knowingly does not
	// implement (e.g. HTTP cert upload on m4300 → use SCP).
	ErrKnownUnimplemented = errors.New("known unimplemented")
	ErrCredential         = errors.New("credential error")
	ErrConfig             = errors.New("config error")
	ErrUnknownModel       = errors.New("unknown switch model")
	ErrSNMP               = errors.New("snmp error")
	ErrNSDP               = errors.New("nsdp error")
	ErrHTTP               = errors.New("http error")
)

// ErrHTTPAuth / ErrHTTPUnexpectedPage specialise ErrHTTP (errors.Is matches
// both the specific and general sentinel).
var (
	ErrHTTPAuth           = fmt.Errorf("%w: auth", ErrHTTP)
	ErrHTTPUnexpectedPage = fmt.Errorf("%w: unexpected page", ErrHTTP)
)

// WriteVerificationError reports a verify-after-write mismatch with the
// observed before/after state (Python WriteVerificationError).
type WriteVerificationError struct {
	Msg    string
	Before any
	After  any
}

func (e *WriteVerificationError) Error() string {
	return fmt.Sprintf("%s (before=%v after=%v)", e.Msg, e.Before, e.After)
}
