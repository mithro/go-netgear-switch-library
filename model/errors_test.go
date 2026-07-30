package model_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// TestSentinelErrors verifies sentinel errors can be matched with errors.Is.
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "ErrProtectedPort direct",
			err:  model.ErrProtectedPort,
			want: model.ErrProtectedPort,
		},
		{
			name: "ErrProtectedPort wrapped",
			err:  fmt.Errorf("x: %w", model.ErrProtectedPort),
			want: model.ErrProtectedPort,
		},
		{
			name: "ErrUnsupportedCapability",
			err:  model.ErrUnsupportedCapability,
			want: model.ErrUnsupportedCapability,
		},
		{
			name: "ErrKnownUnimplemented",
			err:  model.ErrKnownUnimplemented,
			want: model.ErrKnownUnimplemented,
		},
		{
			name: "ErrCredential",
			err:  model.ErrCredential,
			want: model.ErrCredential,
		},
		{
			name: "ErrConfig",
			err:  model.ErrConfig,
			want: model.ErrConfig,
		},
		{
			name: "ErrUnknownModel",
			err:  model.ErrUnknownModel,
			want: model.ErrUnknownModel,
		},
		{
			name: "ErrSNMP",
			err:  model.ErrSNMP,
			want: model.ErrSNMP,
		},
		{
			name: "ErrNSDP",
			err:  model.ErrNSDP,
			want: model.ErrNSDP,
		},
		{
			name: "ErrHTTP",
			err:  model.ErrHTTP,
			want: model.ErrHTTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.want) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.want)
			}
		})
	}
}

// TestHTTPErrorHierarchy verifies ErrHTTPAuth and ErrHTTPUnexpectedPage
// are specialisations of ErrHTTP.
func TestHTTPErrorHierarchy(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "ErrHTTPAuth matches ErrHTTP",
			err:  model.ErrHTTPAuth,
		},
		{
			name: "ErrHTTPUnexpectedPage matches ErrHTTP",
			err:  model.ErrHTTPUnexpectedPage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, model.ErrHTTP) {
				t.Errorf("errors.Is(%v, model.ErrHTTP) = false, want true", tt.err)
			}
		})
	}
}

// TestWriteVerificationError verifies the error message formatting.
func TestWriteVerificationError(t *testing.T) {
	err := &model.WriteVerificationError{
		Msg:    "pvid mismatch",
		Before: 1,
		After:  5,
	}

	got := err.Error()
	want := "pvid mismatch (before=1 after=5)"

	if got != want {
		t.Errorf("WriteVerificationError.Error() = %q, want %q", got, want)
	}
}

// TestWriteVerificationErrorWrapped verifies errors.As can extract
// WriteVerificationError through wrapping.
func TestWriteVerificationErrorWrapped(t *testing.T) {
	original := &model.WriteVerificationError{
		Msg:    "config mismatch",
		Before: "old",
		After:  "new",
	}
	wrapped := fmt.Errorf("failed to verify write: %w", original)

	var wve *model.WriteVerificationError
	if !errors.As(wrapped, &wve) {
		t.Errorf("errors.As() = false, want true")
	}

	if wve != original {
		t.Errorf("errors.As() extracted %v, want %v", wve, original)
	}
}
