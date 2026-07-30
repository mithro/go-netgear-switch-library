// Package netgearswitch is the top-level entry point for this library; see
// alias.go for the re-exported model types/errors/registry that let callers
// depend on this single package instead of also importing model directly.
package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/shlex"
	"github.com/mithro/go-netgear-switch-library/model"
)

// secretCommandTimeout bounds how long a `!command` secret spec's process
// may run before it is killed, mirroring Python's _SECRET_COMMAND_TIMEOUT.
const secretCommandTimeout = 10 * time.Second

// SecretRunner runs an external command with the given name and arguments
// (as produced by shlex-splitting a `!command args...` secret spec) and
// returns its captured, untrimmed stdout. A non-nil exitErr means the
// command could not be started/completed or exited non-zero; its message is
// folded into the model.ErrCredential-wrapped error ResolveSecret returns.
// Passing a nil SecretRunner to ResolveSecret selects the default
// os/exec-based runner (10s timeout, stdout/stderr captured separately).
type SecretRunner func(name string, args []string) (stdout string, exitErr error)

// defaultRunner is the default SecretRunner: it runs name/args via os/exec
// under a secretCommandTimeout deadline, capturing stdout and stderr
// separately. On failure -- including a timeout, since a killed process
// also surfaces as a non-nil cmd.Run() error -- the returned error's
// message includes the exit code (when there is one) and the trimmed
// stderr text, matching the information Python's CredentialError carries.
func defaultRunner(name string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timed out after %s", secretCommandTimeout)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("exit %d: %s", exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return "", err
	}
	return stdout.String(), nil
}

// ResolveSecret resolves one secret spec to its value:
//
//   - spec == nil: returns (nil, nil) -- no secret configured.
//   - "${NAME}": looked up via env; if env reports the name unset, returns
//     an error wrapping model.ErrCredential that names NAME.
//   - "!cmd args...": shlex-split and run via runner (the default
//     os/exec-based runner if runner is nil); an empty command after
//     splitting, or a runner failure (non-zero exit, could-not-run, or
//     timeout), returns an error wrapping model.ErrCredential that
//     includes the command and the runner's failure detail (exit code +
//     stderr, for the default runner). On success the command's stdout is
//     returned with leading/trailing whitespace trimmed.
//   - anything else: returned as-is, a literal secret value.
//
// env mirrors a map[string]string lookup (name -> (value, present)) so
// callers can inject a fake environment in tests without mutating the
// process's real one.
func ResolveSecret(spec *string, env func(string) (string, bool), runner SecretRunner) (*string, error) {
	if spec == nil {
		return nil, nil
	}
	s := *spec
	if runner == nil {
		runner = defaultRunner
	}

	switch {
	case strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}"):
		name := s[2 : len(s)-1]
		val, ok := env(name)
		if !ok {
			return nil, fmt.Errorf("environment variable %q is not set: %w", name, model.ErrCredential)
		}
		return &val, nil

	case strings.HasPrefix(s, "!"):
		args, err := shlex.Split(s[1:])
		if err != nil {
			return nil, fmt.Errorf("secret command %q could not be parsed: %w: %w", s, err, model.ErrCredential)
		}
		if len(args) == 0 {
			return nil, fmt.Errorf("empty command in secret spec: %w", model.ErrCredential)
		}
		out, runErr := runner(args[0], args[1:])
		if runErr != nil {
			return nil, fmt.Errorf("secret command %v could not be run: %w: %w", args, runErr, model.ErrCredential)
		}
		trimmed := strings.TrimSpace(out)
		return &trimmed, nil

	default:
		return &s, nil
	}
}

// EnsureSecureFile returns an error wrapping model.ErrConfig if path is
// readable or writable by its group or by other (mode&0o077 != 0),
// instructing the caller to chmod 600 it. It is meant to be called on a
// config file once it is known to contain a literal (non-env, non-command)
// secret spec, mirroring Python's ensure_secure_file.
func EnsureSecureFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("%s has insecure permissions %#o; chmod 600 it (contains a literal secret): %w", path, mode, model.ErrConfig)
	}
	return nil
}
