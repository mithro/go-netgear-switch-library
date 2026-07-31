# Captured HTTP web-UI fixtures (virtual package copy)

Byte copies of `tests/fixtures/http/*` from the pinned Python reference
`python-netgear-switch-library` @ `1841111` (snapshot worktree
`go-port-pin-1841111`), copied 2026-07-31. Real captured switch web-UI pages
(HTML) and GoAhead XML responses.

This is the SAME fixture set already carried in `webui/testdata/http/` (used
there to verify the dialect parsers byte-faithfully). It is duplicated here,
byte-for-byte, because Go's `testing`/`go:embed` resolve `testdata/` relative
to each PACKAGE, not the module root -- the `virtual` package's own tests
(the virtual HTTP face's login/dispatch/renderer tests, and Tasks 9/10's
byte-faithful per-model renderers) need their own local copy to read from.

Do not edit -- regenerate by re-copying from `webui/testdata/http/` (or,
ultimately, the re-pinned Python reference) if this set ever changes.
