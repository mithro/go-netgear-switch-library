# Captured HTTP web-UI fixtures

Byte copies of `tests/fixtures/http/*` from the pinned Python reference
`python-netgear-switch-library` @ `1841111` (snapshot worktree
`go-port-pin-1841111`), copied 2026-07-31. Real captured switch web-UI pages
(HTML) and GoAhead XML responses. Used to verify the webui dialect parsers
byte-faithfully and to drive the virtual HTTP face's renderers. Do not edit —
regenerate by re-copying from the (re-pinned) reference.

Twelve more files were copied 2026-08-17 from the same reference @ `b26eb1f`
(worktree `go-port-pin-b26eb1f`), for the GetUsers/GetServices slice:
`{gsm7252ps,m4300_24x}_user_management.html`, `gsm7252ps_user_configuration.html`
(the SNMPv3 trap page `ParseXUIUsers` must NOT mistake for login accounts), and
`{gsm7252ps,m4300_24x}_{http,https,ssh}_configuration.html` +
`{gsm7252ps,m4300_24x}_telnet.html` (the four management-service pages), plus
`gsm7228ps_http_configuration.html` (the S3300 page with no admin control at
all, for `ParseServicePage`'s refusal path).
