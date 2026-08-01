# Slice 07 Dossier: FASTPATH CLI Transport + Fake CLI Listener (Python → Go porting reference)

> **Source of truth:** frozen pin snapshot
> `/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-7ebfe5d`
> (commit `7ebfe5d475411a7d88fd5cc68ff86ee3a4505362`, detached — "fix: XuiListPage
> defaults break the import on Python 3.11"). Every claim below cites
> `file:line` in that snapshot. The live checkout and the Go repo were never
> read. All line numbers are exact as of this pin.

---

## 0. CRITICAL CORRECTION TO THE TASK PREMISE — read this first

The task brief assumes the Python "FAKE (virtual) CLI listener" is *"a REAL
SSH server + REAL Telnet listener that emulates the device CLI"*. **That is
not what exists in this pin.** `virtual/faces/cli.py`'s own module docstring
says the opposite, verbatim:

> "Unlike the HTTP face (which binds a real `ThreadingHTTPServer` so httpx
> clients hit a socket), the CLI face is an IN-PROCESS transport: it
> implements the same `CliSession` seam `CliReader`/`CliWriter` depend on and
> dispatches each command string straight to the `cli_fastpath` renderer
> (reads) or to a state mutation (writes) — **no SSH server, no socket, no
> host keys**." (`virtual/faces/cli.py:5-11`)

And the reasoning given: "live SSH cannot be exercised from CI (no network)
and the real byte transports are documented as transport-only, so the mock
proves the command-dispatch + parser round trip (the part that CAN be
tested) rather than standing up a paramiko server whose value would be
untestable here anyway." (`virtual/faces/cli.py:9-11`)

`VirtualSwitch.cli_session()` confirms this at the call-site: "Unlike the
SNMP/NSDP/HTTP faces (real sockets bound in `start()`), the CLI face is an
in-process `CliSession` needing no socket" (`virtual/server.py:130-140`).
There is **no host key**, **no accepted username/password pair enforced by a
listener**, **no port bound**, and consequently **no prompt/banner/MOTD
strings are ever emitted on a wire** — the mock's `run()` method returns bare
command-output text (never framed with a prompt), and `VirtualCliFace.close()`
is a no-op (`virtual/faces/cli.py:420-421`: `def close(self) -> None: pass`).

**Implication for the Go port plan author:** a byte-faithful "real SSH +
real Telnet fake listener" is a *new design decision*, not a port of
existing Python behavior — there is no Python prompt/banner string, auth
handshake, or paging-emulation byte sequence to be faithful to on the fake
side, because the Python fake never puts any of that on a wire. What Go
*can* port faithfully is: (a) the real transport's client-side session state
machine (`session.py`'s `ShellDriver`, quoted in full below — this the Go
fake's SSH/Telnet server-side prompt output must satisfy from the *client's*
regex perspective if a real-listener fake is built), and (b) the in-process
command-dispatch table (`VirtualCliFace.run`), which is the actual
byte-for-byte-relevant "what does this command return" ground truth. This
dossier documents both, plus flags every point where a Go real-listener fake
must *invent* prompt/banner text consistent with §2's prompt regex (since
none is transcribed in Python) — see the Parity Checklist §6 items marked
**[NEW DESIGN]**.

---

## 1. `src/netgear_switch/transport/cli/session.py` (241 lines) — the shared session state machine

Module docstring: "`CliSession` is the single seam `cli_read.CliReader`
depends on... `ShellDriver` holds the byte-level interactive-shell logic
(send a command, read back until the FASTPATH prompt reappears, strip the
command echo and the trailing prompt) so all three real transports share it
— they differ only in how a channel's `send`/`recv` bytes are wired."
(`session.py:1-14`)

### 1.1 Sentinels — quoted verbatim

```python
# session.py:28-46
_PROMPT_RE = re.compile(r"\)\s*(?:\([^)]*\)\s*)?[#>]\s*$")
_PASSWORD_RE = re.compile(r"[Pp]assword:\s*$")
_MAX_READS = 10_000

_SCP_TOFU_RE = re.compile(r"host key|continue connecting|\(yes\s*/\s*no", re.IGNORECASE)
_SCP_PASSWORD_RE = re.compile(r"[Pp]assword:")
_SCP_CONFIRM_RE = re.compile(r"\(y\s*/\s*n\)")
_SCP_SUCCESS_RE = re.compile(
    r"bytes transferred|completed successfully|operation completed", re.IGNORECASE
)
_SCP_FAILURE_RE = re.compile(
    r"transfer failed|failed!|%\s*error|error during", re.IGNORECASE
)
```

- `_PROMPT_RE` (`session.py:28`): comment above it (`session.py:25-28`)
  explains the shape: "FASTPATH prompts look like `(GSM7252PS) #`
  (privileged) or `(GSM7252PS) >` (unprivileged); some pages also show
  `(GSM7252PS) (Config)#`. Match a `)` followed by an optional word and a
  `#`/`>` at end of the buffered output." **Anchored to end-of-buffer**
  (`\s*$`) — unlike the SCP sentinels below.
- `_PASSWORD_RE` (`session.py:29`): also end-anchored.
  `_MAX_READS = 10_000` (`session.py:32`) — "a hard cap so a transport that
  never sees a prompt (wrong device, hung link) fails instead of looping
  forever" (`session.py:30-31`).
- The five SCP sentinels (`session.py:39-47`) are **NOT** end-anchored —
  comment explicitly notes: "Not anchored to end-of-buffer (unlike
  `_PROMPT_RE`): these appear inline as the switch's SCP client runs, so
  they are matched anywhere in the accumulated read buffer" (`session.py:38-39`).
  They are GROUNDED in prior art: "GROUNDED in the working certbot-hook
  `FastpathScpUpdater._send_copy` regexes" (`session.py:35-36`).

There is **no separate login-prompt regex** in `session.py` — login
(`User:`/username) is each transport's own responsibility (see §2.2, §2.3);
`ShellDriver.setup()` only ever consumes an *initial prompt* and drives
`enable` + paging-off, assuming auth already happened at the transport
layer before `ShellDriver` is constructed.

### 1.2 `CliSession` Protocol (`session.py:50-72`)

```python
class CliSession(Protocol):
    def run(self, command: str) -> str: ...
    def run_scp_copy(self, command: str, scp_password: str) -> str: ...
    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str: ...
    def close(self) -> None: ...
```
Docstring on `run`: "issues one command and returns its output text with the
echoed command line and the trailing prompt removed. Setup (enable + disable
paging) is the transport's responsibility, done before the first `run`."
(`session.py:53-55`)

`CliTransportError` (`session.py:75-76`): "A CLI transport failed to
connect, authenticate, or read a prompt." — the ONE exception type every
transport raises for connect/auth/prompt failures.

### 1.3 `ShellDriver` — full state machine

Constructor (`session.py:89-104`):
```python
def __init__(
    self,
    send: Callable[[bytes], None],
    recv: Callable[[int], bytes],
    *,
    enable_cmd: str = "enable",
    paging_off_cmd: str = "terminal length 0",
    enable_password: str | None = None,
    newline: str = "\r\n",
) -> None:
```
"`send` writes bytes to the channel; `recv` returns up to `n` bytes
(blocking, may return a partial chunk). This is deliberately transport-free
so SSH, telnet and console reuse it unchanged." (`session.py:82-84`)
Default `newline` is `"\r\n"` (`session.py:97`) — every written line is
`(text + "\r\n").encode("latin-1")` (`session.py:121-122`, `_write_line`).
**Encoding is `latin-1` everywhere** (both `_write_line`'s encode and
`_read_until`'s `chunk.decode("latin-1", errors="replace")` at
`session.py:111`) — not UTF-8. Go port must byte-preserve this (Go `string`
+ raw byte slices are fine; just never assume UTF-8 validity).

**`_read_until(self, *, allow_password: bool) -> str`** (`session.py:106-119`):
```
buf = ""
for _ in range(_MAX_READS):
    chunk = self._recv(4096)          # read up to 4096 bytes at a time
    if chunk:
        buf += chunk.decode("latin-1", errors="replace")
    if _PROMPT_RE.search(buf):
        return buf
    if allow_password and _PASSWORD_RE.search(buf):
        return buf
    if not chunk:
        break                          # channel closed, no prompt seen
raise CliTransportError("no CLI prompt seen before end of stream")
```
Read chunk size is **exactly 4096 bytes** per `recv()` call
(`session.py:109`). Loop bound is `_MAX_READS` (10,000) iterations, NOT a
wall-clock timeout — the transport-level `settimeout`/timeout parameter
(§2.1–2.3) is what actually bounds wall-clock time per `recv()` call; a
`recv()` that blocks forever with `_MAX_READS` never reached would hang
forever (transport timeouts are the real backstop).

**`setup()`** (`session.py:124-134`) — the connect→auth→enable→disable-paging
sequence:
```
self._read_until(allow_password=False)     # 1. consume initial banner/prompt
self._write_line(self._enable_cmd)          # 2. send "enable"
out = self._read_until(allow_password=True) # 3. read reply, may be a password prompt
if _PASSWORD_RE.search(out):
    self._write_line(self._enable_password or "")  # 4. answer enable password
    self._read_until(allow_password=False)          #    (reuses the LOGIN password)
self._write_line(self._paging_off_cmd)      # 5. send "terminal length 0"
self._read_until(allow_password=False)      # 6. consume its reply
```
Comment: "Consume the initial banner/prompt, `enable`, then disable
paging." (`session.py:125`). Step 4's password-reuse comment: "enable asked
for a password; reuse the login password by default." (`session.py:130`).

**`run(command)`** (`session.py:136-139`):
```
self._write_line(command)
raw = self._read_until(allow_password=False)
return self._clean(raw, command)
```

**`run_scp_copy(command, scp_password)`** (`session.py:141-198`) — drives
the interactive `copy scp://...` prompt sequence. Docstring
(`session.py:142-161`) states the three mid-flight prompts it answers, in
order of the loop's `if` checks (`session.py:173-195`):
1. `_SCP_FAILURE_RE` checked FIRST every iteration → raises
   `CliTransportError(f"SCP copy reported a failed transfer: {command!r}")`
   (`session.py:173-176`).
2. `_SCP_TOFU_RE` (host-key TOFU) → writes `"yes"` via `_write_line`, resets
   `buf = ""` (`session.py:177-180`).
3. `_SCP_PASSWORD_RE` → writes `scp_password` via `_write_line`, resets
   `buf = ""` (`session.py:181-184`).
4. `_SCP_CONFIRM_RE` (`(y/n)` overwrite) → `self._send(b"y")` — **bare byte
   `y`, NO trailing newline** ("FASTPATH's `(y/n)` overwrite confirm takes a
   single keystroke", `session.py:186-189`), resets `buf = ""`.
5. `_SCP_SUCCESS_RE` → sets local `succeeded = True` but does NOT return yet
   (`session.py:190-191`).
6. `_PROMPT_RE` → returns the full `transcript` (`session.py:192-193`).
7. `if not chunk: break` → loop ends without a prompt: if `succeeded` was
   already set, return `transcript` anyway (`session.py:196-197`);
   otherwise raise `CliTransportError(f"SCP copy did not complete: {command!r}")`
   (`session.py:198`).
Each branch resets the local `buf` to `""` after acting (but NOT
`transcript`, which accumulates every chunk across the whole call,
`session.py:171`) — so each sentinel is matched only against bytes received
*since the last answered prompt*, not the whole transcript.

**`run_write_memory(command="write memory", *, prestuff)`**
(`session.py:200-229`):
- `prestuff=True` path: `self._send((command + "\ry\r").encode("latin-1"))`
  (`session.py:210`) — sends command + `\r` + `y` + `\r` **in one single
  write call**, no read in between. Docstring: "`prestuff=True`
  (GSM7252PS) pre-stuffs the `y` in the SAME write as the command, because
  that image's confirm has a tiny timeout that a read-then-answer round trip
  races" (`session.py:203-205`).
- `prestuff=False` path: `self._write_line(command)` (normal `\r\n`
  newline, NOT `\r`) then the read loop watches `_SCP_CONFIRM_RE` (reused
  `(y/n)` regex) and answers with bare `self._send(b"y")` (no newline) when
  seen (`session.py:221-224`). Docstring: "`prestuff=False` (M4300) waits
  for the `(y/n)` prompt then answers `y`" (`session.py:206-207`).
- Loop ends on `_PROMPT_RE` match → returns `transcript`
  (`session.py:225-226`); `if not chunk: break` then falls through to
  `raise CliTransportError("write memory did not complete")` (`session.py:229`)
  — **no `succeeded` short-circuit here** unlike `run_scp_copy` (an
  asymmetry: write-memory never treats "saw a success phrase but no prompt"
  as success).

**`_clean(raw, command)`** (`session.py:231-241`, `@staticmethod`) — strips
echo + trailing prompt:
```python
lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
if lines and command.strip() and command.strip() in lines[0]:
    lines = lines[1:]                       # drop echoed command line
while lines and _PROMPT_RE.search(lines[-1]):
    lines = lines[:-1]                      # drop trailing prompt line(s)
return "\n".join(lines).strip("\n")
```
Command-echo match is **substring containment** (`command.strip() in
lines[0]`), not exact equality — tolerates a device echoing the command with
extra leading/trailing whitespace or control bytes on that line. The prompt
strip is a `while` loop (can strip MULTIPLE trailing blank/prompt-matching
lines), applied to `lines[-1]` (last line) each time.

---

## 2. Per-transport specifics

### 2.1 SSH — `src/netgear_switch/transport/cli/ssh.py` (147 lines)

**Library: `paramiko`**, imported LAZILY inside `connect()`
(`ssh.py:91-96`) — "paramiko is an OPTIONAL dependency (the `[ssh]` extra)
and is imported LAZILY inside `connect`... exactly like the httpx transport
under `transport/http`" (`ssh.py:3-5`). Missing paramiko raises
`CliTransportError("SSH CLI transport requires paramiko (install the '[ssh]' extra)")`
(`ssh.py:93-96`).

**Version pin and legacy-crypto rationale — quoted in full** (`ssh.py:7-27`):
> "Old FASTPATH firmware (the GSM7252PS/M4300 generation) only offers the
> legacy key exchange `diffie-hellman-group14-sha1` and the `ssh-rsa`
> (SHA-1) host-key algorithm. paramiko 3.0 dropped both from its DEFAULT
> preferred lists (and later releases removed some legacy SHA-1 primitives
> outright), so a stock modern paramiko negotiates NOTHING with these
> switches and the handshake fails.
>
> Two mitigations, applied together:
> 1. Pin the dependency to a release that still ships and prefers the legacy
>    algorithms — `paramiko>=2.12,<3` (2.12 is CONFIRMED working against a
>    real GSM7252PS). This is the `[ssh]` extra's constraint in
>    `pyproject.toml`.
> 2. Belt-and-suspenders, ALSO re-insert the legacy algorithms into the
>    `Transport`'s preferred KEX / host-key lists explicitly here via
>    `get_security_options()` when the running paramiko still defines them,
>    so the transport keeps working even if a newer paramiko is installed
>    that retains the primitives but merely de-prioritised them."

Exact algorithm identifiers (`ssh.py:41-43`):
```python
_LEGACY_KEX = "diffie-hellman-group14-sha1"
_LEGACY_HOSTKEYS = ("ssh-rsa",)
```

`_prefer_legacy_algorithms(transport)` (`ssh.py:70-88`, `@staticmethod`):
```python
opts = transport.get_security_options()
available_kex = set(opts.kex)
if _LEGACY_KEX in available_kex:
    opts.kex = (_LEGACY_KEX, *(k for k in opts.kex if k != _LEGACY_KEX))
available_keys = set(opts.key_types)
wanted_keys = tuple(k for k in _LEGACY_HOSTKEYS if k in available_keys)
if wanted_keys:
    opts.key_types = (
        *wanted_keys,
        *(k for k in opts.key_types if k not in wanted_keys),
    )
```
Moves the legacy KEX/host-key algorithm to the FRONT of the preferred list
(doesn't remove others) and is a documented no-op ("never an error") if the
running paramiko no longer defines the legacy primitive at all
(`ssh.py:72-77`).

**Connect sequence** (`connect()`, `ssh.py:90-118`):
```python
transport = paramiko.Transport((self._host, self._port))
self._prefer_legacy_algorithms(transport)
transport.start_client(timeout=self._timeout)
transport.auth_password(self._username, self._password)
channel = transport.open_session(timeout=self._timeout)
channel.get_pty()
channel.invoke_shell()
channel.settimeout(self._timeout)
```
Key facts:
- **Uses `paramiko.Transport` directly, NOT `paramiko.SSHClient`** — so
  there is **no host-key verification/policy at all** (no
  `set_missing_host_key_policy`, no known_hosts check, nothing). This is a
  from-scratch `Transport` object with `start_client()` called directly —
  **any host key is accepted implicitly** because it is never checked.
  **Go port parity implication:** the equivalent `x/crypto/ssh.ClientConfig`
  should use `HostKeyCallback: ssh.InsecureIgnoreHostKey()` (or a custom
  callback that always returns nil) to match this Python behavior exactly.
- **Auth method: password only** — `transport.auth_password(username, password)`
  (`ssh.py:101`). No pubkey, no keyboard-interactive, no agent.
- **Default port 22**, default timeout `_DEFAULT_TIMEOUT = 20.0` seconds
  (`ssh.py:44,57-58`).
- **PTY requested with NO explicit term type/width/height** —
  `channel.get_pty()` (`ssh.py:103`) is called with zero arguments, so
  paramiko's own defaults apply (paramiko's `get_pty` default term is
  `"vt100"`, default `width=80`, `height=24`, `width_pixels=0`,
  `height_pixels=0` — these are paramiko library defaults, not values
  chosen in this codebase; the Go `x/crypto/ssh` session's
  `RequestPty("vt100", 24, 80, ssh.TerminalModes{})` is the direct
  equivalent to replicate byte-for-byte if the switch's output differs by
  terminal width).
- **Shell mode, not exec** — `channel.invoke_shell()` (`ssh.py:104`), never
  `exec_command`. This is required because `ShellDriver` needs a live
  interactive PTY session (multiple commands over one channel).
  `channel.settimeout(self._timeout)` (`ssh.py:105`) sets the PER-`recv()`-
  CALL timeout (this is what actually bounds `ShellDriver._read_until`'s
  10,000-iteration loop in practice — a `recv()` that times out raises,
  which propagates as a connect/read failure).
- All of the above wrapped in one `try/except Exception as exc:` that calls
  `self.close()` then re-raises as
  `CliTransportError(f"SSH connect/auth failed: {exc}")` (`ssh.py:106-108`)
  — **any exception during the whole connect+auth+pty+shell sequence** is
  normalized to one error type.

**`ShellDriver` construction** (`ssh.py:111-117`):
```python
self._driver = ShellDriver(
    channel.sendall,
    channel.recv,
    enable_cmd=self._spec.enable_cmd,
    paging_off_cmd=self._spec.paging_off_cmd,
    enable_password=self._password,
)
self._driver.setup()
```
`send` is bound to `channel.sendall` (blocks until all bytes written, unlike
plain `send`); `recv` is bound to `channel.recv` directly.
`enable_password=self._password` — **the SSH login password IS the enable
password** by default (no separate enable-password config field on this
transport).

**`run`/`run_scp_copy`/`run_write_memory`** (`ssh.py:120-136`): each
lazily calls `self.connect()` if `self._driver is None`, then delegates to
the driver 1:1. Note the `assert self._driver is not None` right after
(mypy narrowing idiom, not a runtime behavior of interest).

**`close()`** (`ssh.py:138-147`):
```python
if self._channel is not None:
    with contextlib.suppress(Exception):   # teardown must not raise
        self._channel.close()
    self._channel = None
if self._transport is not None:
    with contextlib.suppress(Exception):
        self._transport.close()
    self._transport = None
self._driver = None
```
Channel closed BEFORE transport; **all exceptions during teardown are
swallowed** — comment "teardown must not raise" appears on both suppress
blocks.

### 2.2 Telnet — `src/netgear_switch/transport/cli/telnet.py` (104 lines)

**Library: stdlib `telnetlib`**, imported LAZILY (`telnet.py:58-64`).
Module docstring flags its deprecation: "the stdlib `telnetlib` module was
DEPRECATED in Python 3.11 and REMOVED in Python 3.13... on 3.13+
constructing this transport raises a clear `CliTransportError` telling the
caller to use SSH or the console transport instead." (`telnet.py:8-12`).
The `ImportError` handler at `telnet.py:60-64` raises exactly:
`CliTransportError("telnet CLI transport requires the stdlib 'telnetlib', removed in Python 3.13 -- use the SSH or console transport instead")`.
"Telnet on a management switch is plaintext and best avoided anyway."
(`telnet.py:12`)

**IAC negotiation:** telnetlib handles IAC negotiation internally with its
own default (mostly-refuse) option handler — **there is no custom option
handler installed in this file**; `telnetlib.Telnet(host, port,
timeout=...)` (`telnet.py:66`) is constructed with defaults. **Go port
parity implication:** whatever raw-socket/hand-rolled IAC handling the Go
telnet client uses must replicate `telnetlib`'s default behavior of
transparently stripping/refusing IAC sequences from the byte stream fed to
`ShellDriver` — i.e. `ShellDriver` NEVER sees raw IAC bytes in the Python
implementation, so the Go equivalent must do IAC processing at a layer
BELOW the shared `ShellDriver`-equivalent, exactly like `telnetlib` does
here.

**Login sequence** (`_login`, `telnet.py:50-55`):
```python
# FASTPATH telnet prompts "User:" then "Password:" before the shell.
conn.read_until(b"User:", timeout=self._timeout)
conn.write(self._username.encode("latin-1") + b"\r\n")
conn.read_until(b"Password:", timeout=self._timeout)
conn.write(self._password.encode("latin-1") + b"\r\n")
```
Exact literal byte sequences waited for: `b"User:"` then `b"Password:"`
(NOT regexes — `telnetlib.read_until` does a literal substring search).
Both writes append `\r\n`; encoding `latin-1` (matches `ShellDriver`).
**No confirmation read after the password write** — `_login` returns
immediately after writing the password; the very next thing that happens is
`ShellDriver.setup()`'s own `_read_until(allow_password=False)` consuming
whatever comes back (the initial post-login prompt/banner).

**Connect sequence** (`connect()`, `telnet.py:57-79`):
```python
conn = telnetlib.Telnet(self._host, self._port, timeout=self._timeout)
self._login(conn)
```
wrapped in `try/except Exception as exc: self.close(); raise CliTransportError(f"telnet connect/login failed: {exc}")`
(`telnet.py:68-70`). Default port `23` (`telnet.py:38`), default timeout
`_DEFAULT_TIMEOUT = 20.0` (`telnet.py:25`) — **NOTE: some models (gsm7228ps)
override this default at the caller** — see §3.2, telnet CLI listens on
port **60000**, not 23, for that model.

**`ShellDriver` construction** (`telnet.py:72-78`):
```python
self._driver = ShellDriver(
    lambda data: conn.write(data),
    lambda n: conn.read_eager() or conn.read_some(),
    enable_cmd=self._spec.enable_cmd,
    paging_off_cmd=self._spec.paging_off_cmd,
    enable_password=self._password,
)
```
`recv` callable is `lambda n: conn.read_eager() or conn.read_some()` —
**non-blocking `read_eager()` first (returns immediately with whatever is
already buffered, possibly `b""`), falling back to blocking `read_some()`**
only when `read_eager()` returned nothing. The `n` parameter (4096, from
`ShellDriver._read_until`) is **ignored entirely** — telnetlib's
`read_eager`/`read_some` take no length argument. Go port parity: the Go
telnet transport's `recv` closure must replicate this two-tier
eager-then-blocking read pattern, not a fixed-size blocking read.

**`run`/`run_scp_copy`/`run_write_memory`/`close`** (`telnet.py:81-104`):
same lazy-connect delegation pattern as SSH. `close()` (`telnet.py:99-104`)
suppresses exceptions on `conn.close()`, no separate channel/transport
split (telnet has one connection object).

### 2.3 Console (serial) — `src/netgear_switch/transport/cli/console.py` (103 lines)

**Library: `pyserial`** (`import serial`), imported LAZILY, part of the
same `[ssh]` extra as paramiko (`console.py:8,56-61`: "pyserial is imported
lazily so `import netgear_switch` never depends on it"; missing-dep error:
`CliTransportError("console CLI transport requires pyserial (install the '[ssh]' extra)")`).

**Framing/baud** (`console.py:21-23`):
```python
_DEFAULT_BAUD = 115200
_DEFAULT_TIMEOUT = 20.0
```
Comment: "NETGEAR console ports default to 115200 8N1." (`console.py:21`) —
**8 data bits, no parity, 1 stop bit is the IMPLICIT default from
`serial.Serial(...)` not passing `bytesize`/`parity`/`stopbits`
explicitly** (`console.py:63-65`):
```python
ser = serial.Serial(
    self._device, baudrate=self._baudrate, timeout=self._timeout
)
```
Only `baudrate` and `timeout` are passed — pyserial's OWN library defaults
supply `bytesize=EIGHTBITS`, `parity=PARITY_NONE`, `stopbits=STOPBITS_ONE`,
`xonxoff=False`, `rtscts=False`, `dsrdtr=False` (no flow control at all).
Go port: `go.bug.st/serial` (or `github.com/tarm/serial`) defaults must be
set explicitly to 8-N-1, no flow control, 115200 baud, to match.

**Login sequence** (`_login`, `console.py:48-53`):
```python
# Prod the console (it may already be at a prompt) then answer the
# User:/Password: login the shared driver's setup() does not cover.
ser.write(b"\r\n")
ser.write(self._username.encode("latin-1") + b"\r\n")
ser.write(self._password.encode("latin-1") + b"\r\n")
```
**Notably different from SSH/Telnet: this is a BLIND write sequence with NO
reads at all** — no `read_until(b"User:")` wait, unlike telnet's `_login`.
It sends a bare `\r\n` first "to prod the console (it may already be at a
prompt)", then unconditionally writes username\r\n and password\r\n in
immediate succession, trusting the device's own line-buffering to have the
`User:`/`Password:` prompts appear and be answered by the time these bytes
arrive. **This is the least robust of the three login sequences** — a
console at an unexpected state (e.g. already logged in, or mid-banner) could
desync. `ShellDriver.setup()`'s first `_read_until` is what actually
resyncs by hunting for `_PROMPT_RE` in whatever comes back.

**Connect sequence** (`connect()`, `console.py:55-78`): opens serial, calls
`_login`, wraps in the same `try/except → self.close(); raise
CliTransportError(f"console open/login failed: {exc}")` pattern
(`console.py:67-69`).

**`ShellDriver` construction** (`console.py:71-77`): `send=ser.write`,
`recv=ser.read` directly (pyserial's `.read(n)` blocks up to `timeout`
seconds waiting for `n` bytes, or returns fewer — matches the
`Callable[[int], bytes]` recv contract exactly, unlike telnet's lambda
wrapper). Same `enable_cmd`/`paging_off_cmd`/`enable_password=self._password`
wiring as the other two transports.

**`close()`** (`console.py:98-103`): suppresses exceptions on `ser.close()`.

### 2.4 `__init__.py` (`transport/cli/__init__.py`, 1 line)

```python
"""CLI transports (SSH/telnet/console) implementing the CliSession seam."""
```
No re-exports, no code — pure docstring module.

---

## 3. The FAKE CLI face — `src/netgear_switch/virtual/faces/cli.py` (421 lines)

As established in §0, this is an **in-process** `CliSession` implementation
with no socket, no host key, no listener of any kind. It is documented here
in full because it is the actual command-dispatch ground truth a Go fake
(whether in-process or a real listener) must reproduce.

### 3.1 Two behavioral contracts stated up front (`cli.py:24-36`)

> "Two behaviours are modelled on purpose because the library's correctness
> depends on them:
> * An accepted configuration command returns EMPTY output; anything the
>   switch would reject returns text. (The empty/non-empty CONTRACT is
>   live-proven on an M4300-24X; the exact wording of the rejection strings
>   below is NOT a transcription of any capture, and nothing in the library
>   parses them.)
> * `vlan participation` / `vlan tagging` / `vlan pvid` are accepted but
>   completely INERT while the port is in `switchport mode access` — the
>   live finding... that makes `switchport mode general` a mandatory step
>   of every per-port CLI VLAN write."

**IMPORTANT for parity grading:** the rejection-string WORDING (`_INVALID`,
`_no_such_vlan`, etc., §3.5) is explicitly NOT ground truth from a capture —
only the empty-vs-non-empty CONTRACT matters. A Go port that reproduces
different wording but preserves the empty/non-empty contract is faithful; a
Go port that gets the wording byte-identical is not required to, but string
identity is trivially easy to also match here since these are Python
literals to copy verbatim (§3.5).

### 3.2 Command regexes (`cli.py:51-79`) — quoted in full

```python
_SHOW_VLAN_ID_RE = re.compile(r"^show vlan (\d+)$")
_SHOW_IFACE_RE = re.compile(r"^show interface ethernet (\S+)$")
_SETUP_RE = re.compile(r"^(enable|terminal length \d+|disable)$")
_COPY_RE = re.compile(r"^copy\s+(\S+)\s+(\S+)$")

_CONFIGURE_RE = re.compile(r"^config(?:ure)?(?: terminal)?$")
_VLAN_DATABASE_RE = re.compile(r"^vlan database$")
_VLAN_CREATE_RE = re.compile(r"^vlan (\d+)$")
_VLAN_NAME_RE = re.compile(r"^vlan name (\d+) (\S+)$")
_VLAN_DELETE_RE = re.compile(r"^no vlan (\d+)$")
_INTERFACE_RE = re.compile(r"^interface (\S+)$")
_SWITCHPORT_MODE_RE = re.compile(r"^switchport mode (access|general|trunk)$")
_PARTICIPATION_RE = re.compile(r"^vlan participation (include|exclude) (\d+)$")
_TAGGING_RE = re.compile(r"^(no )?vlan tagging (\d+)$")
_PVID_RE = re.compile(r"^vlan pvid (\d+)$")
_POE_RE = re.compile(r"^(no )?poe$")
_POE_RESET_RE = re.compile(r"^poe reset$")
_SHUTDOWN_RE = re.compile(r"^(no )?shutdown$")
_IP = r"(\d+\.\d+\.\d+\.\d+)"
_NETWORK_PARMS_RE = re.compile(rf"^network parms {_IP} {_IP}(?: {_IP})?$")
_IP_MGMT_ADDR_RE = re.compile(rf"^ip management address {_IP} {_IP}$")
_IP_GATEWAY_RE = re.compile(rf"^ip default-gateway {_IP}$")
```
`_SHOW_IFACE_RE` comment (`cli.py:52-55`): "Accept ANY interface-name shape
the model prints (`1/0/7`, `1/g7`, `1/xg49`) and resolve it through the
renderer's own naming (`cli_fastpath.port_for_iface`), instead of the old
hardcoded `r"\d+/0/(\d+)"` which could never match the Smart-firmware
S3300-52X's real names."

### 3.3 Mode stack (`cli.py:82,96-108,155-157`)

```python
_VLAN_DB, _CONFIG, _INTERFACE = "vlan-db", "config", "interface"
```
`VirtualCliFace.__init__` (`cli.py:99-108`):
```python
self._modes: list[str] = []       # [] = EXEC; ["vlan-db"]; ["config","interface"]
self._iface_port: int | None = None
```
Comment: "The command-mode stack, innermost last: `[]` is EXEC mode,
`["vlan-db"]` is the VLAN database, `["config", "interface"]` is interface
config mode. `exit` pops one level and `end` returns to EXEC, like a real
shell." `_mode` property (`cli.py:155-157`) returns `self._modes[-1] if
self._modes else "exec"`.

### 3.4 Mode-transition commands (`_config_command`, `cli.py:303-367`)

- `"exit"` (`cli.py:306-311`): pops one mode level if non-empty; if the new
  top mode isn't `_INTERFACE`, clears `self._iface_port`. Always returns
  `_ACCEPTED` (`""`), even at EXEC (a no-op pop of nothing).
- `"end"` (`cli.py:312-315`): clears the entire mode stack AND
  `_iface_port` in one shot. Always `_ACCEPTED`.
- `"vlan database"` (`cli.py:316-321`): reachable "from EXEC and from
  global config mode on real FASTPATH" — pushes `_VLAN_DB` if
  `self._mode in ("exec", _CONFIG)`, else returns `_INVALID`.
- `config`/`configure`/`configure terminal` (regex `_CONFIGURE_RE`,
  `cli.py:322-326`): pushes `_CONFIG` only from `"exec"`, else `_INVALID`.
- `network parms <ip> <mask> [<gw>]` (`cli.py:327-338`): **privileged EXEC
  only** AND only on models where `_uses_ip_management_dialect()` is False
  (`cli.py:331`) — "the M4300 12.0.x rejects `network parms` in every mode".
  On success sets `self.state.mgmt.address/netmask/gateway` and
  `self.state.mgmt.mode = "static"`.
- Dispatch by current mode (`cli.py:339-367`): if `_VLAN_DB` →
  `_vlan_db_command`; if `_CONFIG` → tries `interface <iface>` (pushes
  `_INTERFACE`, resolves the port via `cli_fastpath.port_for_iface`,
  `_INVALID` if unresolvable), then `ip management address`/`ip
  default-gateway` (gated the OPPOSITE way — `_INVALID` unless
  `_uses_ip_management_dialect()` is True); if `_INTERFACE` with a resolved
  `_iface_port` → `_interface_command`. Any command not matched by the
  current mode's handler returns `None` (meaning: "not a config command,
  fall through to the `show` dispatch" — see `cli.py:304-305`, `run`
  handles this fallthrough at `cli.py:387-390`).

### 3.5 Literal output strings — the FULL enumerated set

These are the **only** static strings this face ever emits (besides the
`cli_fastpath` render functions, which are OUT OF SCOPE per the task brief
but referenced by name below since `VirtualCliFace.run` calls them
directly):

| Constant / call site | Literal text | Emitted when |
|---|---|---|
| `_INVALID` (`cli.py:88`) | `"% Invalid input detected at '^' marker."` | any rejected config-mode command (switchport-mode unsupported, PoE unsupported, unknown interface, wrong mode for `network parms`/`ip management`, etc.) |
| `_ACCEPTED` (`cli.py:89`) | `""` (empty string) | every accepted config command |
| `_no_such_vlan(vlan)` (`cli.py:92-93`) | `f"ERROR: VLAN {vlan} does not exist"` | `vlan name`, `no vlan`, `vlan participation`, `vlan tagging`, `vlan pvid` against a nonexistent VLAN id |
| VLAN-1-delete guard (`cli.py:186-187`) | `"ERROR: The default VLAN cannot be deleted"` | `no vlan 1` |
| `run_scp_copy` bad syntax (`cli.py:126-127`) | `"% Invalid input: expected 'copy <src> <dest>'"` | `copy` command that doesn't match `_COPY_RE` |
| `run_scp_copy` success (`cli.py:132`) | `f"Data transfer complete. bytes transferred to {dest}"` | any syntactically-valid `copy <src> <dest>` |
| `run` fallback / unknown command (`cli.py:418`) | `"Command not found / Incomplete command. Use ? to list commands."` | any command matching no `show`, no config command, no setup command |
| Setup no-op (`_SETUP_RE`, `cli.py:373-374`) | `""` | `enable` / `terminal length N` / `disable` |

`run_write_memory` (`cli.py:134-151`) returns `""` in both branches
(`reload` and `write memory`), never emits text — it only mutates
`state.reboots` (reload) or `deploy.saved = True` + appends to
`deploy.commands` (write memory).

Two special EXEC-level toggle commands handled directly in `run()`
(`cli.py:375-382`, not via `_config_command`):
```python
if c == "no ip http secure-server":
    self._deploy().https_disabled = True; self._deploy().commands.append(c); return ""
if c == "ip http secure-server":
    self._deploy().https_enabled = True; self._deploy().commands.append(c); return ""
```

**No prompt string, no banner, no MOTD is ever concatenated onto any of
these** — confirmed by re-reading every return statement in `cli.py`; the
face returns bare content text, and `ShellDriver`'s prompt-stripping logic
(§1.3) is simply never exercised against this face because nothing calls
`ShellDriver` here — `SyncSwitch`/`CliReader`/`CliWriter` call
`VirtualCliFace.run()` directly as their injected `CliSession`.

### 3.6 Model-gating helper predicates (`cli.py:200-229`)

- `_has_switchport_modes()` (`cli.py:200-211`): `return
  self.state.model_key != "gsm7252ps"`. Comment: "Probed live 2026-07-30:
  the gsm7252ps (XE image) answers `% Unrecognized command` to `switchport
  mode ?`... Keyed on the MODEL rather than read out of `CliModelSpec` on
  purpose: the mock has to be an independent statement of what the device
  does, so that a wrong spec is caught here instead of being mirrored."
  (Note: the mock's `_INVALID` text differs from the live device's actual
  `% Unrecognized command` wording — consistent with §3's "wording is not
  ground truth" disclaimer.)
- `_uses_ip_management_dialect()` (`cli.py:213-218`): `return
  self.state.model_key.startswith("m4300")`.
- `_poe_capable()` (`cli.py:220-228`): `return
  get_model(self.state.model_key).poe_port_count > 0`. Comment: "The
  M4300-24X has none, and its firmware consequently has no `poe` command
  whatsoever."
- `_general(port)` (`cli.py:159-164`): `sim.switchport_mode in ("general",
  "trunk")` — the gate for whether `vlan participation`/`vlan tagging`/`vlan
  pvid` actually mutate state vs. being accepted-but-inert.

### 3.7 `_interface_command` (`cli.py:230-301`) — per-port config dispatch

Handles, in order: `switchport mode {access|general|trunk}` (gated by
`_has_switchport_modes()`); `poe reset` (gated by `_poe_capable()`, calls
`state.apply_poe_reset(port)`); `poe`/`no poe` (gated by `_poe_capable()`,
calls `state.apply_poe_admin(port, on=...)`); `shutdown`/`no shutdown`
(`sim.admin = enabled`; **coherence rule**: `if not enabled: sim.link =
False` — "A shut port cannot stay linked", `cli.py:257-259`); `vlan
participation {include|exclude} {vid}` (mutates `vsim.member`/
`vsim.untagged` ONLY if `_general(port)`, else accepted-but-inert; a newly
included port is also added to `untagged` — "A newly included port is
UNTAGGED until `vlan tagging` says otherwise", `cli.py:272-274`); `[no]
vlan tagging {vid}` (toggles `vsim.untagged` membership, same
general-mode gate); `vlan pvid {vid}` (sets `state.pvids[port]`, same
gate).

### 3.8 `_vlan_db_command` (`cli.py:166-198`) — VLAN database mode

`vlan {vid}` create (idempotent — selecting an existing VLAN is accepted,
"matching a real switch: `vlan 5` on an existing VLAN 5 is not an error",
`cli.py:172-173`); `vlan name {vid} {name}`; `no vlan {vid}` delete — with
the VLAN-1-protection and PVID-reassignment coherence rule: "no port can be
left with its PVID pointing at a VLAN that no longer exists, so those ports
fall back to VLAN 1" (`cli.py:192-193`, iterates `state.pvids.items()`
resetting any port whose `pvid == vid` to `1`).

### 3.9 SCP cert-deploy stand-in (`cli.py:109-133`)

`run_scp_copy` here is explicitly NOT a byte-level prompt drive (that's
`ShellDriver.run_scp_copy`, §1.3) — it directly parses `copy <src> <dest>`
via `_COPY_RE`, records into `ScpCertDeploy.commands`/`.copies`
(`virtual/state.py:318-334`, out of strict scope but referenced:
`commands: list[str]`, `copies: list[tuple[str,str]]`, `https_disabled:
bool`, `https_enabled: bool`, `saved: bool`), and always returns the
success string. Docstring: "The real `ShellDriver.run_scp_copy` drives a
byte-level prompt handshake (TOFU/password/(y/n))... This in-process face
has no byte stream, so it records the copy... and reports success"
(`cli.py:116-124`).

### 3.10 `close()` (`cli.py:420-421`)

```python
def close(self) -> None:
    pass
```
Literally a no-op — confirms §0's point that there is nothing to
drain/leak-check here in the Python implementation. **This is the single
biggest divergence from the other virtual faces' Stop discipline** (see §5).

---

## 4. Facade / registration wiring (CLI-backend-relevant slices only)

### 4.1 `registry.py` — `Backend` enum and per-model CLI backend declarations

```python
# registry.py:19-29
class Backend(enum.Enum):
    SNMP = "snmp"
    NSDP = "nsdp"
    HTTP = "http"
    # FASTPATH command-line interface, reachable over three transports. SSH and
    # TELNET are network backends registered on the FASTPATH models below;
    # CONSOLE is the same CLI over a physical serial line (a transport option,
    # not a network-reachable backend, so it is not registered on any model).
    SSH = "ssh"
    TELNET = "telnet"
    CONSOLE = "console"
```
`CONSOLE` is **never set in any model's `backends` frozenset** — it's a
transport CHOICE a caller makes explicitly (needs a serial device path),
not something `_BACKEND_PREFERENCE`-driven auto-dispatch ever selects.

Per-model CLI backend declarations:
- `gsm7252ps` (`registry.py:187-193`): `{Backend.SNMP, Backend.HTTP,
  Backend.SSH, Backend.TELNET}` — has BOTH SSH and TELNET.
- `gsm7228ps` (`registry.py:194-220`): `{Backend.SNMP, Backend.HTTP,
  Backend.TELNET}` — **TELNET ONLY, no SSH**. Comment quoted in full:
  > "TELNET (not SSH): the S3300-52X's FASTPATH CLI is reachable over
  > telnet on the NON-STANDARD port 60000 (not 23) — live-verified
  > 2026-07-30 on 10.1.5.11 (login admin+password, prompt
  > `(manage-sw-netgear-s3300-1) >`), with a full read sweep captured into
  > `tests/fixtures/cli/gsm7228ps_*.txt`. SSH is genuinely ABSENT: the
  > switch runs no ssh listener on any port (its SNMP tcpConnTable shows
  > only 80/443/60000). So the CLI backend is TELNET only; the telnet
  > transport dials `CliModelSpec.telnet_port=60000`." (`registry.py:199-206`)
  — **this is the one place in the whole pin where an actual live device
  prompt string is captured**: `(manage-sw-netgear-s3300-1) >` — confirms
  `_PROMPT_RE`'s shape empirically.
- m4300-24x, m4300-16x (per `protocols/cli/commands.py`, §4.4 below) also
  carry SSH via their own registry entries (not re-quoted here, out of the
  grep window but referenced consistently across `_dispatch.py`/`sync_api.py`
  comments as "the four FASTPATH CLI models").

### 4.2 `_dispatch.py` — CLI capability gates and client builder

`require_cli_backend(model)` (`_dispatch.py:194-199`):
```python
def require_cli_backend(model: SwitchModel) -> None:
    """Raise unless the model exposes a CLI (SSH/telnet/console) backend."""
    from .protocols.cli.commands import CLI_BACKENDS
    if not (CLI_BACKENDS & model.backends):
        raise UnsupportedCapabilityError(f"model {model.key!r} has no CLI backend")
```

`cli_reads_supported(model)` (`_dispatch.py:202-217`): gates on BOTH
"model has any CLI_BACKENDS member" AND `CLI_SPECS[model.key].reads_verified`.
Docstring: "The FASTPATH models (m4300-24x/-16x, gsm7252ps) are now
verified and return True; other models return False and the facade never
dispatches a live read to their CLI backend." (per §5 of the parse of
`commands.py`, gsm7228ps is ALSO verified — this docstring predates that
addition but the code (`CLI_SPECS.get(model.key)` + `.reads_verified`) is
correct for all four current entries.)

`cli_writes_supported(model)` (`_dispatch.py:220-234`): requires
`cli_reads_supported(model)` first (`_dispatch.py:231-232`), THEN checks
`.writes_verified`. Docstring: "every CLI write verifies itself by reading
back through `CliReader`, so a model whose CLI reads are not trusted cannot
honestly verify a CLI write either."

`build_sync_cli_client(host, username, password, model)`
(`_dispatch.py:237-265`) — **the CLI transport SELECTION logic**:
```python
if not password:
    raise CredentialError(f"no CLI password configured for {host!r}")
spec = cli_spec(model)
if Backend.TELNET in model.backends and Backend.SSH not in model.backends:
    from .transport.cli.telnet import TelnetCliTransport
    return TelnetCliTransport(host, username, password, spec, port=spec.telnet_port)
from .transport.cli.ssh import SshCliTransport
return SshCliTransport(host, username, password, spec)
```
Docstring: "SSH (paramiko) is the default network CLI transport. A model
that exposes TELNET but NOT SSH (the S3300-52X / gsm7228ps... instead gets
the telnet transport dialled at `cli_spec(model).telnet_port`. Both
transports are imported lazily. **The console transport is never
auto-selected here** (it needs a serial device path, not a host)."
(`_dispatch.py:245-250`) — **SSH is the fallback default for every model
that isn't TELNET-only**; console must be constructed by hand by a caller.
**Password check happens BEFORE `cli_spec(model)` lookup** — a missing
password raises `CredentialError`, never masked by a spec-lookup error.

### 4.3 `sync_api.py` — backend-preference order, lazy CLI session, cert-deploy wiring

`_BACKEND_PREFERENCE` tuple (`sync_api.py:52-59`):
```python
_BACKEND_PREFERENCE = (
    Backend.SNMP,
    Backend.NSDP,
    Backend.HTTP,
    Backend.SSH,
    Backend.TELNET,
    Backend.CONSOLE,
)
```
Comment: "All three CLI backends are listed last so a CLI-only model still
resolves; every currently registered CLI model also has SNMP, which
therefore wins by default for them." (`sync_api.py:51-53`) — **in this pin
NO model is ever actually CLI-selected by DEFAULT auto-dispatch**, because
every CLI-capable model also has SNMP (which is tried first and always
wins). CLI is only reached when the caller EXPLICITLY passes
`backend=Backend.SSH`/`Backend.TELNET`/`Backend.CONSOLE`, or for the
CLI-specific ops that have no SNMP equivalent
(`upload_certificate_scp`).

`_LazyCliSession` (`sync_api.py:111-142`) — full class quoted:
```python
class _LazyCliSession:
    """Wraps CLI-transport construction so building the real SSH session
    (which needs a resolved password and raises CredentialError if none is
    set) is deferred until an op actually RUNS a command. Ops a CliReader
    refuses WITHOUT touching the session -- e.g. get_poe on a non-PoE model,
    which raises UnsupportedCapabilityError before any run() -- must never
    trigger CLI password resolution or a live connection. Without this, the
    facade's SSH fall-through for such an op raised CredentialError instead
    of the honest UnsupportedCapabilityError (and diverged from AsyncSwitch,
    which never builds a CLI client)."""
    def __init__(self, resolve: Callable[[], CliSession]) -> None:
        self._resolve = resolve
        self._session: CliSession | None = None
    def _live(self) -> CliSession:
        if self._session is None:
            self._session = self._resolve()
        return self._session
    def run(self, command: str) -> str: return self._live().run(command)
    def run_scp_copy(self, command, scp_password) -> str: return self._live().run_scp_copy(command, scp_password)
    def run_write_memory(self, command="write memory", *, prestuff) -> str: return self._live().run_write_memory(command, prestuff=prestuff)
    def close(self) -> None:
        if self._session is not None:
            self._session.close()
```
This is a lazy-connect wrapper — construction of the underlying
`CliSession` (which resolves credentials and would open a socket) is
deferred to first `.run()`/`.run_scp_copy()`/`.run_write_memory()` call.

`_cli_session()` on `SyncSwitch` (`sync_api.py:818-826`): "Return a ready
CLI session: the injected one, else a freshly-built SSH transport (username
`admin`, reusing the web-admin password as the CLI password by default —
exactly like `_reader_for(CLI)`)." Hardcodes username `"admin"`
(`sync_api.py:825`).

`_reader_for(Backend.SSH/TELNET/CONSOLE)` branch (`sync_api.py:368-387`,
the `else:  # a CLI backend` branch): builds `CliReader(_LazyCliSession(self._cli_session), self.model)`
ONLY if `cli_reads_supported(self.model)`, else raises
`UnsupportedCapabilityError(f"model {self.model.key!r} CLI reads are UNVERIFIED-pending cross-verify")`.
Cached in `self._reader_cache[backend]` (`sync_api.py:388`) — **keyed by
the SPECIFIC backend enum value** (`Backend.SSH` vs `Backend.TELNET` vs
`Backend.CONSOLE` are three DIFFERENT cache keys even though they'd resolve
to the same `CliModelSpec`), so calling with `backend=Backend.SSH` then
`backend=Backend.TELNET` on the same `SyncSwitch` builds TWO separate
`CliReader`/`_LazyCliSession` pairs.

**LIFECYCLE GAP — flagged for the Go port:** `SyncSwitch.close()`
(`sync_api.py:271-276`) reads:
```python
def close(self) -> None:
    """Release the HTTP client THIS facade built (never one injected by
    the caller). Safe to call even when no HTTP op was ever dispatched."""
    if self._built_http_client is not None:
        self._built_http_client.close()
        self._built_http_client = None
```
**It only ever closes `self._built_http_client`.** Nothing in `close()`
iterates `self._reader_cache`/`self._writer_cache` to close any cached
`_LazyCliSession` (or, for that matter, any cached SNMP/NSDP client — those
backends never hold a persistent connection). **This means: if a caller
dispatches a CLI read/write op (which lazily opens a real SSH/telnet
socket via `_LazyCliSession._live()`), that socket is NEVER closed by
`SyncSwitch.close()`/`__exit__`** — it leaks until GC finalizes the
paramiko `Transport`/telnetlib `Telnet` object (which has no `__del__`
guarantee of prompt closure) or the process exits. This is a genuine
Python-side gap, not a deliberate design choice documented anywhere in this
pin. **Recommendation for the Go port: do NOT reproduce this leak.** The Go
`Switch.Close()`/`Stop()` equivalent should close any lazily-opened CLI
session it built, matching the leak-free discipline already established for
the SNMP/HTTP virtual faces (§5) — this is a place where faithful-port and
leak-free-by-design should diverge from the Python source, and the plan
author should flag it as an intentional improvement, not silently drop the
behavior without noting it deviates from the pin.

`upload_certificate_scp` (`sync_api.py:828-885`): builds a session via
`self._cli_session()` (**NOT** through `_reader_for`/`_writer_for`'s cache —
a fresh, uncached call each time), and explicitly closes it in a `finally`
block ONLY if `self._cli_client is None` (i.e., only a self-built session,
never a caller-injected one) — `sync_api.py:881-884`:
```python
finally:
    if self._cli_client is None:
        session.close()
```
This IS leak-free — it's specifically the `_reader_for`/`_writer_for`
CLI-backend path (§ above) that has the gap, not this cert-deploy path.

### 4.4 `aio_api.py` — CLI has NO async backend at all

`AsyncSwitch._reader_for` CLI branch (`aio_api.py:281-289`) unconditionally
raises:
```python
raise UnsupportedCapabilityError(
    f"model {self.model.key!r} CLI reads are not available via the "
    "async facade (CLI is synchronous + UNVERIFIED-pending cross-verify)"
)
```
Same for writes (`aio_api.py:336-347`) and
`upload_certificate_scp` (`aio_api.py:672-680`):
```python
raise UnsupportedCapabilityError(
    f"model {self.model.key!r}: upload_certificate_scp is CLI/SCP-based "
    "and the async facade has no CLI backend (CLI is synchronous) -- "
    ...
)
```
Rationale stated consistently across all three sites: "the CLI transports
are SYNCHRONOUS (`telnetlib`/`paramiko` blocking sockets, `pyserial`
blocking I/O), with no async twin." **Go port implication:** unlike Python
(where sync-only is a real architectural constraint from stdlib telnetlib +
paramiko), Go's `x/crypto/ssh` and net package are not inherently
sync/async-split — the Go port does not need to reproduce this limitation
unless the plan intentionally mirrors the Python API's sync/async split for
other reasons (e.g. matching a `SyncSwitch`/`AsyncSwitch` Go pairing). Flag
as a design decision point, not a hard technical constraint to port.

### 4.5 `virtual/server.py` — `VirtualSwitch.cli_session()` and the Stop-discipline contrast

Already quoted in §0. Full method (`server.py:130-140`):
```python
def cli_session(self) -> VirtualCliFace:
    """Return an in-process mock FASTPATH CLI session over this switch's state.
    Unlike the SNMP/NSDP/HTTP faces (real sockets bound in start()), the
    CLI face is an in-process CliSession needing no socket -- see
    virtual.faces.cli. Raises UnsupportedCapabilityError (via cli_spec)
    for a model with no CLI backend."""
    from ..protocols.cli.commands import cli_spec
    return VirtualCliFace(self.state, cli_spec(self._model_info))
```
**Critically: `VirtualCliFace` instances are NOT tracked by
`VirtualSwitch`** — `cli_session()` returns a brand-new `VirtualCliFace`
every call, is not stored in any `self._cli_face` field, and
`VirtualSwitch.stop()` (`server.py:142-154`) never references it at all
(only iterates `self._snmp_face`/`self._nsdp_face`/`self._http_face`).
This is CONSISTENT with §3.10's `close()` being a no-op — there's genuinely
nothing to leak (no socket, no thread, no OS resource), so `VirtualSwitch`
correctly has nothing to track here. **This is fine for an in-process fake
but becomes a real gap if the Go port adds a real-listener fake** — a
Go `VirtualSwitch` (or its CLI-fake equivalent) that binds a real SSH/Telnet
listener MUST be tracked and drained by `Stop()`, unlike this Python
in-process face.

### 4.6 `virtual/faces/__init__.py`

One-line docstring module, no code: `"""Protocol faces onto a
VirtualSwitchState (e.g. an SNMP agent, Task 15)."""` (`faces/__init__.py:1`).

---

## 5. Concurrency / lifecycle — contrast with the other virtual faces' Stop discipline

The task brief asks whether the CLI face has the same deterministic
leak-free `Stop()` discipline as SNMP/HTTP/NSDP. **It does not need to, and
does not have one, because it binds no resource** (§3.10, §4.5). For
contrast (to inform what a Go REAL-listener fake would need to replicate if
that design is chosen), the SNMP face's discipline, read directly from
`virtual/faces/snmp.py`, is:

- `VirtualSnmpFace.start()` (`snmp.py:354-370` area): binds a UDP socket,
  starts a dedicated background `threading.Thread` running the pysnmp
  asyncio dispatcher, uses a `threading.Event` (`self._ready`) to signal
  "socket bound and dispatcher running" back to the caller before `start()`
  returns.
- `VirtualSnmpFace.stop()` (`snmp.py:372-399`): "Close the dispatcher, join
  the background thread, and close the socket" — calls
  `self._loop.call_soon_threadsafe(self._engine.close_dispatcher)`, then
  `self._thread.join(timeout=5)` (a bounded join, not infinite), THEN sets
  `self._thread = None`, and closes `self._sock` explicitly AFTER the
  thread has fully stopped ("closing `self._sock` here too, after the
  thread has fully stopped, is a..." — comment continues past the grep
  window but the ordering is unambiguous: socket close happens only after
  the thread-join completes, avoiding a use-after-close race).

**If the Go port's plan chooses to build a REAL SSH+Telnet fake listener**
(a new design decision per §0, not a straight port), the Go equivalent
`Stop()` must apply this SAME pattern: signal shutdown → close/cancel every
accepted connection's goroutine (each connection ideally on its own
goroutine, `net.Listener.Accept()` loop on another) → `WaitGroup.Wait()`
(the Go idiom matching Python's bounded `.join(timeout=5)`) → close the
listening socket(s) last. This mirrors the existing Go SNMP/NSDP/HTTP
virtual faces' Stop discipline referenced in the task brief (not re-verified
here — out of this dossier's Python-source scope — but the Python-side
SNMP pattern above is the shape to match).

---

## 6. Go library recommendations

- **SSH client (real transport, `transport/cli/ssh.go` equivalent):**
  `golang.org/x/crypto/ssh`. `ssh.ClientConfig{User: username, Auth:
  []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback:
  ssh.InsecureIgnoreHostKey()}` — the `InsecureIgnoreHostKey()` choice is
  NOT a security shortcut taken casually; it is the literal parity target,
  since `paramiko.Transport` + `start_client()` (no `SSHClient`, no host-key
  policy at all) never checks a host key either (§2.1). Legacy KEX/host-key
  parity: `x/crypto/ssh`'s default `ClientConfig` also excludes
  `diffie-hellman-group14-sha1` and `ssh-rsa` (SHA-1) from its modern
  defaults in recent releases — the Go equivalent of `ssh.py`'s
  `_prefer_legacy_algorithms` is populating `ClientConfig.KeyExchanges` to
  include `"diffie-hellman-group14-sha1"` and `ClientConfig.HostKeyAlgorithms`
  to include `"ssh-rsa"`, placed FIRST (or simply included, since
  `x/crypto/ssh` will use whatever the server also offers, unlike paramiko's
  now-restrictive preference ordering issue — verify at implementation time
  whether `x/crypto/ssh` still supports these two primitives at all, since
  some Go versions have also begun deprecating SHA-1 host keys; this is a
  **flagged risk**, not resolved by this dossier).
- **SSH server (a real-listener fake, if that design is adopted):**
  `golang.org/x/crypto/ssh`'s `ssh.ServerConfig` — but since the Python fake
  has NO host key, NO auth policy, and NO prompt/banner ground truth to
  copy (§0), the Go fake's `ServerConfig.PasswordCallback` accepting a fixed
  username/password and its ephemeral host key generation are **new design
  choices**, not ports. Recommend generating a fresh ephemeral RSA/ED25519
  host key per fake instance (parity concept: Python's client never checks
  it anyway, so any key works) rather than embedding a fixed key.
- **Telnet:** no telnet client/server in Go stdlib. Options: hand-roll IAC
  handling (small state machine: `IAC DO/DONT/WILL/WONT <opt>` →
  respond `IAC WONT <opt>` / `IAC DONT <opt>` to refuse everything, matching
  `telnetlib`'s default refuse-everything posture — confirm this is
  `telnetlib`'s actual default before committing, since this dossier did
  not read CPython's `telnetlib` source, only observed that `telnet.py`
  installs no custom option handler), or a small existing Go telnet
  library (`github.com/reiver/go-telnet` or similar — evaluate license and
  maintenance before adopting; a ~150-line hand-rolled IAC filter is likely
  lower-risk given the narrow behavior needed: parity with a rarely-
  exercised default). For the CLIENT side, the exact literal byte waits
  (`b"User:"`, `b"Password:"`) and the eager-then-blocking two-tier read
  pattern (§2.2) must be replicated regardless of which IAC approach is
  chosen.
- **Serial:** `go.bug.st/serial` (actively maintained, cross-platform) is
  the more common current recommendation over `github.com/tarm/serial`
  (largely unmaintained); set `BaudRate: 115200, DataBits: 8, Parity:
  serial.NoParity, StopBits: serial.OneStopBit` explicitly (Go has no
  implicit-default equivalent to pyserial's constructor defaults — every
  field must be set).
- **Shared `ShellDriver` equivalent:** a straightforward direct port —
  `_PROMPT_RE`/`_PASSWORD_RE`/the five SCP regexes translate 1:1 to Go
  `regexp` (verify Go's RE2 engine accepts all six patterns unchanged — they
  use no backreferences/lookaround, so RE2 compatibility is expected but
  should be verified: `\)\s*(?:\([^)]*\)\s*)?[#>]\s*$` etc. are all
  RE2-safe). `latin-1` byte handling in Go: do NOT decode to Go `string`
  via UTF-8 assumptions — either keep everything as `[]byte` through the
  regex-matching path (Go's `regexp` operates on `[]byte` natively via
  `Match`/`Find` on byte slices) or use `golang.org/x/text/encoding/charmap.ISO8859_1`
  for an explicit latin-1↔UTF-8 round trip if string operations are wanted.

---

## 7. Parity Checklist

Legend: **[PORT]** = faithful 1:1 port of documented Python behavior.
**[NEW DESIGN]** = no Python ground truth exists; a Go-side design decision,
flagged so the plan author does not mistake it for a port target.
**[FIX]** = a Python-side gap the Go port should deliberately NOT reproduce.

### 7.1 Shared session state machine (`ShellDriver` equivalent)

- [ ] **[PORT]** `_PROMPT_RE = \)\s*(?:\([^)]*\)\s*)?[#>]\s*$` — end-anchored prompt match (`session.py:28`)
- [ ] **[PORT]** `_PASSWORD_RE = [Pp]assword:\s*$` — end-anchored (`session.py:29`)
- [ ] **[PORT]** `_MAX_READS = 10_000` iteration cap, not a wall-clock timeout (`session.py:32`)
- [ ] **[PORT]** SCP TOFU regex `host key|continue connecting|\(yes\s*/\s*no` (case-insensitive), matched anywhere in buffer, not end-anchored (`session.py:39`)
- [ ] **[PORT]** SCP password regex `[Pp]assword:` (no end-anchor, unlike the main `_PASSWORD_RE`) (`session.py:40`)
- [ ] **[PORT]** SCP `(y/n)` confirm regex `\(y\s*/\s*n\)` (`session.py:41`)
- [ ] **[PORT]** SCP success regex `bytes transferred|completed successfully|operation completed` (case-insensitive) (`session.py:42-44`)
- [ ] **[PORT]** SCP failure regex `transfer failed|failed!|%\s*error|error during` (case-insensitive), checked FIRST every loop iteration (`session.py:45-47`, `173-176`)
- [ ] **[PORT]** Newline for all written commands: `\r\n` (`session.py:97,122`)
- [ ] **[PORT]** All bytes encoded/decoded as `latin-1`, `errors="replace"` on decode (`session.py:111,122`)
- [ ] **[PORT]** `recv` reads up to 4096 bytes per call (`session.py:109`)
- [ ] **[PORT]** `setup()` sequence: read initial prompt → send `enable_cmd` → read (allow password) → if password prompt seen, send `enable_password or ""` then read again → send `paging_off_cmd` → read (`session.py:124-134`)
- [ ] **[PORT]** enable password defaults to the SAME password used for login (`ssh.py:116`, `telnet.py:77`, `console.py:76` — all pass `enable_password=self._password`)
- [ ] **[PORT]** `run(command)`: write line, read until prompt, strip echo+prompt (`session.py:136-139`)
- [ ] **[PORT]** `run_scp_copy`: TOFU→`"yes"`, password-prompt→`scp_password`, `(y/n)`→bare `b"y"` (NO newline), success-marker sets a flag but doesn't return early, prompt-match returns transcript, stream-end-with-success-flag-set still returns transcript (not an error), stream-end-without-success raises (`session.py:141-198`)
- [ ] **[PORT]** each SCP prompt handler resets the local match buffer to `""` after acting, but the accumulated `transcript` keeps growing (`session.py:171,179,183,188`)
- [ ] **[PORT]** `run_write_memory(prestuff=True)`: single write of `command + "\r" + "y" + "\r"`, no intermediate read (`session.py:209-210`)
- [ ] **[PORT]** `run_write_memory(prestuff=False)`: normal `\r\n`-terminated write, then watches `(y/n)` and answers bare `b"y"` (no newline) when seen; NO success-flag short-circuit at stream-end (unlike `run_scp_copy`) — always raises on unexpected stream end (`session.py:211-229`)
- [ ] **[PORT]** `_clean`: normalize `\r\n`/`\r`→`\n`, split lines; drop first line if `command.strip()` is a SUBSTRING of it (not exact match); drop trailing lines while they match `_PROMPT_RE` (can strip more than one); final `strip("\n")` (`session.py:231-241`)

### 7.2 SSH transport

- [ ] **[PORT]** default port `22`, default timeout `20.0`s (`ssh.py:44,57-58`)
- [ ] **[PORT]** auth method: password ONLY (`ssh.py:101`)
- [ ] **[PORT]** NO host-key verification of any kind (`ssh.py:90-108` never checks) → Go: `InsecureIgnoreHostKey()`
- [ ] **[PORT]** legacy KEX `diffie-hellman-group14-sha1` and host-key algo `ssh-rsa` must be negotiable — re-inserted at front of preferred lists when the underlying SSH library still supports them (`ssh.py:41-43,70-88`)
- [ ] **[PORT]** PTY requested with library defaults (no explicit term/size args passed) — replicate paramiko's implicit `vt100`/`80x24` unless the Go library's defaults differ, in which case set them explicitly to match (`ssh.py:103`)
- [ ] **[PORT]** shell mode (`invoke_shell`), never exec mode (`ssh.py:104`)
- [ ] **[PORT]** per-recv timeout set on the channel after shell invocation (`ssh.py:105`)
- [ ] **[PORT]** any connect/auth/pty/shell-setup exception → one normalized error type (`CliTransportError` equivalent) wrapping the original (`ssh.py:106-108`)
- [ ] **[PORT]** `close()`: close channel then transport, suppress ALL exceptions during teardown (`ssh.py:138-147`)
- [ ] **[PORT]** paramiko is an OPTIONAL/lazy dependency in Python; Go equivalent: no direct analogue needed (Go has no lazy-import concept), but keep SSH support behind a build tag or separate package ONLY if the Go project has an equivalent "optional extras" pattern established elsewhere — verify against Go project conventions, not dictated by this dossier.

### 7.3 Telnet transport

- [ ] **[PORT]** default port `23` (`telnet.py:38`), default timeout `20.0`s (`telnet.py:25`)
- [ ] **[PORT]** login: wait for literal bytes `User:` → write `username + "\r\n"` → wait for literal bytes `Password:` → write `password + "\r\n"` — NO read after the password write (`telnet.py:50-55`)
- [ ] **[PORT]** IAC negotiation must be transparent to the shared driver — client refuses/ignores option negotiation by default (matching telnetlib's default handler), never surfacing raw IAC bytes to `ShellDriver`-equivalent (`telnet.py:8-12`, no custom option handler present)
- [ ] **[PORT]** recv is two-tier: non-blocking "whatever's buffered" first, falling back to a blocking read only if nothing was buffered; the `n`-byte-count parameter from the shared driver is ignored (`telnet.py:74`)
- [ ] **[PORT]** `gsm7228ps` model: telnet port **60000**, not 23 (`registry.py:199-206`, `commands.py:77-81,338`) — SSH is genuinely absent for this model
- [ ] **[PORT]** any connect/login exception → normalized `CliTransportError` equivalent (`telnet.py:68-70`)
- [ ] **[PORT]** `close()` suppresses all exceptions (`telnet.py:99-104`)

### 7.4 Console/serial transport

- [ ] **[PORT]** 115200 baud, 8 data bits / no parity / 1 stop bit / no flow control, default timeout 20.0s (`console.py:21-23,63-65` — the 8N1/no-flow-control comes from the underlying library's implicit defaults, so Go must set them EXPLICITLY since Go libraries don't share pyserial's defaults)
- [ ] **[PORT]** login is a BLIND write sequence with no interleaved reads: `\r\n`, then `username + "\r\n"`, then `password + "\r\n"`, all written unconditionally (`console.py:48-53`) — deliberately less robust than telnet's wait-for-literal-prompt approach; resync happens only via `ShellDriver.setup()`'s first prompt-hunting read
- [ ] **[PORT]** `send`/`recv` map directly to the serial port's `Write`/`Read` (no lambda wrapping needed, unlike telnet) (`console.py:71-77`)
- [ ] **[PORT]** `close()` suppresses all exceptions (`console.py:98-103`)

### 7.5 Fake CLI face — in-process command dispatch (the real byte-accurate ground truth)

- [ ] **[PORT]** mode stack: `[]`=EXEC, `["vlan-db"]`, `["config"]`, `["config","interface"]`; `exit` pops one level (clearing `_iface_port` when leaving interface mode), `end` clears the whole stack (`cli.py:96-108,306-315`)
- [ ] **[PORT]** `_SETUP_RE` (`enable`/`terminal length N`/`disable`) always returns empty string, no state change (`cli.py:57,373-374`)
- [ ] **[PORT]** config command accepted → returns `""`; rejected → returns non-empty text; nothing in the reader/writer layer parses the rejection TEXT itself, only emptiness (`cli.py:24-31,88-89`)
- [ ] **[PORT]** literal string: `"% Invalid input detected at '^' marker."` (`cli.py:88`)
- [ ] **[PORT]** literal string: `f"ERROR: VLAN {vlan} does not exist"` (`cli.py:92-93`)
- [ ] **[PORT]** literal string: `"ERROR: The default VLAN cannot be deleted"` for `no vlan 1` (`cli.py:186-187`)
- [ ] **[PORT]** literal string: `"% Invalid input: expected 'copy <src> <dest>'"` for malformed copy (`cli.py:126-127`)
- [ ] **[PORT]** literal string: `f"Data transfer complete. bytes transferred to {dest}"` for valid copy (`cli.py:132`)
- [ ] **[PORT]** literal string: `"Command not found / Incomplete command. Use ? to list commands."` fallback for unrecognized commands (`cli.py:418`)
- [ ] **[PORT]** `vlan database` reachable from EXEC and global-config only (`cli.py:316-321`)
- [ ] **[PORT]** `configure`/`config`/`configure terminal` reachable from EXEC only (`cli.py:322-326`)
- [ ] **[PORT]** `network parms` (EXEC-only, gated off for `m4300*` models) vs `ip management address`+`ip default-gateway` (config-mode, gated ON only for `m4300*` models) — mutually exclusive dialects (`cli.py:213-218,327-338,350-363`)
- [ ] **[PORT]** `vlan {n}` create is idempotent (selecting an existing VLAN succeeds) (`cli.py:168-175`)
- [ ] **[PORT]** VLAN delete reassigns any port whose PVID pointed at the deleted VLAN back to VLAN 1 (`cli.py:190-197`)
- [ ] **[PORT]** `switchport mode {access|general|trunk}` rejected entirely (as `_INVALID`) for `gsm7252ps` only — every other model accepts it (`cli.py:200-211,232-237`)
- [ ] **[PORT]** `vlan participation`/`vlan tagging`/`vlan pvid` are ACCEPTED (return `""`) but INERT (no state mutation) unless the port's `switchport_mode` is `general` or `trunk` (`cli.py:159-164,261-300`)
- [ ] **[PORT]** including a port in a VLAN also marks it untagged by default (`cli.py:270-274`)
- [ ] **[PORT]** `poe`/`no poe`/`poe reset` rejected as `_INVALID` for any model with `poe_port_count == 0` (`cli.py:220-228,238-248`)
- [ ] **[PORT]** `shutdown` (disabling a port) also forces `link = False`; `no shutdown` only clears the admin-down flag, does not force link up (`cli.py:249-260`)
- [ ] **[PORT]** `no ip http secure-server` / `ip http secure-server` tracked via `ScpCertDeploy.https_disabled`/`.https_enabled` + appended to `.commands`, both return `""` (`cli.py:375-382`)
- [ ] **[PORT]** `run_write_memory`: `"reload"` increments a reboot counter and returns `""`; any other command (i.e. `"write memory"`) appends to `ScpCertDeploy.commands` and sets `.saved = True`, returns `""` — the two must never be conflated (`cli.py:134-151`)
- [ ] **[PORT]** in-process `run_scp_copy` (the mock face's, NOT `ShellDriver`'s) is a pure syntax-parse + record, always "succeeds" if syntactically valid `copy <src> <dest>` (`cli.py:115-132`)
- [ ] **[PORT]** `close()` on the in-process fake is a true no-op (`cli.py:420-421`)
- [ ] **[PORT]** `VirtualSwitch.cli_session()` returns a FRESH, untracked face every call — not cached, not stopped by `VirtualSwitch.stop()` (`server.py:130-140,142-154`)

### 7.6 Facade / registration wiring

- [ ] **[PORT]** `Backend.CONSOLE` is never set on any model's registry entry — it is a caller-chosen transport, never auto-selected (`registry.py:19-29`, `_dispatch.py:249-250`)
- [ ] **[PORT]** `gsm7252ps` has both SSH and TELNET; `gsm7228ps` has TELNET ONLY at port **60000** (no SSH listener at all on real hardware) (`registry.py:187-220`)
- [ ] **[PORT]** live-captured real prompt for gsm7228ps: `(manage-sw-netgear-s3300-1) >` (`registry.py:202-203`) — the one real prompt string ground truth in this entire pin
- [ ] **[PORT]** CLI reads require BOTH "model has a CLI_BACKENDS member" AND `CliModelSpec.reads_verified` (`_dispatch.py:202-217`)
- [ ] **[PORT]** CLI writes require CLI reads to already be supported, AND `CliModelSpec.writes_verified` (`_dispatch.py:220-234`)
- [ ] **[PORT]** transport selection: TELNET-only models get `TelnetCliTransport` dialled at `spec.telnet_port`; every other CLI-capable model gets `SshCliTransport`; console is never auto-selected (`_dispatch.py:237-265`)
- [ ] **[PORT]** missing CLI password raises a credential error BEFORE any spec lookup or connection attempt (`_dispatch.py:254-256`)
- [ ] **[PORT]** backend auto-preference order tries SNMP, NSDP, HTTP before any CLI backend — CLI is only reached via explicit backend selection or CLI-only ops (`sync_api.py:52-59`)
- [ ] **[PORT]** CLI session construction is LAZY — deferred to first actual command dispatch, so capability-gated ops that never run a command never trigger credential resolution or a live connection (`sync_api.py:111-142`)
- [ ] **[PORT]** default CLI username is hardcoded `"admin"`, password defaults to the resolved web-admin password (`sync_api.py:818-826`)
- [ ] **[PORT]** reader/writer caches are keyed per-`Backend` enum value — `SSH`/`TELNET`/`CONSOLE` are three independent cache slots even for the same model/host (`sync_api.py:368-388` and its writer analogue)
- [ ] **[FIX]** Python's `SyncSwitch.close()` never closes a lazily-built CLI session cached in `_reader_cache`/`_writer_cache` — a real socket leak on the Python side (`sync_api.py:271-276`). **The Go port's `Close()`/`Stop()` should close any such cached CLI session** — this is a deliberate deviation from the pin, not an oversight to replicate.
- [ ] **[PORT]** `upload_certificate_scp`'s own session build/close (via `_cli_session()`, NOT the reader/writer cache) IS already leak-free — closes in a `finally` unless the session was caller-injected (`sync_api.py:828-885`)
- [ ] **[NEW DESIGN]** async CLI support: Python has none (telnetlib/paramiko are sync-only); Go's SSH/Telnet stacks are not inherently sync-only, so whether the Go port offers an async CLI path is a fresh decision, not a port constraint (`aio_api.py:281-289,336-347,672-680`)

### 7.7 Fake-listener design decisions (if a real SSH+Telnet fake is built — NOT ports, since no Python ground truth exists)

- [ ] **[NEW DESIGN]** choose and document a fixed prompt format consistent with `_PROMPT_RE`'s shape — e.g. `(<MODEL>) #` / `(<MODEL>) >` / `(<MODEL>) (Config)#`, matching the ONE captured real example `(manage-sw-netgear-s3300-1) >` (`registry.py:202-203`)
- [ ] **[NEW DESIGN]** choose login prompt text for the fake's SSH/Telnet server side — Python's client-side hints are the literal bytes it waits for: telnet expects `User:` then `Password:` (`telnet.py:52,54`); no SSH login-banner text exists anywhere in this pin (paramiko auth is a protocol-level password exchange, not a shell-visible prompt)
- [ ] **[NEW DESIGN]** ephemeral host key generation per fake instance (parity concept: the real Python client never validates it, so any key satisfies parity) rather than a fixed embedded key
- [ ] **[NEW DESIGN]** decide whether the fake's dispatch table is the SAME in-process `VirtualCliFace`-equivalent Go code wrapped in a byte-framing layer (RECOMMENDED — reuses the fully-specified §3/§7.5 dispatch table verbatim) versus a separate reimplementation
- [ ] **[NEW DESIGN]** `Stop()` discipline for a real-listener fake: must accept-loop → per-connection goroutine → signal shutdown → close connections → bounded `WaitGroup.Wait()` → close listener(s) last, mirroring the Python SNMP face's thread-join-then-socket-close ordering (`snmp.py:372-399`), since the in-process Python CLI fake has no discipline to port (`cli.py:420-421`)

---

## Appendix: files read for this dossier (with line counts)

| File | Lines |
|---|---|
| `src/netgear_switch/transport/cli/__init__.py` | 1 |
| `src/netgear_switch/transport/cli/console.py` | 103 |
| `src/netgear_switch/transport/cli/session.py` | 241 |
| `src/netgear_switch/transport/cli/ssh.py` | 147 |
| `src/netgear_switch/transport/cli/telnet.py` | 104 |
| `src/netgear_switch/virtual/faces/cli.py` | 421 |
| `src/netgear_switch/virtual/faces/__init__.py` | 3 |
| `src/netgear_switch/virtual/server.py` | 249 |
| `src/netgear_switch/protocols/cli/commands.py` (supporting context — `CliModelSpec` fields referenced throughout §1–4; not in the task's primary scope list but directly imported by every in-scope transport file) | 440 |
| `src/netgear_switch/_dispatch.py` (CLI-relevant slices: lines 194-265) | — |
| `src/netgear_switch/registry.py` (CLI-relevant slices: `Backend` enum + per-model backend sets) | — |
| `src/netgear_switch/sync_api.py` (CLI-relevant slices: `_LazyCliSession`, `_reader_for`/`_writer_for` CLI branches, `_cli_session`, `upload_certificate_scp`, `close`) | — |
| `src/netgear_switch/aio_api.py` (CLI-relevant slices: the three `UnsupportedCapabilityError` raise sites) | — |
| `src/netgear_switch/virtual/faces/snmp.py` (comparison-only, for §5's Stop-discipline contrast: `start()`/`stop()`) | — |
| `src/netgear_switch/virtual/state.py` (comparison-only: `ScpCertDeploy`/`VlanSim` dataclass fields referenced by `cli.py`) | — |
