# Make knc Use libknc

Goal: make the `knc` executable use `libknc` for authentication, framing,
buffering, EOF propagation, and poll integration, while preserving current
observable executable behaviour.

## 1. Add Compatibility Coverage First

Before changing transport code, extend `test/knc-exec-tests.py` so the current
`knc` behaviour is pinned down.

- [x] Cover client `-N <fd>` mode with an inherited non-stdio network fd.
- [x] Cover explicit client service principal with `-P <principal>`.
- [x] Cover mechanism selection with `-m krb5`.
- [x] Cover no-program stdio mode.
- [x] Cover Unix socket mode EOF cases:
  - [x] client EOF followed by daemon response
  - [x] daemon EOF followed by client EOF
  - [x] `-o no-half-close`
- [x] Add old/new binary matrix support once a libknc-backed test binary exists:
  - legacy client to legacy server
  - legacy client to libknc server
  - libknc client to legacy server
  - libknc client to libknc server

Acceptance criteria:

- `make check` still does not run the optional executable suite.
- `make check-knc-exec` runs the expanded black-box suite.
- New tests fail clearly if EOF propagation, fd wrapping, auth failure, or
  credential propagation changes.

## 2. Add A Temporary libknc-backed Binary

This was the staging step that let the libknc transport path share the existing
command-line, listener, process-launch, and Unix socket setup code before the
installed `knc` binary was switched over.

- [x] Keep installed `knc` on the current implementation during development.
- [x] Add a temporary libknc-backed build target.
- [x] Add test-suite options to select client and server binaries independently.
- [x] Use the temporary binary to run old/new interop combinations.

Acceptance criteria:

- The existing `knc` binary remains unchanged while the libknc path is under
  construction.
- The executable test suite can run with independent client/server binaries.

## 3. Fix libknc Gaps

Patch libknc where it cannot yet model current `knc` behaviour directly.

- [ ] Fix fd `0` handling in `knc_get_pollfds()` by testing fds against `-1`,
  not truthiness.
- [ ] Add a libknc option for current `-o no-half-close` semantics.
- [ ] Decide and implement legacy EOF compatibility:
  - current `knc` treats raw socket EOF as protocol EOF
  - libknc currently has command EOFs and may treat raw EOF as short input
- [ ] Ensure local fd EOF queues the corresponding network EOF after pending
  outbound data has drained.
- [ ] Ensure local write `EPIPE` maps to the matching opposite-side EOF.
- [ ] Add metadata helpers for:
  - display client name (`KNC_CREDS`)
  - exported client name (`KNC_EXPORT_NAME`)
  - mechanism name or hex string (`KNC_MECH`)

Acceptance criteria:

- libknc unit tests cover fd `0`, EOF, EPIPE, and metadata helper behaviour.
- The temporary libknc-backed executable can express all current `knc` relay
  semantics without duplicating protocol logic in `bin/knc.c`.

## 4. Implement libknc-backed do_work()

Replace the executable's transport core with a libknc context.

- [x] Reshape setup code so the libknc context exists earlier:
  - call `knc_ctx_init()` before Unix socket / exec / stdio local-fd setup
  - pass `knc_ctx` into helpers such as `do_unix_socket()`
  - have those helpers give or set their fds directly on the `knc_ctx`
  - keep `work_t` for connection metadata and credential propagation, not as
    the primary owner of transport fds
  - avoid managing the same fd lifetime in both `knc.c` and libknc
- [x] Create a `knc_ctx` per connection.
- [x] Apply executable options:
  - `KNC_OPT_NOPRIVACY`
  - new no-half-close option
  - requested mechanism from `-m`
  - debug level/prefix if useful
- [x] Attach the network fd with `knc_give_net_fd()`.
- [x] Server path: call `knc_accept()`.
- [x] Client path: import service name or explicit `-P` principal, then call
  `knc_initiate()`.
- [x] Authenticate.
- [x] Populate environment variables or Unix socket prelude from libknc
  metadata.
- [x] Attach local fds:
  - exec mode: child stdout as local read fd, child stdin as local write fd
  - no-program stdio mode: stdin/stdout, preserving tested direction
  - Unix socket mode: the connected Unix socket fd
- [x] Run the libknc poll loop until I/O is complete or an error occurs.
- [x] Close and destroy the context.

Acceptance criteria:

- The libknc-backed executable passes the executable suite in client and
  server roles.
- The code no longer hand-rolls GSS wrapping/unwrapping in `bin/knc.c`.

## 5. Run Interop Matrix

Use the temporary binary to prove wire compatibility and behaviour compatibility.

- [ ] Legacy client to legacy server.
- [ ] Legacy client to libknc server.
- [ ] Libknc client to legacy server.
- [ ] Libknc client to libknc server.

Run the matrix over:

- [ ] exec mode
- [ ] no-program stdio mode
- [ ] Unix socket mode
- [ ] half-close cases
- [ ] `-o no-half-close`
- [ ] auth failure
- [ ] explicit service principal
- [ ] requested mechanism

Acceptance criteria:

- Any incompatibility is either fixed in libknc or explicitly documented as a
  deliberate protocol change.

## 6. Flip Installed knc

Once the libknc-backed path passes the executable suite, make the installed
`knc` binary use libknc.

- [x] Replace the current `do_work()` transport path with the libknc-backed
  implementation.
- [x] Remove `bin/gssstdio.c` and `bin/gssstdio.h` from the executable build.
- [ ] Remove now-unused hand-rolled GSS buffer code from `bin/knc.c`.
- [ ] Keep only CLI, listener, process, Unix socket, and credential propagation
  code in the executable.
- [x] Update build files.
- [ ] Update documentation if behaviour or dependencies are user-visible.

Acceptance criteria:

- `make` passes.
- `make check` passes.
- `make check-knc-exec` passes.
- The installed `knc` executable is backed by libknc.

## 7. Remaining gssstdio Gap Analysis

- [ ] Decide whether stalled server-side GSS authentication should preserve the
  old `gstd_accept()` 60s packet read timeout.  The libknc-backed executable
  currently calls `knc_authenticate()`, whose helper loop can wait
  indefinitely unless libknc reports an error.
- [ ] Change `AC_CONFIG_SRCDIR` away from `bin/gssstdio.c` before deleting the
  old source file.
- [ ] Remove the compiled-out legacy GSS transport code from `bin/knc.c` after
  the libknc-backed path has settled.

## Likely Commit Sequence

- [ ] Add missing compatibility tests.
- [ ] Fix libknc fd `0`, EOF, EPIPE, and metadata behaviour.
- [x] Add temporary libknc-backed binary plus binary matrix support.
- [x] Make the libknc-backed executable pass executable tests.
- [x] Flip installed `knc` to libknc.
- [ ] Remove legacy executable GSS transport code.
