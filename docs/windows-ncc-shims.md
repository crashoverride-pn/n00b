# Native Windows ncc Shim Inventory

This is a running ledger for shims added while getting n00b compiling with a
native Windows `ncc.exe`. The goal is to separate temporary n00b-side
workarounds from fixes that should move into `ncc`.

## Likely ncc Work

These exist because `ncc` does not yet parse or model parts of the
Clang-MSVC/Windows preprocessed dialect.

- `include/n00b.h`: normalizes MSVC/UCRT integer limit macros such as
  `INT16_MAX`, `INT32_MIN`, `UINT64_MAX`, `UINT32_MAX`, `SIZE_MAX`, and
  `UINT64_C(...)` away from `i16`/`i32`/`ui32`/`ui64` suffix spellings that
  `ncc` currently rejects. The replacements use standard literal forms so
  headers can still compare them in preprocessor `#if` expressions. Once
  `ncc` accepts MS integer suffixes, remove this block.

- `include/core/platform.h`: local Win32 declarations remain as a fallback for
  n00b translation units that do not opt into the pico/SDK `_WINDOWS` path.
  When `_WINDOWS` is defined, the header now includes the real Windows SDK
  (`winsock2.h`, `ws2tcpip.h`, `windows.h`) instead of redeclaring SDK types
  such as `CONTEXT`, `LARGE_INTEGER`, and `MEMORY_BASIC_INFORMATION`. This
  avoids collisions now that `ncc` can parse the SDK headers used by
  picoquic/picotls.

- `include/conduit/socket_udp.h`, `src/conduit/socket_udp.c`,
  `include/conduit/socket.h`, `include/net/quic/conn.h`,
  `include/net/quic/endpoint.h`, `include/arpa/inet.h`,
  `include/netdb.h`, `include/netinet/in.h`, `include/poll.h`,
  `include/sys/socket.h`, `include/sys/time.h`, and
  `include/internal/win32_sockets.h`: provide socket include compatibility for
  native Windows n00b translation units. `include/internal/win32_sockets.h`
  now defers to the real Windows SDK when `_WINDOWS` is defined, and keeps its
  small local Winsock declaration surface only for fallback TUs that still do
  not use the SDK path. The SDK branch also includes UCRT `<io.h>` so fd/OS
  handle bridges such as `_get_osfhandle` come from the standard headers.
  `include/poll.h` maps POSIX `poll` calls to `WSAPoll`, while
  `include/sys/time.h` provides a local `gettimeofday` shim for n00b sources
  that are not compiled as part of picotls.

- `include/unistd.h`: provides a native Windows compatibility facade for the
  small POSIX fd and sleep surface reached by picoquic/picotls and n00b
  networking translation units. It maps simple fd APIs to UCRT `_read`,
  `_write`, `_close`, etc., implements `usleep` over `Sleep`, and provides
  `mkstemp`/`mkstemps` wrappers over `_open(..., _O_CREAT | _O_EXCL)` for
  QUIC test/example temp-file users.

- `src/conduit/io_wsa.c` and `include/internal/win32_sockets.h`: avoid
  including Clang-MSVC `<stdatomic.h>` and UCRT wide-character headers such as
  `<wchar.h>`/`<wctype.h>` in the Windows WSA backend. Those header paths
  currently reach intrinsic vector tokens such as `__m64`/`__v2si` that `ncc`
  does not parse on Windows, so the backend uses a `volatile LONG` startup flag
  and local declarations for the small CRT wide-character surface it needs.

- `src/conduit/io_wsa.c` and `src/conduit/subproc_windows.c`: hoist pointer
  iteration variables out of `for` initializers in native Windows-only conduit
  code. `ncc` currently rejects GC stack-map roots declared inside unsupported
  statement contexts, even when the declaration is standard C loop syntax.

- `src/conduit/local_windows.c`: the named-pipe backend keeps local Win32
  constant/type/prototype declarations only for the no-SDK fallback path. When
  `_WINDOWS` is defined, the real SDK supplies pipe, token, and SID APIs such
  as `TOKEN_INFORMATION_CLASS`, `TOKEN_USER`, `CreateNamedPipeW`, and
  `GetTokenInformation`, avoiding collisions with the local fallback surface.

- `src/core/stw.c`: includes `core/platform.h` instead of `<windows.h>` on
  Windows to avoid the SDK parser gap above.

- `src/core/xxhash_wrap.c`: disables xxhash prefetch intrinsics on Windows and
  includes `<intrin.h>` before the vendored xxhash header. Revisit after `ncc`
  supports the relevant Clang-MSVC intrinsic surface cleanly.

- `src/core/alloc.c` and `src/core/mmaps.c`: early per-file replacements of
  `UINT32_MAX`/`UINT64_MAX` with casted all-ones values. These are now
  superseded by the `include/n00b.h` macro normalization and should be removed
  once the global approach or an `ncc` parser fix is in place.

## n00b Windows Portability

These are normal n00b-side Windows compatibility changes and are not
necessarily `ncc` parser work.

- `include/n00b.h`: provides Windows `pid_t` beside the existing `siginfo_t`
  shim, and exposes a guarded `ssize_t` typedef early enough for dependency
  headers such as picotls that are included from n00b translation units.

- `include/core/time.h`: uses Win32 time APIs for timestamp capture and
  monotonic nanoseconds because `clock_gettime` is not available in the native
  Windows target.

- `include/n00b.h`: provides a small Windows `clock_gettime` compatibility
  shim (`CLOCK_REALTIME` through `timespec_get`, `CLOCK_MONOTONIC` through
  `GetTickCount64`) for modules that still call the POSIX API directly. The
  inline shim is marked `[[n00b::nogc]]` so `ncc` does not inject GC stack-map
  code before the GC stack types are declared in the central header.

- `include/core/futex.h`: aligns the Windows duplicate declaration of
  `n00b_thread_exit` with the actual `uint64_t` signature.

- `src/core/exit.c`: removes an unconditional POSIX `<unistd.h>` include.

- `src/core/alloc_interpose.c` and `include/core/alloc_interpose.h`: resolve
  pre-runtime allocator calls through direct CRT functions on Windows instead
  of Unix `dlsym(RTLD_NEXT)`.

- `include/core/alloc_interpose_shim.h`: redirects Windows `_aligned_malloc`
  and `_aligned_free` from shimmed picotls TUs into n00b's interposed
  allocator, matching the existing malloc-family shim behavior.

- `src/core/file.c`: keeps the currently unsupported native Windows STREAM file
  path compiling by stubbing fd-only `close`/`read` branches with `ENOSYS` and
  by defining minimal open-flag constants for the mode-translation helper.
  This should be replaced with real Windows file/CRT fd support when that
  subsystem is implemented.

- `include/n00b.h`: maps POSIX `gmtime_r(timep, result)` to UCRT
  `gmtime_s(result, timep)` on Windows with POSIX-style return semantics, and
  marks the inline wrapper `[[n00b::nogc]]` so it is not instrumented before
  GC stack-map runtime declarations are visible.

- `include/n00b.h`: maps POSIX `timegm` to UCRT `_mkgmtime` on Windows for
  UTC `struct tm` conversion in certificate-validity parsing code.

- `include/n00b.h`: maps POSIX `setenv`/`unsetenv` to UCRT `_putenv_s` on
  Windows for tests and small tools that mutate process-local environment
  variables. The `setenv(..., overwrite = 0)` path probes existing variables
  with `_dupenv_s` instead of deprecated `getenv`.

- `include/n00b.h` defines `PATH_MAX` when absent on Windows. Display helper
  tools that build recursive output paths locally map POSIX
  `mkdir(path, mode)` to UCRT `_mkdir(path)` instead of using a global macro,
  because n00b also has VFS method fields named `mkdir`.

- `include/n00b.h` and `include/strings.h`: map POSIX case-insensitive string
  compares `strcasecmp`/`strncasecmp` to UCRT `_stricmp`/`_strnicmp` on
  Windows for modules that use POSIX spellings directly or include POSIX
  `<strings.h>`.

- `include/time.h`: wraps the UCRT time header and provides a Windows
  `nanosleep` shim over `Sleep` for modules that use POSIX timed waits
  directly. The inline shim is marked `[[n00b::nogc]]` for the same early
  header-instrumentation reason as the `clock_gettime` shim.

- `include/unistd.h`: maps `fchmod` to a no-op on native Windows, where UCRT
  exposes path-based `_chmod` but no fd-based POSIX permission API. This keeps
  temp-file permission adjustments compiling while preserving Windows'
  no-execute-bit behavior.

- `include/dirent.h`: provides the small POSIX directory iteration surface
  (`DIR`, `struct dirent`, `opendir`, `readdir`, and `closedir`) over UCRT
  `_findfirst`/`_findnext` on native Windows. This keeps parser and codegen
  coverage tests portable without adding test-local directory walkers.

- `src/util/dynamic_lib.c` and `include/core/platform.h`: implement the
  dynamic-library boundary on Windows with `LoadLibraryA`, `GetProcAddress`,
  and `FreeLibrary` instead of POSIX `dlopen`/`dlsym`/`dlclose`.

- `src/util/errno_str.c` and `include/internal/win32_sockets.h`: use the
  internal Win32 socket declaration shim instead of POSIX `<netdb.h>` on
  Windows, and provide `addrinfo`, `getaddrinfo`, `freeaddrinfo`,
  `gai_strerrorA`, and Winsock `EAI_*` constants.

- `include/internal/win32_sockets.h`: also provides `socklen_t`,
  `sockaddr_storage`, `recvfrom`, `sendto`, and `closesocket` declarations
  needed by the native Windows UDP conduit path.

- `src/net/quic/acme_tls.c`: uses the Windows socket shim for nonblocking
  setup, socket close, socket error retrieval, and `WSAPoll` when compiling
  under native Windows. This keeps the ACME TLS helper from treating Winsock
  sockets as CRT file descriptors.

- `src/net/quic/endpoint.c`: maps the qlog directory creation call to UCRT
  `_mkdir` on native Windows.

- `src/net/quic/cert_provisioner_external.c`: runs external certificate
  provisioner commands with UCRT `_spawnvp(_P_WAIT, ...)` on native Windows
  instead of POSIX `fork`/`execvp`/`waitpid`.

- `src/net/quic/preflight.c`: uses Winsock-compatible `setsockopt` arguments,
  `closesocket`, Windows socket error retrieval, `strtok_s`, and `;`-separated
  `PATH` scanning on native Windows.

- `src/net/quic/metrics.c`: handles accepted metrics sockets with Winsock
  `ioctlsocket`, `recv`, `send`, `closesocket`, and millisecond socket timeout
  options on native Windows instead of POSIX `fcntl`/`read`/`write`/`close`.

- `src/net/http/http_compression.c` and `src/net/http/http_cookies.c`: keep
  optional brotli/zstd/libpsl runtime loading local to each module, but map the
  POSIX `dlopen`/`dlsym`/`dlclose` shape to Win32
  `LoadLibraryA`/`GetProcAddress`/`FreeLibrary` under native Windows and probe
  `.dll` candidates.

- `src/naudit/preprocess.c`: uses UCRT `_pipe`, `_dup2`, `_spawnvp(_P_NOWAIT)`,
  `_cwait`, and `"NUL"` to run `ncc -E` and capture stdout on native Windows
  instead of POSIX `pipe`, `posix_spawn`, `waitpid`, and `/dev/null`.

- `src/naudit/exemption.c`: uses UCRT `_spawnvp(_P_WAIT)` and temporary stdin
  redirection for `ssh-keygen` sign/verify on native Windows instead of POSIX
  `posix_spawn` file actions and `waitpid`, and maps exemption directory
  creation to UCRT `_mkdir`.

- `src/naudit/filter.c`: provides a small Windows-only byte-search helper for
  the one GNU `memmem` call used by naudit text-containment filters.

- `src/tools/n00b-static-init-helper.c`: uses UCRT `_pipe`, `_dup2`,
  `_spawnv(_P_NOWAIT)`, and `_cwait` when delegating grammar-image requests to
  `n00b-static-grammar-helper.exe` on native Windows instead of POSIX
  `pipe`/`fork`/`execl`/`waitpid`.

- `examples/quic_acme_http01_demo/main.c`: keeps the embedded HTTP-01 demo in
  the default native Windows build by mapping its single worker thread and
  mutex to `CreateThread`/`CRITICAL_SECTION`, mapping socket close/nonblocking
  setup to `closesocket`/`ioctlsocket`, and suppressing the POSIX-only
  `MSG_NOSIGNAL` send flag on Winsock.

- `src/tools/wax.c`: avoids POSIX process supervision headers and calls on
  native Windows. Foreground helper execution uses UCRT `_spawnvp(_P_WAIT)`;
  daemon/subscriber lifecycle commands report unsupported instead of compiling
  `fork`/`setsid`/`kill`/`waitpid` paths that do not exist in the Windows CRT.

- `test/unit/test_thread_self_foreign.c`: preserves the foreign-thread
  regression test on native Windows by using `CreateThread`/`WaitForSingleObject`
  instead of POSIX `pthread_create`/`pthread_join`.

- `test/unit/test_portability.h`, naudit unit tests, OCI attestation tests, the
  h1 pinned-trust test, the ROCS map test, and the slay rewrite test: extend
  the existing Windows-only test harness shim beyond `asprintf` to cover POSIX
  environment, temp-directory, mkdir/rmdir, cwd, pipe, popen/pclose, GNU
  `memmem`, and no-op nonblocking `fcntl` calls used by test code. This keeps
  the compatibility surface test-local instead of adding production header
  shims for harness-only APIs.

- `test/unit/test_crash.c`: keeps the guard-range portion compiling on native
  Windows while skipping the POSIX `sigaltstack` probe. Windows crash delivery
  uses a different runtime path, so the test does not add fake `stack_t` or
  `sigaltstack` shims.

- `src/util/errno_str.c`: guards POSIX errno names not defined by UCRT
  (`EMULTIHOP`, `ESTALE`, `EDQUOT`) in the same style as the existing
  Linux/BSD extension guards.

- `include/util/path.h` and `src/util/path.c`: avoid POSIX-only
  `<unistd.h>`, `<pwd.h>`, `<dirent.h>`, and related APIs on native Windows.
  The shim maps simple directory/stat operations to UCRT functions where
  available, uses environment fallbacks for user/home lookups, defines missing
  `S_IF*` constants for compile-time file-kind values, and returns `ENOSYS`
  for path operations that still require a real Windows implementation
  (`readlink`, recursive directory removal/walking, and no-replace rename).
  `n00b_app_path` currently returns `"."` on Windows until it is wired to the
  native executable-path API, and `n00b_find_command_paths` skips POSIX
  uid/gid execute-bit filtering.

- `include/util/path.h`: splits `PATH` entries on `;` under Windows instead of
  POSIX `:`.

- `src/display/render/backend_ansi.c` and
  `src/display/render/backend_dumb.c`: avoid POSIX `<unistd.h>` on Windows for
  renderer stdout handling. The ANSI backend defines standard fd numbers for
  compile-time initialization, while the dumb backend routes direct writes
  through UCRT `_write`.

- `src/display/render/backend_registry.c`: uses UCRT `strtok_s` behind a
  local wrapper when tokenizing the Windows renderer plugin search path,
  preserving the existing `strtok_r`-style call sites without requiring a
  global POSIX string shim.

- `src/conduit/xform.c`: drops an unused POSIX `<unistd.h>` include so the
  transform lifecycle code can compile under the native Windows target.

- `src/conduit/proc_lifecycle.c`: builds the `siginfo_t`/`waitid()` status
  normalizer only on non-Windows targets. The Windows WSA backend reports
  process-exit status directly through `GetExitCodeProcess`, so the POSIX
  `si_code`/`CLD_*` path is not part of the native Windows backend.

- `src/vfs/backend_local.c`: avoids POSIX `<dirent.h>`/`<unistd.h>` on native
  Windows. The local backend maps fd-style reads to UCRT `_open`/`_read`/
  `_close`/`_lseeki64` and provides a small `_findfirst`/`_findnext` directory
  iterator so `local_list` can compile and enumerate directories.

- `src/vfs/cache.c`: avoids POSIX `<unistd.h>` on native Windows by mapping the
  cache file helpers to UCRT `_open`/`_read`/`_write`/`_close`, `_unlink`, and
  `_mkdir`.

- `src/parsers/toml.c`: avoids POSIX `<unistd.h>` on native Windows by mapping
  the file-slurp helper to UCRT `_open`/`_read`/`_close`, with binary mode so
  the `stat` size continues to match the number of bytes read.

## Build-System and Dependency Workarounds

These unblock the local native Windows build but are not `ncc` parser work.

- `meson.build` and `meson.options`: add Windows fallback options for
  neighboring libgit2 and zlib headers/libraries when pkg-config dependencies
  are unavailable.

- `meson.build`: skips shell-script integration tests when neither `sh` nor
  `bash` exists on native Windows.

- `meson.build`: skips the POSIX pthread-only `hidden_pool_stw` stress test on
  native Windows. The native Windows foreign-thread smoke coverage remains in
  `test_thread_self_foreign`.

- `meson.build`: passes the Windows stack reserve to `lld-link` as
  `-Wl,/STACK:16777216` instead of GNU `-Wl,--stack,16777216`, which the
  MSVC-style linker parses as a missing input file.

- `subprojects/packagefiles/mir/meson.build`: replaces a POSIX `sh` environment
  probe with a Python probe.

- `src/text/unicode/tools/gen_tables.py`: opens generated and input text files
  as UTF-8 explicitly to avoid native Windows codepage decoding failures.

- `scripts/embed_metagrammar.py`: emits the audit-rule-file metagrammar as a
  `static const char[]` built from adjacent string literals, normalizes input
  CRLF to LF, writes LF-only generated output, and avoids macro
  line-continuations. This keeps the generated `audit_rule_file_grammar.h`
  parseable by native Windows `ncc` when the source checkout uses CRLF.

- `subprojects/picotls/meson.build`: adds Windows include directories,
  `_WINDOWS`/`_WINDOWS64` defines, `wintimeofday.c`, and targeted warning
  suppressions in the n00b-authored Meson shim. The `_WINDOWS`/`_WINDOWS64`
  defines are now exported through the declared dependency so n00b translation
  units that include picotls headers see the same Windows header path.

- `subprojects/picoquic/meson.build`: adds `_WINDOWS`/`_WINDOWS64` defines in
  the n00b-authored Meson shim and exports them through the declared dependency
  so n00b translation units that include picoquic headers use the real Windows
  SDK branch instead of picoquic's POSIX include branch.

## External Local Build Note

- Neighboring `ncc.exe` was rebuilt with a larger PE stack reserve after stack
  overflow while compiling large n00b translation units. This is outside the
  n00b repo, but it is probably an `ncc` build default to revisit.

## Non-Shim Cleanup Candidate

- `src/core/init.c`: default conduit setup was split into a helper while
  isolating an earlier `ncc` stack-overflow failure. It is not a Windows shim
  and should be reviewed or reverted before finalizing the patch set if it is
  no longer needed.
