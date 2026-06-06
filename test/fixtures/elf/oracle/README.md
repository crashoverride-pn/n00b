# ELF Oracle Helpers

Optional ELF oracle tests use a subprocess helper. Prefer
`N00B_ELF_ORACLE_BIN` when you already have a helper binary. On Linux/x86-64,
the test can also build the checked-in thin helper from Brandon's packager
checkout when `N00B_ELF_ORACLE_ROOT` is set.

The helper protocol is line-oriented:

```text
verdict=valid-target
code=0
detail=ok
```

The first runner compares only `verdict`. `code` and `detail` are diagnostic
until the helper protocol settles.

When `N00B_TEST_ELF_ORACLE=1` is set, missing or invalid oracle configuration
is a test failure. Leaving that gate unset keeps the suite as a default skip.

Example:

```sh
N00B_TEST=1 \
N00B_TEST_SUITES=elf_oracle \
N00B_TEST_ELF_ORACLE=1 \
N00B_ELF_ORACLE_ROOT=/Users/viega/ncc/packager \
bash build.sh
```

Root auto-build is intentionally Linux/x86-64 only because Brandon's packager
validator targets Linux ELF64 behavior. Other hosts should use
`N00B_ELF_ORACLE_BIN` if a compatible helper is available.
