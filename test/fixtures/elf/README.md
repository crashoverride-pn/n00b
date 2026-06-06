# ELF Fixtures

ELF rewrite tests start with generated fixtures from
`test/unit/objfile_elf_casegen.h`. Keep committed binary fixtures out of this
directory unless a case cannot be expressed clearly by the generator.

Fixture cases should graduate through this lifecycle:

- `explore`: compare N00b and an oracle, but do not assert default behavior.
- `pending`: behavior is understood but not owned by N00b yet.
- `known`: default known-answer case independent of external repos.
- `diverge`: intentional difference from the oracle.
- `retired`: superseded case.

The optional Brandon-oracle test suite is transitional. Once a behavior is
owned by N00b, encode it as a known-answer test.
