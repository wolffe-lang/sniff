# Architecture map

This is the intended module boundary, not an implementation claim. The
pre-code prediction is `tests/prediction.json`. S1's final reader scope must
be revised from the measured producer census, not from these hypotheses.

| Stage | Modules / responsibility | Acceptance |
|---|---|---|
| S0 | fixture builders, binary oracle adapters, transcript comparison, census | digest-bound builds, named red-first harness failures |
| S1 | bounded bytes, ELF64, Mach-O64/dSYM, DWARF units/forms/lines, symbols, ranges/locations, CFI | dump modes byte-identical to the pinned reader oracle |
| S2 | Linux x86-64 process control, breakpoint patching, source stepping, unwind, scalar values, GDB command parser | scripted GDB sessions and lupin local-value agreement |
| S3 | macOS arm64 task/exception ports, BRK, register access, signing | S2 commands against LLDB and lupin |
| S4 | PAX process backend, static dev-image packaging | S2 console session agrees with Linux after named normalization |
| S5 | hardware watchpoints, conditions, expressions, aggregate presentation | pinned fenrir front end; every unsupported construct refused by name |
| S6 | all-stop threads, signals, attach/detach | per-platform scripted sessions |
| S7 | ELF and Mach-O core readers | process-independent replay |
| S8 | remote serial client and small remote process stub | QEMU gdbstub and remote-process sessions |
| S9 | Debug Adapter Protocol server | recorded editor-client exchange |

## Reader invariants

DWARF format width is not target address width. Every unit, contribution,
attribute block and string has a containing byte bound; checked arithmetic
precedes allocation and offset arithmetic. Abbreviation references and DIE
references must remain within their specified domains. Unsupported encodings
are named errors, not a guessed byte skip.

Line-table sequences reset independently; an `end_sequence` row is not a
source statement. Preserve columns, discriminator, `is_stmt`, prologue and
epilogue flags, and the original row order. DWARF 4 and 5 use different file
and directory-table conventions.

CFI from the linked runtime is not proof of CFI for a wolf function. The census
must attribute units to producers and frame ranges to owning functions.
A base-type DIE does not imply an aggregate can be printed.

## Expressions

S5 will vendor a pinned, provenance-marked copy of fenrir's front end.
Its typed side tables are keyed by AST node ID; consumers must check the
nonempty diagnostic code before consuming partial tables. Its current F1
core has no indexing, dereference, casts, floating-point literals, methods,
generics, enum or list expressions. Reusing that core is not permission to
silently accept those constructs: named refusals remain visible.

## Still to measure in S0

Container identities and package versions; all wolf and C fixture binaries;
two-build digests; full DWARF census; GDB/LLDB session captures; lupin source
stops and locals; red-first transcript rows; the final green record and plant.
None of those is claimed by the initial scaffold.
