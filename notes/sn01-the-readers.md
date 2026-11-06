# sn01: the readers (S1)

`sniff dump MODE FILE` reads ELF64 x86-64 and Mach-O 64 arm64 files, dSYM
bundles included. It prints twelve views, byte-identical to the pinned oracle
of the file's platform on every recorded fixture: 29 Linux builds and 17
macOS builds, wolf runtime units included. Nothing here runs or evaluates a
process; that begins in S2.

## Prediction

`tests/sn01-prediction.json` and `tests/reader-cap-prediction.json` were
committed before the code they predict. Scored:

- **Modules, in order.** Bytes, ELF64, Mach-O 64 with dSYM, symbols, units,
  abbreviations and forms, indexed tables, lines, lists and expressions, CFI,
  then the dump. As predicted, except for the layout: the readers live in one
  module (`src/readers/`) and the renderers in another (`src/dump/`), not in
  `src/dwarf/*`.
- **Modes.** All eleven llvm-dwarfdump modes plus `--symbols` (R-sn01-1's
  oracles) mirror their oracle on every fixture, including the rows where
  the Linux oracle itself fails. GCC's location-view bytes in
  `.debug_loclists` make LLVM 18 print empty lists, then exit 1 on a truncated
  entry. A reader that follows DWARF 5 alone does the same, with the same
  stdout and status.
- **Not predicted.** The two oracles differ in a handful of spellings:
  `advance_loc` targets, `.debug_loc` brackets, and arm64 `W`/`B` register
  names. Each container keeps its platform's spelling. Also unpredicted:
  `--eh-frame` and `--debug-frame` print the same two sections, and pointer
  names are never printed (Rust's `*const ()` is `() *`).
- **Red-first rows.** Every module row was red before its implementation,
  except the list and frame unit rows. Those were written after their
  readers, so the dump matrix red at `88b4672` is their witness. The hostile
  integration row was red by name (two overflow traps in 2509 runs) before
  wrapping arithmetic fixed it. The compact-unwind refusal row was red before
  its mode.
- **Named refusals.** Unsupported class, endianness, architecture,
  compression, split and supplementary DWARF, compact unwind, unknown forms,
  expression operations and CFI instructions, and resource limits are all
  refused by name. Macro and name indexes have no mode and stay outside S1.

## Forbidden

Only the sources in `docs/SOURCES.md` were read: DWARF 4 and 5, the ELF gABI,
the AMD64 psABI, LSB Core (Exception Frames, Symbol Versioning), the Arm ABIs,
and Apple's documentation and SDK declarations. No debugger, DWARF library,
binutils, cctools or kernel source was opened, and no search result pointing
into one. The oracles ran only as pinned binaries, on recorded fixtures and on
synthetic inputs kept with their complete output under `tests/evidence/`.
Every vendor name traces to a fixture line or a probe. Nothing was installed.

## Inputs verified

- **Pins.** wolf 0.2.37 and lupin 0.1.59 archives by SHA-256; the Linux image
  by package closure and binary digests; the macOS oracles by version, and
  `llvm-nm` by SHA-256 too.
- **Fixtures.** Every gate run rebuilds them twice and hashes them, and the
  matrix runs both tools on those same bytes and paths.
- **Retired workers' drafts.** The indexed-table and expression drafts were
  reviewed against DWARF 5 §§7.26–7.29 and §§2.5–2.6 with Table 7.9. Each
  entered red at `734ee0f` (its spec without its API) and turned green
  natively and checked.
- **Caps.** Measured on the largest fixtures, not inferred
  (`tests/evidence/linux/reader-caps.json`): 392124 DIEs, 1428600
  attributes, 12.7M units of tree work, 41492 rows per line table. The
  defaults sit 2.67x, 2.94x, 5.27x and 25x above them.

## Evidence index

| Row | Witness |
|---|---|
| reader units, native and checked | `tools/test-readers.py`: 11 programs, 60 named rows |
| dump matrix | `tools/dump-matrix.py`: 12 modes x 29 Linux fixtures, 12 x 17 macOS, full bytes and exit status |
| hostile inputs | `tools/test-hostile.py`: every mode on truncated and corrupted fixtures; exit 0, or exit 1 with a named row |
| compact unwind | `--unwind-info` refuses by name where `__unwind_info` exists |
| vendor names | `tests/evidence/vendor-names.json`, `tests/evidence/expression-encoding/` |
| oracle spellings | `tests/evidence/oracle-probes/` |

The gauntlet records, the plant record and every END line are in the PR.

## Done-when

- [x] ELF64 and Mach-O 64 with dSYM bundles
- [x] DWARF 4 and 5: info and abbreviations, lines, `str_offsets`, `addr`, ranges and `rnglists`, locations and `loclists`
- [x] CFI from `.debug_frame` and `.eh_frame`, separately
- [x] symbols
- [x] every `sniff dump` mode byte-identical on every recorded fixture, both platforms
- [x] hostile input refused by name; bounded work and allocation
- [x] compact unwind refused by name (R-sn00-2); the DWARF 5 file-zero ambiguity stays a stated boundary
