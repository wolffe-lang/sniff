# S7, second part: Mach-O core files of macOS programs

The prediction (`tests/s7-macho-prediction.json`) was committed before any code, on trunk `5d99cad3`.

## What was built

| | |
|---|---|
| reader | `src/readers/macho_core.lu` reads an arm64 MH_CORE: its LC_SEGMENT_64 segments, one LC_THREAD a thread with its flavours walked by their counts (ARM_THREAD_STATE64 as the 34 slots the macOS platform's registers use, ARM_EXCEPTION_STATE64), and its LC_NOTEs. `all image infos` gives the images (path, UUID, load address, segments) and `addrable bits` the addressable bits. Nine refusals by name, and caps on load commands, their bytes, segments, threads, flavours, a flavour's words, notes, images, a path's bytes and an image's segments. Unit rows run natively and on the checked machine (`src/macho_core_test.lu`), each cap at its value and one past it. |
| layouts | `tools/abi-probe-macos.c` compiles against the SDK and prints 35 constants and offsets. `tools/check-abi.py` holds `macho_core.lu` to its record (`tests/evidence/macos-s3/abi.txt`), and the macOS gate holds the record stable. |
| session | `src/session/core.lu` reads a Mach-O core with the forms an ELF core has: `PROG CORE`, `-c CORE [PROG]`, `-c CORE` alone and `core-file`. Memory comes from its segments, then from the program's own sections. The program is the image list's first image, placed only when its UUID is the given program's; with none placed, the file the core names is read with its dSYM. The selected thread is the one whose exception class is a stop. gdb's banner gives the program's path, the signal and the stop. |
| harness | `tools/session-mac.py` writes each take's cores afresh with the pinned lldb. They go under the take's directory, with RLIMIT_FSIZE at 64 MiB, `SHELL=/bin/sh` and the take's own HOME and TMPDIR. They are deleted however the take ends, and the take prints the bytes it left behind. Each core's line names the lldb that wrote it. Every lldb and sniff it starts is ended by its pid when it overruns, and the row fails by name. The take has a deadline, after which no process starts. |
| rows | Seven lldb rows: bt with arguments and printed locals, the pc, a frame record read with `x`, four threads, a wolf program, a stack-only core and a fault. Four `expect` rows: a missing core, a truncated one, another program's, no program. The Linux set's eight `core-gcc-refuse-*` rows. |

## Measured

- lldb writes MH_CORE for arm64 with `process save-core`.
  - In the `modified-memory` style, a core is 0.9 to 1.0 MB: the stack, writable data, the heap, and any page lldb wrote to.
  - The program's text page is present, with the original instructions restored.
  - In the `stack` style, a core is 36 to 86 KB.
  - In the `full` style, a core is about 5.9 GB (the system's shared cache): no row writes one.
- A fault's core is written by lldb's on-crash commands (`-k`). lldb stops running `-o` commands once the program has crashed.
- `all image infos`:
  - A 24-byte header (version 1, image count, entries' file offset, entry size 48).
  - 48-byte entries: path offset, UUID, load address, segment list offset, segment count, a flag.
  - 32-byte segment entries.
  - Every offset is from the start of the file.
  - The first image is the program. Its UUID is the program's LC_UUID, and it loads at its own address (lldb starts it with address randomisation off).
- `addrable bits` reads (4, 47, 47, 0). `process metadata` is JSON with each thread's id.
- lldb names a core's stop by the exception class:
  - 0x3c is `ESR_EC_BRK_AARCH64`, a breakpoint.
  - 0x24 is `ESR_EC_DABORT_EL0`, a data abort.
  - A thread in a system call (0x15) has no stop reason.
  - The thread lldb selects is the one with a stop reason: thread 4 of 4 in the workers core.
- lldb over a core:
  - Run control: `mach-o-core does not support resuming processes`.
  - Watchpoints: `watchpoints are not supported`.
  - Breakpoints can be set, but their sites cannot be written.
  - Launch replaces the core.
  - Given another program, lldb keeps it with no UUID check, and its frames are named `_mh_execute_header + N`.
  - Given no program, lldb reads the program from the path the image list names.
  - Given a truncated core, lldb itself dies with SIGSEGV.
- Where the stack sits:
  - A program lldb starts finds lldb's environment above its stack (`target.inherit-env` is true).
  - `/usr/bin/lldb` is a shim. It runs the lldb of the selected developer directory with `CPATH`, `LIBRARY_PATH`, `MANPATH` and `SDKROOT` added, which is 324 bytes of strings and four more pointers. `xcrun --find lldb` names that lldb itself, which adds none.
  - Started by the shim, a program's stack top sits 352 bytes lower than when the lldb runs directly. One lldb gave the same stack top in each of five launches.
  - A core is written afresh in each take, so its stack words are where that take's lldb put them.
  - `count` calls nothing and makes no frame record: at its breakpoint `$fp` is still main's, whose record returns into dyld in the shared cache.

## Boundaries

- The rows compare no value the stack held before the stop, such as an uninitialised local or a word a library left there: such values can name addresses in the shared cache, which moves from boot to boot.
- The system libraries' text is only in the dyld shared cache. sniff names no frame there, live or over a core, and reads no memory there.
- The eight refusal rows hold the refusal text against a golden gdb gave on Linux, for the gcc build of the same source over an ELF core. They show that sniff's refusals over a Mach-O core read as gdb's do. They do not show anything macOS-specific in how sniff reaches a refusal; the `expect` rows carry that.
- Hosted macOS skips the core rows by name, because their cores need the pinned lldb on a Mac. The Mac's record is their only evidence. The stored lldb output is replayed on every host.
- The gate's lldb is `lldb` found on the harness's own PATH (`/usr/bin:/bin:/usr/sbin:/sbin`), whatever PATH the caller has. On every Mac, a contributor's included, that is `/usr/bin/lldb`, the shim. The stored evidence was written with `xcrun --find lldb`.
- The memory row holds under either lldb. It reads `depth_sum`'s frame record. Main's saved frame pointer, a stack address, is compared as its distance from the address read. The return address into main is compared as it is: lldb starts the program without address randomisation, so its text is where its load commands put it, as `calls-bt`'s frame addresses are. A take in which the return address moves is a defect to find, not a reason to loosen the row.
- Exception classes other than 0x3c, 0x24 and 0x15 are not measured. arm64e programs (signed pointers) are refused by the reader until they are.
