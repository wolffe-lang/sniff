# sn06: list and help (sniff#11)

Base: sniff trunk `0c2a77d`. The prediction was committed before code (`tests/sn06-prediction.json`, `395804a`).
sniff#11 asks for two of the first commands someone types at the `(sniff)` prompt, `list` and `help`, for an
undefined-command line that stops pointing at a `help` that does not exist, and, if it stays small, gdb's
empty-line repeat. All four are here, with rows on the Linux, macOS and PAX sets, red first against trunk.

## What was built

| | |
|---|---|
| `list` | `src/session/listing.lu`: every form in the issue (no argument and `+`, `-`, `.`, `N`, `FUNCTION`, `FILE:N`, `FILE:FUNCTION`, `FIRST,LAST`, `FIRST,`, `,LAST`, `FIRST,+N`) and `*ADDRESS`, over the source-line reader `step` and `frame` use. `l` is its alias |
| the reader | `src/session/report.lu`: a frame's source line is the solitary line a bare `list` centres on, and a file that cannot be read is warned about once, as gdb does, then named |
| `help` | `src/session/help.lu` over the table in `src/session/helptext.lu`: `help`, `help all`, `help CLASS`, `help COMMAND` (and every alias), `help info SUB`, `help maintenance SUB` |
| gdb commands sniff lacks | as the contract asked, named as not implemented yet, never as undefined: `help catch` and `catch fork` both answer `"catch" is a gdb command that sniff does not implement yet.`, for 181 top-level names and 65 info subcommands from the pinned gdb's `help all` and `help info` |
| the undefined-command line | as the contract asked: it dropped its `Try "help"` while `help` did not exist (`de4efcb`), and points at it again since (`233f1d6`); maintenance's names `help maintenance`, as gdb's does |
| aliases | gdb's registered aliases sniff lacked, so that help's names lines are true of sniff: `bre`, `del`, `dow`, `do`, `inf`, `mt` |
| the empty line | `src/session/commands.lu`: at the terminal an empty or blank line repeats the previous line as gdb repeats it, with `list` and `x` rewritten; `x` with no address goes on from the last `x` |
| three behaviour changes outside the issue | the repeat rows exposed them, and each has its own row: at a terminal a new `display` is shown at once, as gdb shows it (batch mode still waits for the next stop; `tty-wolf-loops-repeat-not`); `echo` drops its argument's leading blanks, as gdb does (`echo-leading-space`); `x` with no address goes on after the last `x` with its count, format and size (`tty-wolf-loops-repeat-x`) |
| harness | compare modes per row (`head`, `subset`, `own`) in `tools/session.py`, used by `tools/session-pax.py` and `tools/session-mac.py`; macOS rows may hold stderr and the exit status; C recursion (the reader corpus's) joins the session fixtures, with a copy whose source the build removes |

### list, as measured

The rules are the pinned gdb's, measured as a black box on the three fixtures and on 20 synthetic C programs
that put main at different lines in two shapes (the prediction's `list` section):

- A listing centred on line c prints `max(c - 5, 1)` through ten lines, cut at the end of the file and never
  shifted back. `list 11` on nested's 12 lines prints 6..12. A first line past the end is refused with
  `Line number FIRST out of range; FILE has N lines.`
- `list FUNCTION` centres on the line of the function's entry row. That is the `{` line when the header spans
  lines, not the declaration line and not the first statement. wolf's entry rows already carry the first
  statement's line.
- With nothing listed and no frame line printed, `list` lists around main: first `max(B - 14, 1)`, where B is
  main's breakpoint line.
- After a frame's source line (a stop, `frame`, `up`, `down`, `finish`), `list` and `list -` both centre on it.
  After a listing, `list` goes on after it and `list -` gives the ten lines before it. Past either end:
  `End of the file was already reached, use "list ." to list the current location again` and
  `Already at the start of FILE.`
- A function with no line information (`_start`, the calls fixture's `plain_twice`) lists nothing, status 0.
- A source file that cannot be read: the first time it is wanted, `warning: LINE<TAB>PATH: No such file or
  directory` on stderr and nothing on stdout; every later time, `LINE<TAB>in PATH`, for a listing (its first
  line only) and for a stop alike.

### help: which rows compare bytes and which compare shape

Every names line (`break, brea, bre, br, b`) and every summary line comes from the pinned gdb's output.
The help table is generated from it, never typed. gdb's alias order is kept, and a command with no
registered alias has no names line, as in gdb.

- **Bytes.** The paragraph is gdb's because it describes what sniff does: `help`, `step`, `next`, `stepi`,
  `nexti`, `finish`, `up`, `down`, `ignore`, `echo`, `output`, `info display` (rows `help-bytes-*`).
- **Head.** The names and summary lines are held, and the rest is sniff's own words: what sniff does, and
  what gdb's paragraph describes that is not implemented yet. That covers run's shell and `set args`,
  continue's ignore count, break's probes and threads, watch's `-location`, print's options, backtrace's
  options and COUNT, list's `set listsize`, x's f, i and z formats, the info filters, and the delete, frame
  and kill subcommands. Each `help-COMMAND` row names what in its `why`. `quit` and `maintenance` hold their
  names line only: gdb's summaries name gdb itself ("Exit gdb.").
- **Subset.** The listings (`help`, `h`, `help all`, `help CLASS`, `help info`) are held line by line. Every
  line sniff prints is one of gdb's, in gdb's order, or one of the row's named sniff lines (sniff's
  `maintenance` lines and `quit`'s summary).
  - gdb's alone are the `aliases`, `obscure`, `text-user-interface`, `tracepoints` and `user-defined` classes,
    every command and subcommand sniff lacks, and the footer lines that name `apropos` or claim abbreviations.
  - sniff takes only its dispatcher's exact names and aliases, not gdb's unambiguous prefixes.
- **Own.** Rows for gdb commands sniff lacks hold sniff's sentence and check that the golden shows gdb
  answering the command. `help maint frames` (sniff's own command) holds its text and checks that gdb refuses
  it.

### The empty line

As measured at gdb's terminal:

- Repeated: `next`, `step`, `until`, `stepi`, `nexti`, `continue`, `finish`, `print`, `output`, `info`, `bt`,
  `frame` (with its argument), `up`, `down`, `x`, `break`, `tbreak`, the watches, `ignore`, `kill`, `echo`,
  `help`, `maintenance`, and an undefined command.
- Not repeated: `run`, `delete`, `display`, `undisplay`, `condition` (and `quit`).
- A comment is a previous line that repeats as nothing, and a blank line (spaces, a tab) is an empty one.
- `list` repeats as a bare `list` once it has printed, and `list -` as itself; a `list` that failed repeats as
  typed. `x` repeats as a bare `x`: the same count, format and size, after the last address.
- A command file's empty line does nothing (the manual's Command Files), and sniff's batch mode is unchanged.

## Prediction against result

- Held: every list rule above was predicted from the probe and held on all three sets; help's names and summary
  lines, the bytes rows, the listings as subsets; the undefined lines; the repeat table and its two rewrites;
  no existing row moved.
- Wrong or missed, each now named:
  - a terminal row cannot hold a listing as a subset, and gdb wraps `info breakpoints`' What column at 80
    columns only at a terminal: the terminal rows hold only byte-comparable lines;
  - `ignore` prints `Will ignore next N crossings of breakpoint M.` only at a terminal, which sniff does not
    yet: the remainder;
  - `output`'s unterminated text and PAX's typed-echo removal do not mix at the console: the data repeat row
    uses `print`;
  - on PAX, one stack word in the `x` repeat row holds a stack address (zero-padded, so the stack
    normalisation does not reach it): dropped by name in `tests/pax-rows.json`;
  - the macOS rows compared stdout only, so a refusal on stderr passed at trunk there: those rows now hold
    stderr and the status, with the command file's path named;
  - help print's own paragraph contains `$ `, which PAX's shell-prompt counter read as the shell's second
    prompt, typing `exit` into the middle of the rows; the console now types the rows and the exit as one
    line.

## Decisions

- The undefined-command line, as the contract asked: a commit before `help` dropped the hint (`de4efcb`) and the
  `help` commit restored gdb's line (`233f1d6`). The rows hold gdb's line, so they were red in between, and
  green at trunk and at the head: trunk already printed gdb's line.
- A gdb command sniff lacks is named as not implemented yet, as the contract asked, both under `help` and when
  it is typed as a command.
- The empty line repeats every command gdb repeats, with the measured no-repeat set and the `list` and `x`
  rewrites, not only `next`, `step` and `list`: the table stayed small, and an empty line after `continue` or
  `up` would otherwise do nothing where gdb repeats it.

## Remainder

- gdb's unambiguous prefixes (`help lis`, `lis 3`); sniff's dispatcher takes exact names and aliases.
- `set listsize` and `show listsize`; `list +N`/`-N` offsets as a single argument; a FUNCTION that resolves to
  more than one line (gdb lists the choices).
- `Note: breakpoint N also set at pc ...`, which gdb prints when a repeated (or any second) `break` lands on the
  same address.
- `ignore`'s terminal-only message, and the terminal's 80-column wrap of `info breakpoints`.
- `until LOCATION` (an argument is read as a count today), `continue N`, `quit EXPR`.

## Forbidden

The clean room held. These were read: the GDB manual's Printing Source Lines, Linespec Locations, Location
Specifications, Command Syntax, Command Files, Getting Help and Examining Source Files sections, staged as
digest-checked inputs. gdb ran only as the pinned binary in the oracle image, and lldb only as the system
binary, in the macOS gate's existing rows. No debugger's source was read.

## Done-when

- [x] the prediction before code
- [x] the rows, red against trunk on the Linux, macOS and PAX sets
- [x] `list`, every form in the issue and its refusals, held to gdb on all three fixtures
- [x] `help`: classes, paragraphs (bytes or shape, named per row), gdb commands sniff lacks named
- [x] the undefined-command line
- [x] the empty-line repeat
- [ ] the gauntlet, the plant and the macOS record at the head: in the PR
