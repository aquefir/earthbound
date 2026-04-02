# Compiling instructions

Earthbound uses POSIX shell scripts to automate the amalgamation of both
its final singular C file `earthbound.c` and the bootstrap script
`earthbound.sh`. The repository Makefile facilitates this; it does not,
contrary to appearances, compile Earthbound into a binary executable.

## Prerequisites

These are **required**:

- A POSIX.1-2001 compliant host system

These are **strongly recommended** but _technically optional:_

- GNU coreutils (`brew install` them on macOS)
- GNU Make 3.82+
	- for running the Makefile as it is the actively maintained approach
	- the `util/` folder has POSIX shell scripts for amalgamation
	  (use them at your own risk)
	- macOS may provide BSD Make under the `make` name; either alias
	  `gmake` to `make` or simply use `gmake` at the command line
	  instead
- Python 3
	- for minifying the amalgamated `earthbound.c`
	- this can be skipped by passing `NOMINIFY=1` to the `make`
	  invocation or to the `util/` build scripts.

## Building

A simple invocation of `make` will create two files in the repository
root:

- `earthbound-$ver.c`
- `earthbound.sh`

For the C file, `$ver` is either a semantic version number or an
abbreviated `git` commit hash. The Makefile picks up on `$ver` as an
environment variable and uses it if it is nonempty, otherwise
backfilling it with the abbreviated hash obtained from a `git` call.

These files can then be uploaded wherever desired and used as shown in
the [README](/README.md).
