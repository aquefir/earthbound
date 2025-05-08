# Earthbound

_An agnostic software procurement system._

![Earthbound](https://cdn.tohoku.ac/earthbound-banner.jpg)

This is a very special project. It is a key component for bootstrapping
nearly all other projects developed by [Aquefir Consulting
LLC](https://aquefir.co/) and indeed the wider world of software using
the &ldquo;developmental quartet&rdquo; consisting of Inbound, Outbound,
Rebound, and this project: **Earthbound**.

Earthbound does not care what form your software comes in. It does not
care where your software comes from, as long as it can find it. Its job
is very simple and _singular,_ and true to UNIX&trade; fashion, it is
very good at it.

-----

## Getting started

There are two ways to get started using Earthbound: the quick way, and
the right way.

### The quick way

```sh
curl -fsSL tohoku.ac/earthbound.c | cc -oeb.bin -
./eb.bin $ini
```

### The right way

> Please remember, we do not intend to be dogmatic in calling this
> &ldquo;the right way&rdquo;. You can (and often should) do more.

Use a bootstrap script from the [Releases](/releases) page.

- Download an `earthbound.sh` release and place it into your repository.
- If you are using version control, check it in as-is.
- Before building, run `./earthbound.sh` to securely download and
compile Earthbound.
	- You will need an ANSI C compiler in your `$PATH` for this.
		- Either its name is `cc`, or it is provided as `$CC`.
	- You will also need `shasum` or `sha256sum` in your `$PATH`.
- Out will come an `eb.bin` file. Run it with your INI: `./eb.bin $ini`

This approach will give your project a script that downloads a
_versioned variant_ of `earthbound.c`, which&mdash;in contrast to the
plain URL downloaded above&mdash;can have its integrity verified using
SHA2-256. The script also altruistically uses `curl` or `wget`, so as
long as one is available, it will work. Finally, while it tries to use
`cc` from the `$PATH`, it will prefer the value of `$CC` if it is not
empty. It will also pass `$CFLAGS` as-is to the compiler invocation.

## Architecture

Earthbound only concerns itself with what we will call **files of
interest**. These are files, often source code, that may come in from
anywhere over the network, that were selected by the downstream
developer to contain in good faith the data they need. Earthbound keeps
hashes of these files of interest and uses them to verify the
files&rsquo; authenticity.

Beyond acquisition, Earthbound has a know-nothing approach, giving
developers total discretion on what to do with these files after they
have been downloaded and validated. This is true to its one purpose of
software procurement, which exalts the UNIX&trade; philosophy of doing
one thing and doing it well.

### Earthbound INIs

Earthbound uses an INI file structure to define a collection of files of
interest along with their hashes and details on where they may be found.
Here is an example configuration that sources a single file from
multiple potential mirrors called `file1.c`:

```ini
# is used for comments, not ;
# must be at the start of a logical line
	 # leading space is OK though
[file1.c]
sha2sum=70d181c0bebbac369cddb65e6304e55a8efdcef50589154faf30390fdc6a1427
# at least one is required, but multiple may be given
# if so, all hashes are checked
sha3sum=4e9e5320e30e44ff31463806d5578fbfdc9212f32d2e9dd41998d0a8aaf830c9
# all of these URLs are candidates and may be tried in any order
source=https://www.example.com/file1.c
source=https://www.example.de/file.c
source=ftp://ftp.example.ch/srv/file_1.c
# sourcing files in archives uses the # symbol like DOM IDs
source=https://cdn.example.com/package.tar.gz#/subdir/file.c
```

A brief list of rules observed by these INIs (consult [the
schema](https://gist.github.com/nicholatian/05cae747b0d3a8928c85c12d65187ff3)
for a precise specification):

1. all key–value pairs must appear under a section heading (there is no
&ldquo;global section&rdquo;)
2. only ASCII is permitted, except within comments, where the high bit
may be set to passively allow UTF-8
3. all URIs must be valid UTF-8 and legalised into ASCII via
percent-encoding
4. file names are specified as the contents of the section name in whole
5. file names cannot constitute paths; no directory component is
permitted

Given an INI like the one above, Earthbound offers several benefits:

1. it will select the source URL using arbitrary algorithms which take
advantage of the lack of ordering or precedence to choose the best
download site
2. when multiple source files may download from the same URL sans the
`#` suffix, the package only needs to be downloaded once
3. a project config can cause the download of _only the files it needs_
without requiring cumbersome and error-prone post-operative scripts

### Features

For the sake of portability, Earthbound defers the heavy tasks of
downloading files and extracting archives to the user&rsquo;s system.
Here is a table of supported downloader programs, the names they are
expected to be found under in the `$PATH`, and the environment variable
Earthbound will allow them to be overridden with:

| Utility | Default | Override   |
|:-------:|:-------:|:----------:|
| curl    | `curl`  | `$EB_CURL` |
| wget    | `wget`  | `$EB_WGET` |

Here is a table of supported archive extraction tools and decompression
tools, the names they are expected to be found under in the `$PATH`, and
the environment variable Earthbound will allow them to be overridden
with:

| Utility | Default    | Override    |
|:-------:|:----------:|:-----------:|
| 7zip    | `p7zip`    | `$EB_7ZIP`  |
| GNU tar | `tar`[^1]  | `$EB_TAR`   |
| Unzip   | `unzip`    | `$EB_UNZIP` |
| Gzip    | `gz`       | `$EB_GZ`    |
| Bzip2   | `bzip2`    | `$EB_BZIP2` |
| Lzip    | `lzip`[^2] | `$EB_LZIP`  |
| Lrzip   | `lrzip`    | `$EB_LRZIP` |
| Rzip    | `rzip`     | `$EB_RZIP`  |
| Xz      | `xz`       | `$EB_XZ`    |
| LZ4     | `lz4`      | `$EB_LZ4`   |
| LZO     | `lzop`     | `$EB_LZOP`  |
| Zstd    | `zstd`     | `$EB_ZSTD`  |

[^1]: will look for `gtar` on macOS hosts, falling back to BSD `tar`.
[^2]: will prefer `plzip` with `-n $(nproc)` if available.

Earthbound expects to be compiled and run on an operating system that
complies with POSIX.1-2001. It will use methods made available by such
compliance to invoke external programs, get environment variable data
and perform file system operations.
