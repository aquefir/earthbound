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

## Usage

Earthbound is a tool for procuring software from yonder (typically, the
Worldwide Web). To this end, it ingests an INI file bearing out what
software it should procure and from where. A
[schema](https://gist.github.com/nicholatian/05cae747b0d3a8928c85c12d65187ff3)
for validating Earthbound INI files is provided in the repository under
the canonical name `schema.inf`.

Assuming the downstream project has such an INI, Earthbound can then be
invoked from the Web with `wget` or `curl`:

```sh
curl -fsSL tohoku.ac/earthbound.c | cc -oeb.bin -
./eb.bin # flags and options...
```

A robust script for securely and portably doing this is provided in the
repository under the name `earthbound.sh`. It auto-selects `curl` or
`wget`, respects `$CC` and `$CFLAGS`, and most importantly does a
SHA2-256 checksum on a _versioned variant_ of the downloaded source file
before compiling it.
