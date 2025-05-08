#!/bin/sh
##
## EARTHBOUND bootstrapper
##
## Written by Alexander Nicholi <//nich.fi/>
## Copyright (C) 2025 Aquefir Consulting LLC <//aquefir.co/>
## Released under the General Public License version 2.0
## <https://www.gnu.org/licenses/gpl-2.0.html>

# SHA2-256 digest of earthbound.c
sum=bfdc5727e55a588eb8fa8c934f728fe4216f3f22d5e9a57d7bde549bbcfa2dc1;
ver=0.0.0;

#####

echo=/bin/echo; # avoid shell builtins
command -v gecho 2>&1 >/dev/null && echo=gecho; # for macOS
command -v stdbuf 2>&1 >/dev/null && echo="stdbuf -o0 ${echo}";
rm=rm;
command -v grm 2>&1 >/dev/null && rm=grm;

if test "$CC" = '' && ! command -v cc 2>&1 >/dev/null; then
	$echo "An ANSI C compiler under the name 'cc' is required to be";
	$echo 'available in the $PATH to bootstrap Earthbound.';
	$echo 'Alternatively, one may be provided under the environment';
	$echo 'variable $CC.';
	exit 2;
fi

if ! command -v shasum 2>&1 >/dev/null && ! command -v sha256sum 2>&1 \
>/dev/null && test "$SKIP_CHECKSUM" = ''; then
	$echo 'For security, Earthbound bootstrapping requires a SHA-2';
	$echo 'checksumming utility, either shasum or sha256sum, to ensure';
	$echo 'the source code has not been tampered with.';
	exit 3;
fi

command -v shasum 2>&1 >/dev/null && sha256='shasum -a 256';
command -v sha256sum 2>&1 >/dev/null && sha256='sha256sum';

test "$1" = '-q' && echo="${echo} >/dev/null";
test "$1" = '--quiet' && echo="${echo} >/dev/null";

test "$CC" = '' && CC=cc;

if command -v curl 2>&1 >/dev/null; then
	cmd='curl -fsSL';
elif command -v wget 2>&1 >/dev/null; then
	cmd='wget -qO- -UwUget';
else
	${echo} 'Either curl or wget is required to bootstrap Earthbound.';
	exit 1;
fi

test -f earthbound.c && $rm earthbound.c;
$cmd tohoku.ac/earthbound-$ver.c > earthbound.c;
if test "$SKIP_CHECKSUM" != '' || test "$sha256" != ''; then
	test "$($sha256 -b --quiet earthbound.c)" != "$sum" && {
		$echo 'WARNING!';
		$echo 'The SHA2-256 digest for earthbound.c did not match!';
		$echo 'Bailing out for safety...';
		$rm earthbound.c;
		exit 4;
	};
fi
$CC $CFLAGS -oeb.bin earthbound.c;
$echo 'Earthbound bootstrapped to "./eb.bin".';
