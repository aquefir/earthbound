#!/usr/bin/env make
########################################################################
##                             Earthbound                             ##
##                                                                    ##
##             Copyright (C) 2025 Aquefir Consulting LLC.             ##
##         Released under General Public License, version 2.0         ##
########################################################################

.PHONY: all boot code checksum test clean
.SUFFIXES:

ifeq ($(ver),)
ver := $(shell git rev-parse --short HEAD)
endif

sha256 := $(shell command -v shasum 2>&1 >/dev/null && \
	echo 'shasum -a 256' || echo 'sha256sum --quiet')
suffix := $(shell command -v shasum 2>&1 >/dev/null && \
	echo '| awk '"'"'{print $$1}'"'" || echo '')

BOOT_INS := \
	src/boot1.sh

CODE_INS := \
	src/eb1.c

BOOT_OUT := earthbound.sh
CODE_OUT := earthbound-$(ver).c
CHECKSUM := $(CODE_OUT).sha256sum

MINI_IN     := etc/test.c
MINI_OUT    := etc/test2.c
MINI_INSZ   := 942
MINI_OUTSZ  := 413
MINI_OUTSUM := \
	f4b7131665c74c26ed4bc12eff7c3d8df108956ca42660d28363f82a121c1cb9

all: boot code checksum test

$(MINI_OUT): $(MINI_IN)
	@cat $< | util/cminify.py > $@

$(BOOT_OUT): $(BOOT_INS)
	@cat $^ > $@

ifeq ($(NOMINIFY),)
$(CODE_OUT): $(CODE_INS)
	@cat $^ | util/cminify.py > $@
else
$(CODE_OUT): $(CODE_INS)
	@cat $^ > $@
endif

$(CHECKSUM): $(CODE_OUT)
	@$(sha256) -b $< $(suffix) > $@

boot: $(BOOT_OUT) $(CHECKSUM)
	@sed 's/@CHECKSUM@/'`cat $(word 2,$^)`'/g' $< > $<.new
	@mv -- $<.new $<
	@sed 's/@VERSION@/$(ver)/g' $< > $<.new
	@mv -- $<.new $<

code: $(CODE_OUT)

checksum: $(CHECKSUM)

test: $(MINI_OUT)
	@test "`wc -c $(MINI_IN) | awk '{print $$1}'`" = $(MINI_INSZ)
	@test "`wc -c $(MINI_OUT) | awk '{print $$1}'`" = $(MINI_OUTSZ)
	@test "`$(sha256) -b $(MINI_OUT) $(suffix)`" = $(MINI_OUTSUM)

clean:
	@$(RM) $(MINI_OUT)
	@$(RM) $(BOOT_OUT)
	@$(RM) $(CODE_OUT)
	@$(RM) earthbound*.c
	@$(RM) *.sha256sum
