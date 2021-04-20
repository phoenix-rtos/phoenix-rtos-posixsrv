#
# Makefile for phoenix-rtos-posixsrv
#
# Copyright 2019, 2021 Phoenix Systems
#
# %LICENSE%
#

SIL ?= @
MAKEFLAGS += --no-print-directory


include ../phoenix-rtos-build/Makefile.common
include ../phoenix-rtos-build/Makefile.$(TARGET_SUFF)

CFLAGS += $(BOARD_CONFIG)


all: $(PREFIX_PROG_STRIPPED)posixsrv

$(PREFIX_PROG)posixsrv: $(addprefix $(PREFIX_O), event.o pipe.o pty.o special.o tmpfile.o posixsrv.o) $(PREFIX_A)libtty.a
	$(LINK)

.PHONY: clean
clean:
	@echo >/dev/null
