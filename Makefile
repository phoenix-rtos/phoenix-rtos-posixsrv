#
# Makefile for phoenix-rtos-posixsrv
#
# Copyright 2019, 2021 Phoenix Systems
#
# %LICENSE%
#

include ../phoenix-rtos-build/Makefile.common
include ../phoenix-rtos-build/Makefile.$(TARGET_SUFF)

CFLAGS += $(BOARD_CONFIG)

.DEFAULT_GOAL := all

ifneq ($(filter %clean,$(MAKECMDGOALS)),)
$(info cleaning targets, make parallelism disabled)
.NOTPARALLEL:
endif

# single component in this whole repo
NAME := posixsrv
SRCS := $(wildcard *.c)
LIBS := libtty
include $(binary.mk)

DEFAULT_COMPONENTS := posixsrv

# create generic targets
.PHONY: all install clean
all: $(DEFAULT_COMPONENTS)
install: $(patsubst %,%-install,$(DEFAULT_COMPONENTS))
clean: $(patsubst %,%-clean,$(DEFAULT_COMPONENTS))
