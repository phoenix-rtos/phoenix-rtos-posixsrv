#
# Makefile for phoenix-rtos-posixsrv
#
# Copyright 2019, 2021 Phoenix Systems
#
# %LICENSE%
#

include ../phoenix-rtos-build/Makefile.common

.DEFAULT_GOAL := all

# single component in this whole repo
NAME := posixsrv
SRCS := $(wildcard *.c)
LIBS := libtty
include $(binary.mk)

ALL_COMPONENTS := posixsrv
DEFAULT_COMPONENTS := $(ALL_COMPONENTS)

# create generic targets
.PHONY: all install clean
all: $(DEFAULT_COMPONENTS)
install: $(patsubst %,%-install,$(DEFAULT_COMPONENTS))
clean: $(patsubst %,%-clean,$(ALL_COMPONENTS))
