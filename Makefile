#
# Makefile for phoenix-rtos-devices
#
# Copyright 2018 Phoenix Systems
#
# %LICENSE%
#

SIL ?= @

#TARGET ?= ia32-qemu
#TARGET ?= armv7-stm32
TARGET ?= arm-imx

BUILD_DIR ?= build/$(TARGET)
BUILD_DIR := $(abspath $(BUILD_DIR))

# Compliation options for various architectures
TARGET_FAMILY = $(firstword $(subst -, ,$(TARGET)-))
include Makefile.$(TARGET_FAMILY)

SOURCES = $(wildcard src/*.c)

DEVICES = ../phoenix-rtos-devices/build/$(TARGET)

CFLAGS += -I./include -I$(DEVICES)/include
LDFLAGS += -L$(DEVICES)/lib -ltty

all:
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS)  $(SOURCES) -o $(BUILD_DIR)/posixsrv_unstripped  $(LDFLAGS)
	$(STRIP) $(BUILD_DIR)/posixsrv_unstripped -o $(BUILD_DIR)/posixsrv


clean:
	$(SIL)rm -rf build/*

.PHONY: clean
