#
# Makefile for posixsrv unit tests
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

# posixsrv is not built on host
ifneq ($(TARGET_FAMILY), host)

NAME := test-rqtimeout
LOCAL_SRCS := test_rqtimeout.c
LOCAL_HEADERS_DIR := nothing
LIBS := unity

include $(test-binary.mk)

endif
