#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

# see https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=286717
.if defined(INVARIANTS)
CFLAGS+=-DINVARIANT_SUPPORT -DINVARIANTS
.endif

# surprisingly not in  opt_global.h
.if !defined(INET) || ${INET} != 0
CFLAGS += -DINET
.endif
.if !defined(INET6) || ${INET6} != 0
CFLAGS += -DINET6
.endif
