#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

# see https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=286717
.if defined(INVARIANTS)
CFLAGS+=-DINVARIANT_SUPPORT -DINVARIANTS
.endif
