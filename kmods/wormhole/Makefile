#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

KMOD=	ng_wormhole
SRCS=	ng_wormhole.c

.PATH:  ${.CURDIR}/../../netgraph
CFLAGS+=-I${.CURDIR}/../..

.include "${.CURDIR}/../../Makefile.inc"
# opts_global.h will set VIMAGE

.include <bsd.kmod.mk>
