#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

KMOD=	ng_pcap
SRCS=	ng_pcap.c

SRCS+=	opt_inet.h
SRCS+=	opt_inet6.h

.PATH:  ${.CURDIR}/../../netgraph
CFLAGS+=-I${.CURDIR}/../..

.include "${.CURDIR}/../../Makefile.inc"

.include <bsd.kmod.mk>
