#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

SUBDIR=	\
	man4 \
	netgraph \
	kmods/pcap \
	kmods/ula4tag \
	kmods/wormhole

.include <bsd.arch.inc.mk>

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
