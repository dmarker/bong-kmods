/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETGRAPH_NG_WORMHOLE_H_
#define _NETGRAPH_NG_WORMHOLE_H_

#define NG_WORMHOLE_NODE_TYPE	"wormhole"
#define NGM_WORMHOLE_COOKIE	1742462349

/* this is what user connects to */
#define NG_WORMHOLE_HOOK	"evthorizon"

/* Netgraph commands understood by this node type */
enum {
	NGM_WORMHOLE_OPEN = 1,
};

#endif /* _NETGRAPH_NG_WORMHOLE_H_ */
