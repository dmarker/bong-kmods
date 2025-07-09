/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETGRAPH_NG_ULA4TAG_H_
#define _NETGRAPH_NG_ULA4TAG_H_

#include <sys/types.h>

/* Node type name. This should be unique among all netgraph node types */
#define NG_ULA4TAG_NODE_TYPE	"ula4tag"

#define NGM_ULA4TAG_COOKIE	202410110

/* Hook names */
#define NG_ULA4TAG_HOOK_UNTAG	"untag"
#define NG_ULA4TAG_HOOK_TAG	"tag"

/* Netgraph commands understood by this node type */
enum {
	NGM_ULA4TAG_GET_CONFIG = 1,	/* get tag numbers for ULA and IPv4 */
	NGM_ULA4TAG_SET_CONFIG,		/* set same */
	NGM_ULA4TAG_GET_STATS,		/* get current counters */
	NGM_ULA4TAG_CLR_STATS,		/* clear current counters */
};

/* We may eventually let you tag GUA traffic */
struct ng_ula4tag_config {
	uint16_t	ulatag;
	uint16_t	ip4tag;
};

/*
 * This needs to be kept in sync with the above structure definition
 */
#define NG_ULA4TAG_CONFIG_TYPE_INFO	{		\
	{ "ulatag",	&ng_parse_uint16_type	},	\
	{ "ip4tag",	&ng_parse_uint16_type	},	\
	{ NULL }					\
}

/*
 * This is unfortunate trickery but we do need to define the same struct twice
 * (once here with uint64_t, once in ng_ula4tag.c with counter_u64_t) and we need
 * to make it possible to define alloc, clear, free later.
 * When you use it, it calls your first macro with "field name" followed by any
 * arguments you want to pass along. The variadic macro makes it nicer than old
 * way of passing fixed number of arg1, arg2, etc.
 */
#define NG_ULA4TAG_STATS_FIELDS(NG_ULA4TAG_FLD, ...)	\
	NG_ULA4TAG_FLD(notpkthdr, __VA_ARGS__)		\
	NG_ULA4TAG_FLD(nobufs,    __VA_ARGS__)		\
	NG_ULA4TAG_FLD(etypevlan, __VA_ARGS__)		\
	NG_ULA4TAG_FLD(dropvid,   __VA_ARGS__)		\
	NG_ULA4TAG_FLD(unkvid,    __VA_ARGS__)		\
	NG_ULA4TAG_FLD(tag_4,     __VA_ARGS__)		\
	NG_ULA4TAG_FLD(tag_ula,   __VA_ARGS__)		\
	NG_ULA4TAG_FLD(bad6addr,  __VA_ARGS__)		\
	NG_ULA4TAG_FLD(unketh,    __VA_ARGS__)


/* this is returned for NGM_ULA4TAG_GET_STATS and must be public */
#define NG_ULA4TAG_STATS_DECL_STRUCT(fname, ftype) ftype fname;
struct ng_ula4tag_stats {
	NG_ULA4TAG_STATS_FIELDS(NG_ULA4TAG_STATS_DECL_STRUCT, uint64_t)
};

#endif /* _NETGRAPH_NG_ULA4TAG_H_ */
