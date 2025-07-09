/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mbuf.h>
#include <sys/counter.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

#include <netgraph/ng_ula4tag.h>

#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(
	M_NETGRAPH_ULA4TAG, "netgraph_ula4tag", "netgraph ula4tag node"
);
#else
#define M_NETGRAPH_ULA4TAG M_NETGRAPH
#endif

static ng_constructor_t	ng_ula4tag_constructor;
static ng_rcvmsg_t	ng_ula4tag_rcvmsg;
static ng_shutdown_t	ng_ula4tag_shutdown;
static ng_newhook_t	ng_ula4tag_newhook;
static ng_disconnect_t	ng_ula4tag_disconnect;

static ng_rcvdata_t	ng_ula4tag_rcvdata_tag;
static ng_rcvdata_t	ng_ula4tag_rcvdata_untag;

/* Parse type for struct ng_ula4tag_config */
static const struct ng_parse_struct_field ng_config_type_fields[]
	= NG_ULA4TAG_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_config_type = {
	&ng_parse_struct_type,
	&ng_config_type_fields
};

/* Parse type for struct ng_ula4tag_stats */
#define NG_GETSTATS_DECL_TYPE(fn, type) { #fn, type },
static const struct ng_parse_struct_field ng_stats_type_fields[] = {
	NG_ULA4TAG_STATS_FIELDS(NG_GETSTATS_DECL_TYPE, &ng_parse_uint64_type)
	{ NULL }
};
static const struct ng_parse_type ng_stats_type = {
	&ng_parse_struct_type,
	&ng_stats_type_fields
};

typedef struct ng_ula4tag_config cfg_t;

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_ula4tag_cmdlist[] = {{
	NGM_ULA4TAG_COOKIE,
	NGM_ULA4TAG_GET_CONFIG,
	"getconfig",
	NULL,
	&ng_config_type
},{
	NGM_ULA4TAG_COOKIE,
	NGM_ULA4TAG_SET_CONFIG,
	"setconfig",
	&ng_config_type,
	NULL
},{
	NGM_ULA4TAG_COOKIE,
	NGM_ULA4TAG_GET_STATS,
	"getstats",
	NULL,
	&ng_stats_type,
},{
	NGM_ULA4TAG_COOKIE,
	NGM_ULA4TAG_CLR_STATS,
	"clrstats",
	NULL,
	NULL,
},{
	0
}};

static int
ng_ula4tag_dropdata(hook_p hook, item_p item)
{
	NG_FREE_ITEM(item);
	return (ENOTCONN);
}

/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_ULA4TAG_NODE_TYPE,
	.constructor =	ng_ula4tag_constructor,
	.rcvmsg =	ng_ula4tag_rcvmsg,
	.shutdown =	ng_ula4tag_shutdown,
	.newhook =	ng_ula4tag_newhook,
	.rcvdata =	ng_ula4tag_dropdata,
	.disconnect =	ng_ula4tag_disconnect,
	.cmdlist =	ng_ula4tag_cmdlist,
};
NETGRAPH_INIT(ula4tag, &typestruct);

/*
 * kernel version of ng_ula4tag_stats
 * It doesn't actually matter that struct offsets will match ng_ula4tag_stats,
 * it matters that all field names are identical for macros.
 */
typedef struct ng_ula4tag_kstats {
	NG_ULA4TAG_STATS_FIELDS(NG_ULA4TAG_STATS_DECL_STRUCT, counter_u64_t)
} kstats_t;

/* Information we store for each node */
typedef struct ng_ula4tag_private {
	node_p		node;		/* back pointer to node */

	hook_p		untag;		/* remove before giving to ether */
	hook_p		tag;		/* add tag to data from ether */

	cfg_t		cfg;		/* ng_ula4tag_config in header */
	kstats_t	kstats;		/* kernel version of stats */
} *priv_p;

/*
 * Notice the singular comes first and the plural uses our magic macro
 * NG_ULA4TAG_STATS_FIELDS, that's the pattern. You should only call
 * the NG_PRIV_* versions of macros (the ones that require a priv_t
 * as their first argument). The other macro is just part of machinery
 * required by NG_ULA4TAG_STATS_FIELDS.
 */
#define	NG_ALLOC_STAT(fname, prv)					\
	(prv)->kstats.fname = counter_u64_alloc(M_WAITOK);
#define	NG_PRIV_ALLOC_STATS(prv)					\
	do {								\
		NG_ULA4TAG_STATS_FIELDS(NG_ALLOC_STAT, prv)		\
	} while(0)

#define	NG_GET_STAT(fname, prv, st)					\
	(st)->fname = counter_u64_fetch((prv)->kstats.fname);
#define	NG_PRIV_GET_STATS(prv, st)					\
	do {								\
		NG_ULA4TAG_STATS_FIELDS(NG_GET_STAT, prv, st)		\
	} while(0)

#define	NG_CLR_STAT(fname, prv) counter_u64_zero((prv)->kstats.fname);
#define	NG_PRIV_CLR_STATS(prv)						\
	do {								\
		NG_ULA4TAG_STATS_FIELDS(NG_CLR_STAT, prv)		\
	} while(0)

#define	NG_FREE_STAT(fname, prv) counter_u64_free((prv)->kstats.fname);
#define	NG_PRIV_FREE_STATS(prv)						\
	do {								\
		NG_ULA4TAG_STATS_FIELDS(NG_FREE_STAT, prv)		\
	} while(0)

#define	NG_PRIV_ADD_STAT(prv, fname, v) counter_u64_add((prv)->kstats.fname, v)
#define	NG_PRIV_INC_STAT(prv, fname) NG_PRIV_ADD_STAT(prv, fname, 1)

/*
 * Allocate the private data structure. The generic node has already
 * been created. Link them together. We arrive with a reference to the node
 * i.e. the reference count is incremented for us already.
 */
static int
ng_ula4tag_constructor(node_p node)
{
	priv_p priv;

	/* Initialize private descriptor */
	priv = malloc(sizeof(*priv), M_NETGRAPH_ULA4TAG, M_WAITOK | M_ZERO);

	/* zero is "don't tag" for everything. So we start as a passthrough */
	memset(&priv->cfg, 0, sizeof(cfg_t));

	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;

	NG_PRIV_ALLOC_STATS(priv);

	return (0);
}

/*
 * This is designed to connect `tag` to an ng_ether(4)'s `lower` hook and
 * `untag` to an ng_bridge(4) `link` hook (not uplink). But user may want to
 * add tags to ULA or IPv4 traffic elsewhere so don't be picky about what is
 * allowed.
 */
static int
ng_ula4tag_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p *hookptr;

	/* use per hook rcvdata */
	if (strcmp(NG_ULA4TAG_HOOK_UNTAG, name) == 0) {
		hookptr = &priv->untag;
		NG_HOOK_SET_RCVDATA(hook, ng_ula4tag_rcvdata_untag);
	} else if (strcmp(NG_ULA4TAG_HOOK_TAG, name) == 0) {
		hookptr = &priv->tag;
		NG_HOOK_SET_RCVDATA(hook, ng_ula4tag_rcvdata_tag);
	} else
		return (EINVAL);

	if (*hookptr != NULL)
		return (EISCONN);

	*hookptr = hook;
	NG_HOOK_SET_PRIVATE(hook, NULL);

	return(0);
}

/*
 * Get a netgraph control message.
 */
static int
ng_ula4tag_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *msg, *resp = NULL;
	int error = 0;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_ULA4TAG_COOKIE:
		switch (msg->header.cmd) {
		case NGM_ULA4TAG_GET_CONFIG: {
			cfg_t *cfg;

			NG_MKRESPONSE(resp, msg, sizeof(*cfg), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			cfg = (cfg_t *) resp->data;
			*cfg = priv->cfg;	/* no sanity checking needed */
			break;
		}
		case NGM_ULA4TAG_SET_CONFIG: {
			cfg_t *cfg = (cfg_t *)msg->data;
			if (msg->header.arglen != sizeof(*cfg) ||
			    cfg->ulatag > EVL_VLID_MASK ||
			    cfg->ip4tag > EVL_VLID_MASK) {
				error = EINVAL;
				break;
			}
			priv->cfg = *cfg;
			break;
		}
		case NGM_ULA4TAG_GET_STATS: {
			struct ng_ula4tag_stats *stats;
			NG_MKRESPONSE(resp, msg, sizeof(struct ng_ula4tag_stats), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			stats = (struct ng_ula4tag_stats *)resp->data;
			NG_PRIV_GET_STATS(priv, stats);
			break;
		}
		case NGM_ULA4TAG_CLR_STATS:
			NG_PRIV_CLR_STATS(priv); /* clear all stats */
			break;
		default:
			error = EINVAL;		/* unknown command */
			break;
		}
		break;
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	/* Done */
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);
	return (error);
}


/*
 * If you set `setencap` to 0 on the vlan (which isn't documented outside bug
 * report 161908) this function has very little to do. But it is NOT the
 * default so we must examine the packet. We do need to know what the tag was
 * later and normalize this to use out of band.
 */
static __inline int
strip_vlan(priv_p priv, item_p item, uint16_t *etype, uint16_t *vid)
{
	struct mbuf *m = NGI_M(item);
	struct ether_header *eh;

	if ((m->m_flags & M_PKTHDR) == 0 || (m->m_pkthdr.len < ETHER_HDR_LEN)) {
		NG_PRIV_INC_STAT(priv, notpkthdr); /* does this happen? */
		NG_FREE_ITEM(item);
		return (EINVAL);
	}
 
	m = m_pullup(m, ETHER_HDR_LEN);
	if (m == NULL) {
		_NGI_M(item) = NULL;
		NG_FREE_ITEM(item);
		NG_PRIV_INC_STAT(priv, nobufs);
		return (ENOBUFS);
	}
	eh = mtod(m, struct ether_header *);
	*etype = ntohs(eh->ether_type);
	*vid = 0x0; /* default from GUA */

	/* If we have a VLAN tag, strip it, not even examining */
	if (*etype == ETHERTYPE_VLAN) {
		struct ether_vlan_header *evl;
		NG_PRIV_INC_STAT(priv, etypevlan); /* so you know to fix ng_vlan */
		m = m_pullup(m, ETHER_VLAN_ENCAP_LEN + ETHER_HDR_LEN);
		if (m == NULL) {
			_NGI_M(item) = NULL;
			NG_FREE_ITEM(item);
			NG_PRIV_INC_STAT(priv, nobufs);
			return (ENOBUFS);
		}
		evl = mtod(m, struct ether_vlan_header *);
		*etype = ntohs(evl->evl_proto);
		*vid = EVL_VLANOFTAG(ntohs(evl->evl_tag));
		/*
		 * Decapsulate:
		 * TPID = ether type encap
		 * Move DstMAC and SrcMAC to ETHER_TYPE.
		 * Before:
		 *  [dmac] [smac] [TPID] [PCP/CFI/VID] [ether_type] [payload]
		 *  |-----------| >>>>>>>>>>>>>>>>>>>> |--------------------|
		 * After:
		 *  [free space ] [dmac] [smac] [ether_type] [payload]
		 *                |-----------| |--------------------|
		 */
		bcopy((char *)evl, ((char *)evl + ETHER_VLAN_ENCAP_LEN),
		    (ETHER_ADDR_LEN * 2));
		m_adj(m, ETHER_VLAN_ENCAP_LEN);
	} else if (m->m_flags & M_VLANTAG) {
		*vid = EVL_VLANOFTAG(m->m_pkthdr.ether_vtag);
	}
	/* should I assert ether_type is now ETHERTYPE_IP or ETHERTYPE_IPV6 ? */
	/* clear out of band tag in case its there */
	m->m_pkthdr.ether_vtag = 0;
	m->m_flags &= ~M_VLANTAG;
	_NGI_M(item) = m;

	return (0);
}

/*
 * Tags are being put on by ng_vlan but are not needed here.
 * The good news is ng_vlan can be set (but by default is not) to just use mbuf
 * flags and pkthdr for tagging. So we can't really assume its set.
 */
static int
ng_ula4tag_rcvdata_untag(hook_p hook, item_p item)
{
	const node_p	node = NG_HOOK_NODE(hook);
	const priv_p	priv = NG_NODE_PRIVATE(node);
	int		error = 0;
	uint16_t	etype, vid;

	if ((error = strip_vlan(priv, item, &etype, &vid)))
		return (error); /* already freed item */

	/* it appears ng_vlan does allow tag of 0xFFF but for us that means drop */
	if (vid == EVL_VLID_MASK) {
		NG_PRIV_INC_STAT(priv, dropvid);
		NG_FREE_ITEM(item);
		return (0);
	}

	/*
	 * This is why we need to know VID, when it comes from `untag` it may
	 * need to be dropped because its not destined for us.
	 * XXX: I feel like ng_bridge should have learnt MAC eventualy but
	 *      we seem to get all the packets tagged for any ula4tag nodes.
	 *      using link so it should learn MAC. is there a bug?
	 */
	if (vid != 0 && vid != priv->cfg.ulatag && vid != priv->cfg.ip4tag) {
		NG_PRIV_INC_STAT(priv, unkvid);
		NG_FREE_ITEM(item);
		return (0);
	}

	NG_FWD_ITEM_HOOK(error, item, priv->tag); /* handles NULL hook */
	return (error);
}


/* This is the easy case. We removed inline VLAN and M_VLANTAG already */
static int
ng_ula4tag_rcvdata_tag4(priv_p priv, item_p item)
{
	int		error;
	struct mbuf	*m = NGI_M(item);

	if (priv->cfg.ip4tag == EVL_VLID_MASK) { /* drop */
		NG_PRIV_INC_STAT(priv, dropvid);
		NG_FREE_ITEM(item);
		return (0);
	}

	if ((m->m_pkthdr.ether_vtag = priv->cfg.ip4tag)) {
		NG_PRIV_INC_STAT(priv, tag_4);
		m->m_flags |= M_VLANTAG;
	}

	NG_FWD_ITEM_HOOK(error, item, priv->untag);
	return (error);
}

/*
 * We know that we have a standard ether_header followed by ip6_hdr
 * because we stripped out any vlan and only process
 *
 * NOTE: this code is written assuming we may want to tag GUA in future.
 */
static int
ng_ula4tag_rcvdata_tag6(priv_p priv, item_p item)
{
	struct mbuf	*m = NGI_M(item); /* NGI_GET_M ??? */
	struct ip6_hdr	*ip6 = NULL;
	int		error;
	uint8_t		*octet;
	uint16_t	guatag = 0; /* instead of priv->cfg.guatag */
	enum {unknown = 1, tag_gua, tag_ula, tag_both } where6 = unknown;

	m = m_pullup(m, ETHER_HDR_LEN + sizeof(struct ip6_hdr));
	if (m == NULL) {
		_NGI_M(item) = NULL;
		NG_FREE_ITEM(item);
		NG_PRIV_INC_STAT(priv, nobufs);
		return (ENOBUFS);
	}
	ip6 = (struct ip6_hdr *) mtodo(m, ETHER_HDR_LEN);
	octet = &ip6->ip6_dst.s6_addr8[0];

	/* examine address to determine whow to tag packet */
	if ((*octet & 0x30) == 0x20) {
		where6 = tag_gua; /* GUA are 2000::/3 */
	} else if (*octet == 0xFF) {
		where6 = tag_both; /* multicast are FF00::/8 */
	} else if (*octet == 0xFE) {
		octet++;
		if ((*octet & 0xC0) == 0x80) {
			where6 = tag_both; /* link local are FE80::/10 */
		}
	} else if ((*octet & 0xFC) == 0xFC) {
		where6 = tag_ula; /* ULA are FC00::/7 */
	}

	switch (where6) {
	case tag_gua:
		if ((m->m_pkthdr.ether_vtag = guatag))
			m->m_flags |= M_VLANTAG;
		NG_FWD_ITEM_HOOK(error, item, priv->untag);
		return (error);
	case tag_ula:
		if ((m->m_pkthdr.ether_vtag = priv->cfg.ulatag)) {
			m->m_flags |= M_VLANTAG;
			NG_PRIV_INC_STAT(priv, tag_ula);
		}
		NG_FWD_ITEM_HOOK(error, item, priv->untag);
		return (error);
	case tag_both:
		/* MAY send 2 packets with different tags */
		if (guatag != priv->cfg.ulatag) {
			struct mbuf *m2 = m_dup(m, M_NOWAIT);
			if (m2 == NULL) {
				NG_FREE_ITEM(item);
				NG_PRIV_INC_STAT(priv, nobufs);
				return (ENOBUFS);
			}
			/* for now guatag is always 0 */
			if ((m2->m_pkthdr.ether_vtag = guatag))
				m2->m_flags |= M_VLANTAG;
			NG_SEND_DATA_ONLY(error, priv->untag, m2);
		}

		if ((m->m_pkthdr.ether_vtag = priv->cfg.ulatag)) {
			m->m_flags |= M_VLANTAG;
			NG_PRIV_INC_STAT(priv, tag_ula);
		}
		NG_FWD_ITEM_HOOK(error, item, priv->untag);
		return (error);
	default:
		NG_FREE_ITEM(item);
		NG_PRIV_INC_STAT(priv, bad6addr);
		return (EINVAL);
	}
}

/*
 * Normalize and split off depending on whether it is IPv4 or IPv6
 */
static int
ng_ula4tag_rcvdata_tag(hook_p hook, item_p item)
{
	const node_p	node = NG_HOOK_NODE(hook);
	const priv_p	priv = NG_NODE_PRIVATE(node);
	int		error;
	uint16_t	etype, vid;

	if ((error = strip_vlan(priv, item, &etype, &vid)))
		return (error);

	switch (etype) {
	case ETHERTYPE_ARP:
		/* fallthrough only IPv4 */
	case ETHERTYPE_IP:
		return ng_ula4tag_rcvdata_tag4(priv, item);
	case ETHERTYPE_IPV6:
		return ng_ula4tag_rcvdata_tag6(priv, item);
	}

	/* Some sort of ether type we don't care about */
	NG_FREE_ITEM(item);
	NG_PRIV_INC_STAT(priv, unketh);
	//printf("unknown ethertype = 0x%02x\n", etype);
	return (EINVAL);
}

static int
ng_ula4tag_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	NG_PRIV_FREE_STATS(priv);
	free(priv, M_NETGRAPH_ULA4TAG);
	return (0);
}

/*
 * Hook disconnection
 *
 * For this type, removal of the last link destroys the node
 */
static int
ng_ula4tag_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);

	if (hook == priv->untag)
		priv->untag = NULL;
	else
		priv->tag = NULL;

	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	    && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) /* already shutting down? */
		ng_rmnode_self(NG_HOOK_NODE(hook));
	return (0);
}
