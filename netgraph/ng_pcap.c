/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/errno.h>

#include <net/ethernet.h>

#include <netgraph/ng_parse.h>
#include <netgraph/ng_pcap.h>
#include <netgraph/netgraph.h>

#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(M_NETGRAPH_PCAP, "netgraph_pcap", "netgraph pcap node");
#else
#define M_NETGRAPH_PCAP M_NETGRAPH
#endif

#define	ETHER_VLAN_HDR_LEN (ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN)
#define	VLAN_TAG_MASK	0xFFFF

static int		ng_pcap_mod_event(module_t, int, void *);
static ng_constructor_t	ng_pcap_constructor;
static ng_rcvmsg_t	ng_pcap_rcvmsg;
static ng_shutdown_t	ng_pcap_shutdown;
static ng_newhook_t	ng_pcap_newhook;
static ng_rcvdata_t	ng_pcap_rcvdata_ether;
#ifdef INET
static ng_rcvdata_t	ng_pcap_rcvdata_inet4;
#endif
#ifdef INET6
static ng_rcvdata_t	ng_pcap_rcvdata_inet6;
#endif
static ng_disconnect_t	ng_pcap_disconnect;

/* Parse type for struct ng_bridge_config */
static const struct ng_parse_struct_field ng_pcap_config_type_fields[]
	= NG_PCAP_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_pcap_config_type = {
	&ng_parse_struct_type,
	&ng_pcap_config_type_fields
};

/* Parse type for 'packet_type' field in ng_pcap_set_source_type.
 * Also return this type for get "getsourcetype".
 */
static const struct ng_parse_fixedstring_info ng_pcap_packet_type_info
	= { NG_PCAP_PKT_TYPE_LENGTH };
static const struct ng_parse_type ng_pcap_packet_type_type = {
	&ng_parse_fixedstring_type,
	&ng_pcap_packet_type_info
};

/* Parse type for struct ng_pcap_source_type. */
static const struct ng_parse_struct_field ng_pcap_set_source_type_fields[]
	= NG_PCAP_SET_SOURCE_TYPE_FIELDS(&ng_pcap_packet_type_type);
static const struct ng_parse_type ng_pcap_set_source_type_type = {
	&ng_parse_struct_type,
	&ng_pcap_set_source_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_pcap_cmdlist[] = {{
	NGM_PCAP_COOKIE,
	NGM_PCAP_GET_CONFIG,
	"getconfig",
	NULL,
	&ng_pcap_config_type,
},{
	NGM_PCAP_COOKIE,
	NGM_PCAP_SET_CONFIG,
	"setconfig",
	&ng_pcap_config_type,
	NULL
},{
	NGM_PCAP_COOKIE,
	NGM_PCAP_GET_SOURCE_TYPE,
	"getsourcetype",
	&ng_parse_hookbuf_type,
	&ng_pcap_packet_type_type
},{
	NGM_PCAP_COOKIE,
	NGM_PCAP_SET_SOURCE_TYPE,
	"setsourcetype",
	&ng_pcap_set_source_type_type,
	NULL
},{
	0
}};

typedef struct ng_pcap_config cfg_t;

/* module level globals */
static struct {
	const char * const unset;
	const char * const ether;
	const char * const inet4;
	const char * const inet6;
	struct {
		const struct ether_header *inet4;
		const struct ether_header *inet6;
	} ethhdr;
	struct {
		const char * const	prefix;
		const size_t		len;
	} link_pfxs[2];
} G = {
	.unset = HOOK_PKT_UNSET,
	.ether = HOOK_PKT_ETHER,
	.inet4 = HOOK_PKT_INET4,
	.inet6 = HOOK_PKT_INET6,
	.ethhdr = { NULL, NULL }, /* modinit fills in */
	.link_pfxs = {{
		.prefix = NG_PCAP_HOOK_SOURCE,
		.len = sizeof(NG_PCAP_HOOK_SOURCE) - 1
	},{
		.prefix = NG_PCAP_HOOK_SNOOP,
		.len = sizeof(NG_PCAP_HOOK_SNOOP) - 1
	}},
};

static __inline const char * const
hook2type(hook_p hook)
{
	if (hook->hk_rcvdata == NULL)
		return (G.unset);
	if (hook->hk_rcvdata == ng_pcap_rcvdata_ether)
		return (G.ether);
#	ifdef INET
	if (hook->hk_rcvdata == ng_pcap_rcvdata_inet4)
		return (G.inet4);
#	endif
#	ifdef INET6
	if (hook->hk_rcvdata == ng_pcap_rcvdata_inet6)
		return (G.inet6);
#	endif
	return (NULL);
}


static __inline ng_rcvdata_t *
type2rcvdata(const char * const pkt_string)
{
	if (strncmp(G.ether, pkt_string, NG_PCAP_PKT_TYPE_LENGTH) == 0)
		return (ng_pcap_rcvdata_ether);
#	ifdef INET
	if (strncmp(G.inet4, pkt_string, NG_PCAP_PKT_TYPE_LENGTH) == 0)
		return (ng_pcap_rcvdata_inet4);
#	endif
#	ifdef INET6
	if (strncmp(G.inet6, pkt_string, NG_PCAP_PKT_TYPE_LENGTH) == 0)
		return (ng_pcap_rcvdata_inet6);
#	endif
	return (NULL);
}

enum pfx_idx {
	PFX_ERR = -1,
	PFX_SRC,
	PFX_SNOOP,
};

static __inline enum pfx_idx
prefix2index(const char *name)
{
	enum pfx_idx idx = PFX_SRC;

	MPASS(name != NULL);

	while (idx <= PFX_SNOOP) {
		int rc = strncmp(
			G.link_pfxs[idx].prefix, name, G.link_pfxs[idx].len
		);
		if (rc == 0)
			return (idx);
		idx++;
	}
	return (PFX_ERR); /* not found */
}


/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_PCAP_NODE_TYPE,
	.mod_event=	ng_pcap_mod_event,
	.constructor =	ng_pcap_constructor,
	.rcvmsg =	ng_pcap_rcvmsg,
	.shutdown =	ng_pcap_shutdown,
	.newhook =	ng_pcap_newhook,
	.disconnect =	ng_pcap_disconnect,
	.cmdlist =	ng_pcap_cmdlist,
};
NETGRAPH_INIT(pcap, &typestruct);

/* Information we store for each node */
struct ng_pcap_priv {
	node_p			node;
	hook_p			snoop;
	hook_p			many[NG_PCAP_MAX_LINKS];
	cfg_t			cfg;
};
typedef struct ng_pcap_priv *priv_p;


static int
ng_pcap_constructor(node_p node)
{
	priv_p priv = malloc(sizeof(*priv), M_NETGRAPH_PCAP, M_WAITOK | M_ZERO);

	priv->node = node;
	NG_NODE_SET_PRIVATE(node, priv);
	priv->cfg.snaplen = NG_PACP_MAX_SNAPLEN;

	return (0);
}

/*
 * Users can request `snoop` or any `source<N>` for an unused N.
 * We don't have to check that, the netgraph(4) machinery already disallows
 * duplicate hook names.
 *
 * But we are going to enforce that N be in range [0, NG_PCAP_MAX_LINKS).
 */
static int
ng_pcap_newhook(node_p node, hook_p hook, const char *name)
{
	int rc = 0;
	const priv_p priv = NG_NODE_PRIVATE(node);
	enum pfx_idx idx = prefix2index(name);

	switch (idx) {
	case PFX_ERR:	/* is it a valid prefix */
		rc = EINVAL;
		break;
	case PFX_SNOOP:
		if (priv->snoop != NULL)
			rc = EISCONN;
		else
			priv->snoop = hook;
		break;
	case PFX_SRC: {
		const size_t	 len = G.link_pfxs[idx].len;
		char		*ep;
		uint32_t	 midx;

		midx = strtoul((name + len), &ep, 10);
		if (*ep)
			return (EINVAL);

		if (midx >= NG_PCAP_MAX_LINKS)
			return (EOVERFLOW);

		/* should not be possible, as dup names disallowed */
		MPASS(priv->many[midx] == NULL);

		priv->many[midx] = hook;
		NG_HOOK_SET_PRIVATE(hook, (void *)(uintptr_t)midx);

		break;
	}}

	return (rc);
}

static int
ng_pcap_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_PCAP_COOKIE:
		switch (msg->header.cmd) {
		case NGM_PCAP_GET_CONFIG: {
			cfg_t *cfg;

			NG_MKRESPONSE(resp, msg, sizeof(*cfg), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			cfg = (cfg_t *) resp->data;

			*cfg = priv->cfg;
			break;
		}
		case NGM_PCAP_SET_CONFIG: {
			cfg_t *cfg;

			if (msg->header.arglen != sizeof(*cfg)) {
				error = EINVAL;
				break;
			}
			cfg = (cfg_t *) msg->data;

			if (cfg->snaplen > NG_PACP_MAX_SNAPLEN ||
			    cfg->snaplen < NG_PACP_MIN_SNAPLEN) {
				error = EINVAL;
				break;
			}
			
			priv->cfg = *cfg;
			break;
		}
		case NGM_PCAP_GET_SOURCE_TYPE: {
			hook_p hook;

			if (msg->header.arglen != NG_HOOKSIZ) {
				error = EINVAL;
				break;
			}

			hook = ng_findhook(node, (char *)msg->data);
			if (hook == NULL) {
				error = ENOENT;
				break;
			} else {
				const char * const pkt_type = hook2type(hook);

				MPASS(pkt_type != NULL);

				NG_MKRESPONSE(resp, msg,
				    NG_PCAP_PKT_TYPE_LENGTH, M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}

				strncpy(resp->data, pkt_type,
				    NG_PCAP_PKT_TYPE_LENGTH);
				resp->data[NG_PCAP_PKT_TYPE_LENGTH - 1] = '\0';
			}
			break;
		}
		case NGM_PCAP_SET_SOURCE_TYPE: {
			hook_p hook;
			struct ng_pcap_set_source_type *st;

			if (msg->header.arglen != sizeof(*st)) {
				error = EINVAL;
				break;
			}
			st = (struct ng_pcap_set_source_type *)msg->data;

			hook = ng_findhook(node, st->hook_name);
			if (hook == NULL) {
				error = ENOENT;
				break;
			} else {
				ng_rcvdata_t	*rcvdata = type2rcvdata(
					st->packet_type
				);
				if (rcvdata == NULL) {
					error = EINVAL;
					break;
				} else {
					NG_HOOK_SET_RCVDATA(hook, rcvdata);
				}
			}
			break;
		}
		default:
			error = EINVAL;		/* unknown command */
			break;
		}
		break;
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	/* Take care of synchronous response, if any */
	NG_RESPOND_MSG(error, node, item, resp);
	/* Free the message and return */
	NG_FREE_MSG(msg);
	return(error);
}


/* lifted unmodified from ng_vlan(4) */
static __inline int
m_chk(struct mbuf **mp, int len)
{
	if ((*mp)->m_pkthdr.len < len) {
		m_freem((*mp));
		(*mp) = NULL;
		return (EINVAL);
	}
	if ((*mp)->m_len < len && ((*mp) = m_pullup((*mp), len)) == NULL)
		return (ENOBUFS);

	return (0);
}

/*
 * In addition to adding the pcap header we need to check mbuf for a VLAN tag.
 * If present we need to put it back into the data.
 */
static int
ng_pcap_rcvdata_ether(hook_p hook, item_p item)
{
	const node_p	node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct mbuf *m;
	struct pcap_pkthdr hdr, *phdr = NULL;
	int error = 0;
	struct timeval timestamp;
	int32_t trim;

	NGI_GET_M(item, m);

	M_ASSERTPKTHDR(m); /* maybe just return error */

	if ((m->m_flags & M_VLANTAG) == 0) { /* easy case */
		M_PREPEND(m, sizeof(*phdr), M_NOWAIT);
		if (m == NULL)
			error = ENOMEM;
		else
			error = m_chk(&m, sizeof(*phdr));
		if (error != 0) {
			NG_FREE_ITEM(item);
			return (error);
		}
	} else {
		struct ether_vlan_header *evl;

		M_PREPEND(m, sizeof(*phdr) + ETHER_VLAN_ENCAP_LEN, M_NOWAIT);
		if (m == NULL)
			error = ENOMEM;
		else
			error = m_chk(&m, sizeof(*phdr) + ETHER_VLAN_HDR_LEN);
		if (error != 0) {
			NG_FREE_ITEM(item);
			return (error);
		}

		/* similar to ng_vlan */
		evl = (struct ether_vlan_header *) mtodo(m, sizeof(*phdr));

		/* evl_dhost and evl_shost */
		bcopy(((char *)evl + ETHER_VLAN_ENCAP_LEN),
		    (char *)evl, (ETHER_ADDR_LEN * 2));

		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = htons(m->m_pkthdr.ether_vtag);
		m->m_pkthdr.ether_vtag = 0;
		m->m_flags &= ~M_VLANTAG;

	}

	/* vlan tag counts, but pcap_pkthdr does not */
	hdr.len = (uint32_t)m->m_pkthdr.len - (uint32_t)sizeof(*phdr); /* pre m_adj */

	/* make sure we don't exceed snaplen */
	trim = priv->cfg.snaplen - hdr.len;
	if (trim < 0)
		m_adj(m, trim);

	hdr.caplen = (uint32_t)m->m_pkthdr.len - sizeof(*phdr); /* post m_adj */
	microtime(&timestamp);
	hdr.tv_sec = timestamp.tv_sec;
	hdr.tv_usec = timestamp.tv_usec;

	phdr = mtod(m, struct pcap_pkthdr *);
	*phdr = hdr;

	/* nope it is 16 bytes not 8 */
	//printf("sizeof(struct timeva) = %lu\n", sizeof(struct timeval));
	//printf("pkt: caplen=%d, len=%d\n", hdr.caplen, hdr.len);
	//printf("pktx: caplen=%d, len=%d\n", phdr->caplen, phdr->len);

	NG_FWD_NEW_DATA_FLAGS(error, item, priv->snoop, m, HK_QUEUE);
	return (error);
}


#if defined(INET) || defined(INET6)
/*
 * This adds 2 things: pcap header and a fake ethernet header.
 * In addition to potential confusion (why we chose obvious MAC addrs), we lose
 * ETHER_ADDR_LEN bytes of capture when packets exceed snaplen. That is just how
 * tcpdump wants it calculated, for whole record after the `struct pcap_pkthdr`.
 * Six bytes is a small trade to be able to have both my level 2 and level3
 * together in a single capture.
 */
static int
ng_pcap_rcvdata_inet(hook_p hook, item_p item, const struct ether_header *eh)
{
	const node_p		node = NG_HOOK_NODE(hook);
	const priv_p		priv = NG_NODE_PRIVATE(node);
	struct mbuf		*m;
	struct pcap_pkthdr	hdr, *phdr = NULL;
	struct timeval		timestamp;
	int			error = 0;
	int32_t			trim;

	NGI_GET_M(item, m);

	M_ASSERTPKTHDR(m); /* maybe just return error */

	M_PREPEND(m, sizeof(*phdr) + ETHER_HDR_LEN, M_NOWAIT);
	if (m == NULL)
		error = ENOMEM;
	else
		error = m_chk(&m, sizeof(*phdr) + ETHER_HDR_LEN);
	if (error != 0) {
		NG_FREE_ITEM(item);
		return (error);
	}

	hdr.len = (uint32_t)m->m_pkthdr.len - (uint32_t)sizeof(*phdr); /* pre m_adj */

	/* make sure we don't exceed snaplen */
	trim = ((int32_t)priv->cfg.snaplen) -  m->m_pkthdr.len;
	if (trim < 0)
		m_adj(m, trim);

	hdr.caplen = (uint32_t)m->m_pkthdr.len - sizeof(*phdr); /* post m_adj */
	microtime(&timestamp);
	hdr.tv_sec = timestamp.tv_sec;
	hdr.tv_usec = timestamp.tv_usec;

	phdr = mtod(m, struct pcap_pkthdr *);
	*phdr = hdr;

	memcpy(mtodo(m, sizeof(*phdr)), eh, sizeof(*eh));

	NG_FWD_NEW_DATA_FLAGS(error, item, priv->snoop, m, HK_QUEUE);
	return (error);
}
#endif

#ifdef INET
/*
 * Require some fake MAC addresses since the layer 3 (inet4|inet6) connections
 * are without them. These need to be:
 *	+ obviously fake
 *	+ locally administered (in case they didn't notice fake)
 *	+ not drawn from FreeBSD OUI (which isn't LLA anyway)
 *
 * Open to better suggestions!
 * XXX will these show up right big-endian? Prolly not...
 */
static int
ng_pcap_rcvdata_inet4(hook_p hook, item_p item)
{
	return (ng_pcap_rcvdata_inet(hook, item, G.ethhdr.inet4));
}
#endif

#ifdef INET6
static int
ng_pcap_rcvdata_inet6(hook_p hook, item_p item)
{
	return (ng_pcap_rcvdata_inet(hook, item, G.ethhdr.inet6));
}
#endif


static int
ng_pcap_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);

	free(priv, M_NETGRAPH_PCAP);

	return (0);
}

/*
 * Hook disconnection
 *
 * For this type, removal of the `snoop` link destroys the node. That is not
 * standard, but there is a reason. We have a utility, ngpcap(8) that creates
 * ng_pcap(4) nodes and if it is killed for any reason we lose our `snoop` hook.
 * If that happens (kill -9 or something worse) we want this node to go away.
 * You probably hooked up to a bunch of ng_tee(4) anyway which will gracefully
 * continue handle ng_pcap disappearing. Then you could easily reconnect by
 * restarting ngpcap(8).
 *
 * ng_lmi(4) does a shutdown when any link (except "debug") is removed. So not
 * totally unprecedented.
 */
static int
ng_pcap_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);

	if (hook != priv->snoop) {
		uint32_t midx = (uintptr_t)NG_HOOK_PRIVATE(hook);

		NG_HOOK_SET_PRIVATE(hook, NULL);
		priv->many[midx] = NULL;
		return (0);
	}

	priv->snoop = NULL;
	if (NG_NODE_IS_VALID(node))
		ng_rmnode_self(node);

	return (0);
}

static int
ng_pcap_mod_event(module_t mod, int event, void *data)
{
	int error = 0;


	switch (event) {
	case MOD_LOAD: {
		/* decafbabbled and decafbabbles */
		static struct ether_header eh4 = {
			.ether_dhost = {0xDE,0xCA,0xFB,0xAB,0xB1,0xED},
			.ether_shost = {0xDE,0xCA,0xFB,0xAB,0xB1,0xE5},
			.ether_type = htons(ETHERTYPE_IP)
		};
		G.ethhdr.inet4 = &eh4;
		static struct ether_header eh6 = {
			.ether_dhost = {0xDE,0xCA,0xFB,0xAB,0xB1,0xED},
			.ether_shost = {0xDE,0xCA,0xFB,0xAB,0xB1,0xE5},
			.ether_type = htons(ETHERTYPE_IPV6)
		};
		G.ethhdr.inet6 = &eh6;
		break;
	}
	case MOD_UNLOAD:
		break;
	default:
		error = EOPNOTSUPP;
	}

	return (error);
}
