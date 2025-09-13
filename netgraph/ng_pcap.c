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

static int		ng_pcap_mod_event(module_t, int, void *);
static ng_constructor_t	ng_pcap_constructor;
static ng_rcvmsg_t	ng_pcap_rcvmsg;
static ng_shutdown_t	ng_pcap_shutdown;
static ng_newhook_t	ng_pcap_newhook;
static ng_connect_t	ng_pcap_connect;
static ng_rcvdata_t	ng_pcap_rcvdata;
static ng_rcvdata_t	ng_pcap_rcvdata_ether;
#ifdef INET
static ng_rcvdata_t	ng_pcap_rcvdata_inet4;
#endif
#ifdef INET6
static ng_rcvdata_t	ng_pcap_rcvdata_inet6;
#endif
static ng_disconnect_t	ng_pcap_disconnect;

/* Parse type for struct ng_bridge_config */
static const struct ng_parse_struct_field ng_config_type_fields[]
	= NG_PCAP_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_config_type = {
	&ng_parse_struct_type,
	&ng_config_type_fields
};

/* Parse type for 'type' field in ng_pcap_set_source_type.
 * Also return this type for get "getsourcetype".
 */
static const struct ng_parse_fixedstring_info ng_packet_type_info
	= { NG_PCAP_PKT_TYPE_LENGTH };
static const struct ng_parse_type ng_packet_type = {
	&ng_parse_fixedstring_type,
	&ng_packet_type_info
};

/* Parse type for struct ng_pcap_source_type. */
static const struct ng_parse_struct_field ng_set_source_type_fields[]
	= NG_PCAP_SET_SOURCE_TYPE_FIELDS(&ng_packet_type);
static const struct ng_parse_type ng_set_source_type = {
	&ng_parse_struct_type,
	&ng_set_source_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_pcap_cmdlist[] = {{
	NGM_PCAP_COOKIE,
	NGM_PCAP_GET_CONFIG,
	"getconfig",
	NULL,
	&ng_config_type,
},{
	NGM_PCAP_COOKIE,
	NGM_PCAP_SET_CONFIG,
	"setconfig",
	&ng_config_type,
	NULL
},{
	NGM_PCAP_COOKIE,
	NGM_PCAP_GET_SOURCE_TYPE,
	"getsourcetype",
	&ng_parse_hookbuf_type,
	&ng_packet_type
},{
	NGM_PCAP_COOKIE,
	NGM_PCAP_SET_SOURCE_TYPE,
	"setsourcetype",
	&ng_set_source_type,
	NULL
},{
	0
}};

typedef struct ng_pcap_config cfg_t;

/* pcap structures are really stable and these are for the version we use */
typedef struct {
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;	/* length of portion present */
	uint32_t len;		/* length of this packet (off wire) */
} pcap_pkthdr_t;

/* This is 24 bytes. Should easily fit in mbuf */
typedef struct {
	uint32_t	magic;
	uint16_t	major;
	uint16_t	minor;
	int32_t		thiszone;
	uint32_t	sigfigs;
	uint32_t	snaplen;
	uint32_t	linktype;
} pcap_hdr_t;

typedef struct {
	const char * const	display;
	ng_rcvdata_t*		function;
} hookmap_t;

/* module level globals */
static struct {
	struct {
		const struct ether_header *inet4;
		const struct ether_header *inet6;
	} ethhdr;
	pcap_hdr_t pcaphdr;
	hookmap_t hookmap[];
} G = {
	.ethhdr = { NULL, NULL }, /* modinit fills in */
	.pcaphdr = {
		.magic = 0xA1B2C3D4,	/* TCPDUMP_MAGIC */
		.major = 2,
		.minor = 4,
		.linktype = 0x1		/* LINKTYPE_ETHERNET */
	},
	.hookmap = {{
		.display = HOOK_PKT_UNSET,
		.function = (ng_rcvdata_t *) NULL
	},{
		.display = HOOK_PKT_ETHER,
		.function = ng_pcap_rcvdata_ether,
#ifdef INET
	},{
		.display = HOOK_PKT_INET,
		.function = ng_pcap_rcvdata_inet4,
#endif
#ifdef INET6
	},{
		.display = HOOK_PKT_INET6,
		.function = ng_pcap_rcvdata_inet6,
#endif
	},{
		.display = NULL,
		.function = (ng_rcvdata_t *) NULL
	}}
};


/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_PCAP_NODE_TYPE,
	.mod_event=	ng_pcap_mod_event,
	.constructor =	ng_pcap_constructor,
	.rcvmsg =	ng_pcap_rcvmsg,
	.shutdown =	ng_pcap_shutdown,
	.newhook =	ng_pcap_newhook,
	.connect =	ng_pcap_connect,
	.rcvdata =	ng_pcap_rcvdata,
	.disconnect =	ng_pcap_disconnect,
	.cmdlist =	ng_pcap_cmdlist,
};
NETGRAPH_INIT(pcap, &typestruct);


/* Information we store for each node. Note that the source hooks
 * are stored in node not priv.
 */
struct ng_pcap_priv {
	node_p			node;
	hook_p			snoop;
	uint32_t		seq;	/* for pkthdr sent */
	cfg_t			cfg;
};
typedef struct ng_pcap_priv *priv_p;


static int
ng_pcap_constructor(node_p node)
{
	priv_p priv = malloc(sizeof(*priv), M_NETGRAPH_PCAP, M_WAITOK | M_ZERO);

	priv->node = node;
	NG_NODE_SET_PRIVATE(node, priv);
	priv->cfg.snaplen = NG_PACP_DEFAULT_SNAPLEN;

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

	rc = strncmp(
		name, NG_PCAP_HOOK_SOURCE, sizeof(NG_PCAP_HOOK_SOURCE) - 1
	);
	if (rc == 0) {
		char		*ep;
		uint32_t	 midx;

		midx = strtoul(
			(name + sizeof(NG_PCAP_HOOK_SOURCE) - 1), &ep, 10
		);
		if (*ep)
			return (EINVAL);

		if (midx >= NG_PCAP_MAX_LINKS)
			return (EOVERFLOW);

		return (0);
	}

	rc = strcmp(name, NG_PCAP_HOOK_SNOOP);
	if (rc == 0) {
		if (priv->snoop != NULL)
			return (EISCONN);

		priv->snoop = hook;
		return (0);
	}

	return (EINVAL);
}

/*
 * At this point we have made a trip through both the pcap node queue and its
 * peer connected to snoop's queue. That means, barring an intervening
 * disconnect, we should have valid hooks. They have had their chance to become
 * valid (other side may have rejected connect) anyway.
 *
 * The check of priv->seq to exp is preventing the ABA problem.
 *
 * And finally indicate to ng_pcap_rcvdata to connect hooks rcvdata up if
 * all went well. If not we disconnect.
 */
static void
ng_pcap_filehdr2(node_p node, hook_p dummy1, void *item, int exp)
{
	int		error = 0;
	item_p		pcaphdr = item;
	const priv_p	priv = NG_NODE_PRIVATE(node);

	if (priv->snoop == NULL || priv->seq != exp) {
		/*
		 * We were disconnected (possibly even reconnected).
		 * Drop our item another one is on its way if there is
		 * going to be a reconnect.
		 */
		NG_FREE_ITEM(pcaphdr);
		return;
	}

	/*
	 * This should not be able to fail, but code changes. If it does
	 * fail the data coming out is useless so disconnect. If we are
	 * not persistent this will shut whole node down.
	 */
	NG_FWD_ITEM_HOOK_FLAGS(error, pcaphdr, priv->snoop, HK_QUEUE);
	if (error != 0)
		ng_rmhook_self(priv->snoop);
	else
		NG_HOOK_SET_PRIVATE(priv->snoop, (void *)(uintptr_t)exp);
}

/*
 * Brief stop on peer node. The point is we had to go through its queue
 * meaning we are half way to knowing both hooks should be valid. (You
 * could get a disconnect before sending the pcaphdr.)
 */
static void
ng_pcap_filehdr1(node_p node, hook_p snoop, void *pcaphdr, int exp)
{
	int rc;
	const node_p pcap = NG_HOOK_NODE(snoop);

	/* get back on pcap node by queue for same reason */
	rc = ng_send_fn1(
		pcap, NULL, &ng_pcap_filehdr2, pcaphdr, exp, NG_WAITOK | NG_QUEUE
	);
	MPASS(rc == 0);
	(void)(rc);
}

static int
ng_pcap_connect(hook_p hook)
{
	const priv_p	priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	int		rc;
	pcap_hdr_t	*hdr;
	struct mbuf	*m;
	item_p		pcaphdr;

	if (hook != priv->snoop)	/* ignore source */
		return (0);


	MGETHDR(m, M_NOWAIT, MT_DATA);
	if (m == NULL)
		return (ENOMEM);

	m->m_pkthdr.rcvif = NULL;
	m->m_pkthdr.len = m->m_len = sizeof(*hdr);

	MPASS(MHLEN > sizeof(*hdr));

	hdr = mtod(m, pcap_hdr_t *);
	*hdr = G.pcaphdr;
	hdr->snaplen = priv->cfg.snaplen; /* only value that must be changed */

	pcaphdr = ng_package_data(m, NG_NOFLAGS);
	if (pcaphdr == NULL)
		return (ENOMEM); /* already freed m */

	priv->seq++;

	/*
	 * The NG_QUEUE means that when ng_pcap_filehdr1 is called we are half
	 * way to knowing our hooks are valid.
	 */
	rc = ng_send_fn1(
		NG_PEER_NODE(priv->snoop),
		priv->snoop,
		&ng_pcap_filehdr1,
		pcaphdr,
		priv->seq,
		NG_QUEUE
	);
	if (rc != 0)
		NG_FREE_ITEM(pcaphdr);

	return (rc);
}


static int
ng_pcap_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	int		error = 0;
	const priv_p	priv = NG_NODE_PRIVATE(node);
	struct ng_mesg	*resp = NULL;
	struct ng_mesg	*msg;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_PCAP_COOKIE:
		switch (msg->header.cmd) {
		case NGM_PCAP_GET_CONFIG: {
			cfg_t	*cfg;

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
			cfg_t	*cfg;

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

			/*
			 * You can't change snaplen after the file header goes
			 * out. That is allocated on connect of snoop. So if
			 * snoop is connected we have to reject any config change.
			 */
			if (priv->snoop != NULL) {
				error = EISCONN;
				break;
			}
			
			priv->cfg = *cfg;
			break;
		}
		case NGM_PCAP_GET_SOURCE_TYPE: {
			hook_p		hook;
			hookmap_t	*iter;

			if (msg->header.arglen != NG_HOOKSIZ) {
				error = EINVAL;
				break;
			}

			hook = ng_findhook(node, (char *)msg->data);
			if (hook == NULL) {
				error = ENOENT;
				break;
			} else {
				/* hk_rcvdata is NULL until snoop connected */
				for (
					iter = &G.hookmap[0];
					iter->display != NULL &&
					iter->function != NG_HOOK_PRIVATE(hook);
					iter++
				);

				MPASS(iter->display != NULL);

				NG_MKRESPONSE(
					resp, msg, NG_PCAP_PKT_TYPE_LENGTH, M_NOWAIT
				);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}

				strncpy(
					resp->data, iter->display,
					NG_PCAP_PKT_TYPE_LENGTH
				);
				resp->data[NG_PCAP_PKT_TYPE_LENGTH - 1] = '\0';
			}
			break;
		}
		case NGM_PCAP_SET_SOURCE_TYPE: {
			hook_p				hook;
			hookmap_t			*iter;
			struct ng_pcap_set_source_type	*st;

			if (msg->header.arglen != sizeof(*st)) {
				error = EINVAL;
				break;
			}
			st = (struct ng_pcap_set_source_type *)msg->data;

			hook = ng_findhook(node, st->hook);
			if (hook == NULL) {
				error = ENOENT;
				break;
			} else {
				for (
					iter = &G.hookmap[0];
					iter != NULL &&
					strncmp(
						iter->display,
						st->type,
						NG_PCAP_PKT_TYPE_LENGTH
					);
					iter++
				);

				if (iter->function == NULL) {
					error = EINVAL;
					break;
				} else {
					/*
					 * ng_pcap_rcvdata will finalize connect
					 * when PCAP file header has been sent.
					 */
					NG_HOOK_SET_RCVDATA(hook, NULL);
					NG_HOOK_SET_PRIVATE(hook, iter->function);
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
 * This function is the generic one until we notice that our PCAP header has
 * gone out. If we see it has we set the hook rcvdata function to take over.
 */
static int
ng_pcap_rcvdata(hook_p hook, item_p item)
{
	const priv_p	priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	ng_rcvdata_t	*rcv = NG_HOOK_PRIVATE(hook);

	/*
	 * This is used by `snoop` and `sourceX` hooks.
	 *
	 * `snoop` drops anything it receives. It is write only.
	 *
	 * `sourceX` is dropped until `snoop` link is established (meaning that
	 * `snoop` is not NULL and priv->seq matches `snoop` hook private data)
	 * and the `sourceX` was configured with "setsourcetype".
	 *
	 * `snoop` continues to come here until shutdown and it will just be
	 * dropped.
	 */
	if (priv->snoop == hook || priv->snoop == NULL || rcv == NULL ||
	    (uintptr_t)NG_HOOK_PRIVATE(priv->snoop) != priv->seq) {
		NG_FREE_ITEM(item);
		return (0);
	}

	/*
	 * Do not zero hook private as we need it for getsourcetype and if
	 * `snoop` is disconnected and reconnected.
	 */
	NG_HOOK_SET_RCVDATA(hook, rcv);
	return rcv(hook, item);
}

/*
 * In addition to adding the pcap header we need to check mbuf for a VLAN tag.
 * If present we need to put it back into the data.
 */
static int
ng_pcap_rcvdata_ether(hook_p hook, item_p item)
{
	int		error = 0;
	const node_p	node = NG_HOOK_NODE(hook);
	const priv_p	priv = NG_NODE_PRIVATE(node);
	struct mbuf	*m;
	pcap_pkthdr_t	hdr, *phdr = NULL;
	struct timeval	timestamp;
	int32_t		trim;

	NGI_GET_M(item, m);

	M_ASSERTPKTHDR(m); /* maybe just return error */

	if ((m->m_flags & M_VLANTAG) == 0) { /* easy case */
		M_PREPEND(m, sizeof(*phdr), M_NOWAIT);
		error = (m == NULL) ? ENOMEM : m_chk(&m, sizeof(*phdr));
		if (error != 0) {
			NG_FREE_ITEM(item);
			return (error);
		}
	} else {
		struct ether_vlan_header *evl;

		M_PREPEND(m, sizeof(*phdr) + ETHER_VLAN_ENCAP_LEN, M_NOWAIT);
		error = (m == NULL) ?
			ENOMEM : m_chk(&m, sizeof(*phdr) + ETHER_VLAN_HDR_LEN);
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

	/* vlan tag counts, but pcap_pkthdr_t does not */
	hdr.len = (uint32_t)m->m_pkthdr.len - (uint32_t)sizeof(*phdr); /* pre m_adj */

	/* make sure we don't exceed snaplen */
	trim = priv->cfg.snaplen - hdr.len;
	if (trim < 0)
		m_adj(m, trim);

	hdr.caplen = (uint32_t)m->m_pkthdr.len - sizeof(*phdr); /* post m_adj */
	microtime(&timestamp);
	hdr.tv_sec = timestamp.tv_sec;
	hdr.tv_usec = timestamp.tv_usec;

	phdr = mtod(m, pcap_pkthdr_t *);
	*phdr = hdr;

	NG_FWD_NEW_DATA_FLAGS(error, item, priv->snoop, m, HK_QUEUE);
	return (error);
}


#if defined(INET) || defined(INET6)
/*
 * This adds 2 things: pcap header and a fake ethernet header.
 * In addition to potential confusion (why we chose obvious MAC addrs), we lose
 * ETHER_ADDR_LEN bytes of capture when packets exceed snaplen. That is just how
 * tcpdump wants it calculated, for whole record after the `pcap_pkthdr_t`.
 * Six bytes is a small trade to be able to have both my level 2 and level3
 * together in a single capture.
 */
static int
ng_pcap_rcvdata_inet(hook_p hook, item_p item, const struct ether_header *eh)
{
	int		error = 0;
	const node_p	node = NG_HOOK_NODE(hook);
	const priv_p	priv = NG_NODE_PRIVATE(node);
	struct mbuf	*m;
	pcap_pkthdr_t	hdr, *phdr = NULL;
	struct timeval	timestamp;
	int32_t		trim;

	NGI_GET_M(item, m);

	M_ASSERTPKTHDR(m); /* maybe just return error */

	M_PREPEND(m, sizeof(*phdr) + ETHER_HDR_LEN, M_NOWAIT);
	error = (m == NULL) ? ENOMEM : m_chk(&m, sizeof(*phdr) + ETHER_HDR_LEN);
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

	phdr = mtod(m, pcap_pkthdr_t *);
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
 * For this type, by default, removal of the `snoop` link destroys the node.
 * That is not standard, but there is a reason. We have a utility, ngpcap(8)
 * that creates ng_pcap(4) nodes and if it is killed for any reason we lose our
 * `snoop` hook. If that happens (kill -9 or something worse) we want this node
 * to go away. You probably hooked up to a bunch of ng_tee(4) anyway which will
 * gracefully continue and handle ng_pcap(4) disappearing. Then you could easily
 * reconnect by restarting ngpcap(8).
 *
 * ng_lmi(4) does a shutdown when any link (except "debug") is removed. So not
 * totally unprecedented.
 */
static int
ng_pcap_disconnect(hook_p hook)
{
	const node_p	node = NG_HOOK_NODE(hook);
	const priv_p	priv = NG_NODE_PRIVATE(node);

	/* nothing to do if it isn't snoop */
	if (hook != priv->snoop) {
		return (0);
	}

	priv->snoop = NULL;

	/*
	 * Either reset all the rcvdata members of our hooks (need to wait for
	 * next pcaphdr to go out) or remove ourself.
	 */
	if (priv->cfg.persistent) {
		hook_p	iter;
		LIST_FOREACH(iter, &node->nd_hooks, hk_hooks) {
			NG_HOOK_SET_RCVDATA(iter, NULL);
		}
	} else if (NG_NODE_IS_VALID(node))
		ng_rmnode_self(node);

	return (0);
}

static int
ng_pcap_mod_event(module_t mod, int event, void *data)
{
	int	error = 0;

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
