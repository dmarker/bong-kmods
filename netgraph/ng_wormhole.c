/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/jail.h>
#include <net/vnet.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_wormhole.h>
#include <netgraph/netgraph.h>

#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(
	M_NETGRAPH_WORMHOLE, "netgraph_wormhole", "netgraph wormhole node"
);
#else
#define M_NETGRAPH_WORMHOLE M_NETGRAPH
#endif

/*
 * This _requires_ vimage to be useful.
 */
#ifndef	VIMAGE
#error	ng_wormhole requires VIMAGE.
#endif	/* VIMAGE */

/* we need this from ng_base */
void	ng_rmnode(node_p node, hook_p dummy1, void *dummy2, int dummy3);

/* we need a flag just for ourselves */
#define HK_COLLAPSE		0x1000


static ng_constructor_t	ng_wormhole_constructor;
static ng_rcvmsg_t	ng_wormhole_rcvmsg;
static ng_shutdown_t	ng_wormhole_shutdown;
static ng_newhook_t	ng_wormhole_newhook;
static ng_connect_t	ng_wormhole_connect;
static ng_rcvdata_t	ng_wormhole_rcvdata;
static ng_disconnect_t	ng_wormhole_disconnect;

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_wormhole_cmdlist[] = {{
	NGM_WORMHOLE_COOKIE,
	NGM_WORMHOLE_OPEN,
	"open",
	&ng_parse_string_type,
	NULL,
},{
	0
}};

/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_WORMHOLE_NODE_TYPE,
	.constructor =	ng_wormhole_constructor,
	.rcvmsg =	ng_wormhole_rcvmsg,
	.shutdown =	ng_wormhole_shutdown,
	.newhook =	ng_wormhole_newhook,
	.connect =	ng_wormhole_connect,
	.rcvdata =	ng_wormhole_rcvdata,
	.disconnect =	ng_wormhole_disconnect,
	.cmdlist =	ng_wormhole_cmdlist,
};
NETGRAPH_INIT(wormhole, &typestruct);

struct ng_wormhole_priv {
	node_p		node;	/* back pointer to node */
	hook_p		warp;	/* connectes to other side */
	hook_p		eh;	/* user connection */
};
typedef struct ng_wormhole_priv *priv_p;

/*
 * We don't get to allocate a hook so what we do is allocate `warp` with `priv`.
 *
 * This is problematic in the sense that we can't let NG_UNREF_HOOK free the
 * hook we allocated with `priv`. We give the hooks an extra ref to prevent
 * that.
 */
struct alloc_priv {
	struct ng_wormhole_priv	priv;
	struct ng_hook		hook;
};

/* At this point we can only open one side of the wormhole. */
static int
ng_wormhole_constructor(node_p node)
{
	priv_p	priv = malloc(
		sizeof(struct alloc_priv), M_NETGRAPH_WORMHOLE, M_WAITOK|M_ZERO
	);
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;

	return (0);
}

/*
 * This is really the workhorse that makes it so we can place the other side
 * and never have to vmove it.
 *
 * prison names are array of MAXHOSTNAMELEN which at present is far larger
 * than NG_HOOKSIZ.
 *
 * Obviously that mismatch means we can't just name the hook after the jail.
 * But even a 64-bit int only needs 19 characters (no commas). 
 *
 * That even leaves space to store some intent like a prefix of "jid=". That
 * ought to give users a clue where the other side of the wormhole lives.
 * And an easy way to go deal with it.
 */
static int
ng_wormhole_open(priv_p pv_near, const char *prison)
{
	int		rc, jid;
	char		*ep;
	struct prison	*pr_near, *pr_far;
	priv_p		pv_far;
	hook_p		hk_near, hk_far;

	pr_near = curthread->td_ucred->cr_prison;
	jid = strtoul(prison, &ep, 10); /* may have got number */

	sx_slock(&allprison_lock);
	if (!*ep)
		pr_far = prison_find_child(pr_near, jid);
	else
		pr_far = prison_find_name(pr_near, prison);
	sx_sunlock(&allprison_lock);
	if (pr_far == NULL) {
		return (EHOSTDOWN); /* jail not found */
	}

	/*
	 * XXX is this sufficient?
	 *
	 * prison_find_name already made sure it was valid and alive.
	 * We just need to make sure it is vnet enabled and has a *different*
	 * vnet than pr_near.
	 */
	if (((pr_far->pr_flags & PR_VNET) == 0 ) ||	/* not vnet */
	    (pr_far->pr_vnet == pr_near->pr_vnet)) {	/* not different */
		mtx_unlock(&pr_far->pr_mtx);
		return (EINVAL);
	}
	prison_hold_locked(pr_far);
	mtx_unlock(&pr_far->pr_mtx);

	pv_far = malloc(sizeof(struct alloc_priv), M_NETGRAPH_WORMHOLE,
	    M_WAITOK | M_ZERO);

	hk_near = &((struct alloc_priv *)pv_near)->hook;
	hk_far = &((struct alloc_priv *)pv_far)->hook;

	/* change to that vnet and create where it is needed */
	CURVNET_SET(pr_far->pr_vnet);
	if ((rc = ng_make_node_common(&typestruct, &(pv_far->node))) != 0) {
		prison_free(pr_far);
		free(pv_far, M_NETGRAPH_WORMHOLE);
		return (rc);
	}
	CURVNET_RESTORE();

	NG_NODE_SET_PRIVATE(pv_far->node, pv_far);

	/*
	 * Fill in hooks and place them on list remembering to give extra
	 * reference. Basically do what ng_add_hook would do except without
	 * calling connect pointer.
	 */
	snprintf(NG_HOOK_NAME(hk_near), NG_HOOKSIZ, "jid=%d", pr_far->pr_id);
	snprintf(NG_HOOK_NAME(hk_far), NG_HOOKSIZ, "jid=%d", pr_near->pr_id);

	/*
	 * leave hk_flgs=0. we have the q-lock for ourself and nothing can talk
	 * to the other side but us yet anyway.
	 */
	hk_far->hk_refs = 3;		/* intentional! */
	hk_near->hk_refs = 3;		/* 1 for hook, 1 for node, 1 extra */
	hk_far->hk_peer = hk_near;
	hk_near->hk_peer = hk_far;
	hk_far->hk_node = pv_far->node;
	hk_near->hk_node = pv_near->node;
#ifdef	NETGRAPH_DEBUG
	hk_far->hk_magic = HK_MAGIC;
	hk_near->hk_magic = HK_MAGIC;
#endif
	NG_NODE_REF(pv_far->node);	/* will now hold each other open */
	NG_NODE_REF(pv_near->node);
	LIST_INSERT_HEAD(&pv_far->node->nd_hooks, hk_far, hk_hooks);
	LIST_INSERT_HEAD(&pv_near->node->nd_hooks, hk_near, hk_hooks);
	pv_far->node->nd_numhooks++;
	pv_near->node->nd_numhooks++;

	pv_far->warp = hk_far;
	pv_near->warp = hk_near;

	/*
	 * At this point if a vnet going down turfs either side of the wormhole
	 * it shutsdown both sides (because it will disconnect `warp`).
	 *
	 * That is fine, we just can't have a one sided wormhole.
	 */
	prison_free(pr_far);

	return (0);
}

/*
 * There is one special case: another wormhole connection.
 * But we don't have valid hooks on both sides. Wait for connect to deal with.
 */
static int
ng_wormhole_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	if (strcmp(name, NG_WORMHOLE_HOOK))
		return (EINVAL);

	if (priv->eh != NULL)
		return (EISCONN);

	/* more commonly just add connection */
	priv->eh = hook;
	return (0);
}

/* at last all 4 nodes are locked */
static void
ng_wormhole_collapse2(node_p nd_aa, hook_p dummy1, void *priv, int dummy3)
{
	priv_p pv_a = (priv_p)priv; /* just trust pv_a */
	priv_p pv_b = NG_NODE_PRIVATE(NG_PEER_NODE(pv_a->eh));
	priv_p pv_aa = NG_NODE_PRIVATE(NG_PEER_NODE(pv_a->warp));
	priv_p pv_bb = NG_NODE_PRIVATE(NG_PEER_NODE(pv_b->warp));

	/* rearange */
	pv_a->warp->hk_peer = pv_b->warp;
	pv_b->warp->hk_peer = pv_a->warp;
	pv_aa->warp->hk_peer = pv_bb->warp;
	pv_bb->warp->hk_peer = pv_aa->warp;

	/* gotta fix hook names to show correct info */
	strncpy(NG_HOOK_NAME(pv_aa->warp), NG_HOOK_NAME(pv_a->warp), NG_HOOKSIZ);
	strncpy(NG_HOOK_NAME(pv_bb->warp), NG_HOOK_NAME(pv_b->warp), NG_HOOKSIZ);

	/*
	 * Only have to destroy one to remove both circular nodes.
	 * We could try ng_rmnode_self but we can't ask for NG_WAITOK. I do see
	 * lots of calls that don't check return but it could fail. Those calls
	 * are all in disconnect.
	 */
	ng_rmnode(pv_a->node, NULL, NULL, 0);
}

/* now nd_bb is locked, only purpose of this, go on to lock nd_aa */
static void
ng_wormhole_collapse1(node_p nd_bb, hook_p dummy1, void *priv, int dummy3)
{
	priv_p pv_a = (priv_p)priv; /* just trust pv_a */
	node_p nd_aa = NG_PEER_NODE(pv_a->warp);
	int rc = ng_send_fn1(
		nd_aa, NULL, &ng_wormhole_collapse2, pv_a, 0, NG_WAITOK
	);
	MPASS(rc == 0);
	(void)(rc);
}

/*
 * When two wormhole's event horizons collide they collapse into a single
 * wormhole.
 *
 * Nothing gets to direct connect. But nothing should have more than 2 wormholes
 * to pass through. And the wormholes hookinfo should always point you to where
 * packets are flowing.
 *
 * This is easier to show than explain. Before connect its all normal.
 * Just two wormholes (wh0a and wh0b) waiting for a connect:
 *                  |
 *      wh0a---warp-+-wh0aa---eh---?
 *                  |
 *                  +-------------------
 *                  |
 *      wh0b---warp-+-wh0bb---eh---?
 *                  |
 *
 * Now connect wh0a to wh0b (evthorizon to evthorizon) pre-collapse:
 * (refer to this s/wh0/pv_/g for finding nodes from pv_a)
 *                  |
 *      wh0a---warp-+-wh0aa---eh---?
 *        |         |
 *       eh         +-------------------
 *        |         |
 *      wh0b---warp-+-wh0bb---eh---?
 *                  |
 *
 * But when everything is done:
 *                  |
 *                  | wh0aa---eh---?
 *                  |   |
 *                  +--warp-------------
 *                  |   |
 *                  | wh0bb---eh---?
 *                  |
 *
 * Keep that map in mind going through the series of events that start here.
 * We start with 4 nodes in 3 vnets. We end with 2 nodes in 2 vnets.
 *
 * pv_a is going to be our arg to both funtions that use ng_send_fn1 through the
 * whole process as right up until the end it can get us to pv_b, pv_aa, and
 * pv_bb (actually so could pv_b).
 *
 * This is allows peer jails to have private connections. Similar to if you
 * pushed the 'a' end of an epair in one jail and the 'b' in another.
 *
 * But normally wh0a will just connect to something in our own vnet which is:
 *
 *                    wh0a----eh---?
 *          vnetX       |
 *         ------------warp-------------
 *          vnetY       |
 *                    wh0aa---eh---?
 *
 * And when asked to connect to anything but another wormhole we just return 0.
 * Probably the most common case.
 *
 */
static int
ng_wormhole_connect(hook_p hook)
{
	int rc;
	priv_p pv_a, pv_b;
	node_p nd_aa, nd_bb;

	/* user can only connect to `eh` so check its peer type */
	if (NG_PEER_NODE(hook)->nd_type != &typestruct)
		return (0);

	pv_a = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	pv_b = NG_NODE_PRIVATE(NG_PEER_NODE(hook));

	/*
	 * We can't allow two wormholes to connect until they are open. Because
	 * a failing collapse (which only happens if they are not both open)
	 * would leave bogus state for the hooks.
	 */
	if (pv_a->warp == NULL || pv_b->warp == NULL)
		return (EINVAL);

	/*
	 * We also refuse to connect if these 2 are in the same vnet. That would
	 * technically be a connected path. It just doesn't make sense for both
	 * ends of a wormhole to be in the same vnet. Just connect them if you
	 * want that.
	 */
	nd_aa =  NG_PEER_NODE(pv_a->warp);
	nd_bb = NG_PEER_NODE(pv_b->warp);
	if (nd_aa->nd_vnet == nd_bb->nd_vnet)
		return (EDOOFUS); /* to distinguish not insult */

	/*
	 * The first one in will set HK_COLLAPSE and tag the peer hook. The 2nd
	 * will see its hook is tagged, clear then start the collapse.
	 */
	if ((hook->hk_flags & HK_COLLAPSE) == 0) {
		/* first to arrive (not a race both stay locked). */
		NG_HOOK_PEER(hook)->hk_flags |= HK_COLLAPSE;
		return (0);
	}
	hook->hk_flags &= ~HK_COLLAPSE;

	/*
	 * ng_bypass, sanely, requires hooks to be on same node. This collapse
	 * is a by_pass between 4 nodes. 2 of which will go away soon.
	 *
	 * But before anything can happen we have to do the queue dance to get
	 * them locked. We need to lock nd_bb then nd_aa before proceeding.
	 */
	rc = ng_send_fn1(
		nd_bb, NULL, &ng_wormhole_collapse1, pv_a, 0, NG_WAITOK
	);
	MPASS(rc == 0);
	return (rc);
}

static int
ng_wormhole_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_WORMHOLE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_WORMHOLE_OPEN: {
			/* By using a command we can accept any jail name */
			if (msg->header.arglen == 0 ||
			    msg->header.arglen > MAXHOSTNAMELEN) {
				error = EINVAL;
				break;
			}
			/* only one move is allowed */
			if (priv->warp != NULL)
				return (EISCONN);

			/* ensure we can't walk off the end */
			((char *)msg->data)[msg->header.arglen] = '\0';

			error = ng_wormhole_open(priv, (char *)msg->data);
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


/*
 * A really trivial function.
 *
 * Just send anything recieved out the other hook.
 */
static int
ng_wormhole_rcvdata(hook_p hook, item_p item )
{
	int rc;
	const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	hook_p dest = (hook == priv->eh) ? priv->warp : priv->eh;

	/* this correctly handles when nothing is connected to either side */
	NG_FWD_ITEM_HOOK(rc, item, dest);

	return (rc);
}

/*
 * shutdown of one side should just shutdown both. This automatically happens
 * because prior to this being called, ng_base called ng_rmnode which killed
 * all our hooks. In particular removing `warp` from both sides collapses the
 * wormhole.
 *
 * When this gets called your hooks are removed already.
 */
static int
ng_wormhole_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	free(priv, M_NETGRAPH_WORMHOLE);

	return (0);
}

/*
 * You can disconnect and reconnect NG_WORMHOLE_HOOK (the `eh` side) as many
 * times as you want. But if `warp` goes the wormhole collapses.
 *
 * This is how we allow either side to do a shutdown.
 */
static int
ng_wormhole_disconnect(hook_p hook)
{
	/*
	 * The usual of all hooks gone means shutdown, but we can simplify to
	 * just caring when `warp` goes down since a shutdown will remove all
	 * hooks anyway.
	 */
	if (NG_NODE_IS_VALID(NG_HOOK_NODE(hook))) {
		const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
		if (hook == priv->eh)
			priv->eh = NULL; /* allow new connection */
		else
			ng_rmnode_self(NG_HOOK_NODE(hook));
	}	

	return (0);
}
