/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETGRAPH_NG_PCAP_H_
#define _NETGRAPH_NG_PCAP_H_

//#include <sys/mbuf.h>
#include <sys/types.h>
#include <netgraph/ng_message.h>
/*
 * This node *almost* doesn't need to exist. You could use an ng_one2many except
 * that then you are limited to all layer 2 or all layer 3.
 *
 * Additionally if we used one2many we couldn't put VLAN tags into the output of
 * the layer 2 output which is the first dealbreaker for one2many. The other is
 * that it turns out to be really handy to destroy the node when its `one` hook,
 * in this case `snoop`, is removed (like tcpdump(1) crashed). That is because
 * pcap if for debugging! And when not attached you don't need the ng_tee(4)
 * wasting cycles copying data to ng_pcap(4).
 *
 * And finally since we get to mix all the data for tcpdump anyway, lets also
 * output a `struct pcaprec_hdr_s` in front of the ethernet (faked or not) with
 * timestamp. This allows us to trim the packets before shoveling to userland.
 *
 * It is still tempting to use ng_one2many so we just have an "ether", "inet",
 * and "inet6" hook and if you want more than one thing on them, well that's a
 * great use for one2many. But they would not go away with pcap node so it isn't
 * perfect. Decided to go ahead and allow any number of "source" hooks that you
 * later configure to be "ether", "inet", or "inet6". one2many being hooked up
 * to tee means data would get copied on every packet even when not snooping. So
 * there really is advantage to cutting out the node that seems obvious to use
 * here.
 * 
 * So the pcap node does need to be told what is on each source.
 */

/* Node type name. This should be unique among all netgraph node types */
#define NG_PCAP_NODE_TYPE	"pcap"

#define NGM_PCAP_COOKIE		1751984553

#define NG_PCAP_MAX_LINKS	16

/*
 * Hook names
 * The one hook that aggregates all the pcap data is called "snoop".
 *
 * You can have up to NG_PCAP_MAX_LINKS which are all named "source<N>"
 * where N is drawn from [0, NG_PCAP_MAX_LINKS).
 *
 * Every "source" link must be configured to be one of:
 *	ethernet
 *	IPv4
 *	IPv6
 *
 * Until a "source" is configured, no traffic is passed on to snoop.
 *
 * For IPv4 and IPv6 a fake ethernet header is prefixed to each packet.
 * This allows all forms to be intermixed for tcpdump.
 *
 * For all of them a pcap header is also prefixed to that the output from
 * "snoop" can be given to tcpdump directly.
 */
#define NG_PCAP_HOOK_SNOOP	"snoop"
#define NG_PCAP_HOOK_SOURCE	"source"

/* no point capturing more than tcpdump would use, also default */
#define NG_PACP_MAX_SNAPLEN	262144
/*
 * Don't see a lower bound in docs. But lets assume it must be at least:
 *	ETHER_VLAN_ENCAP_LEN + 60 (all IPv4 options) + ???
 * (yeah IPv4 larger than IPv6).
 *
 * so 64 + something... I'm going to say another 64 b/c its a nice power of 2
 * and that should be sufficient.
 *
 * should go dig through libpcap and tcpdump...
 */
#define NG_PACP_MIN_SNAPLEN	128

/*
 * Node configuration structure
 * Looks like overkill, but we may add more config options like setting the
 * fake ethernet MAC address for example.
 */
struct ng_pcap_config {
	int32_t			snaplen;
};

/* Keep this in sync with the above structure definition */
#define NG_PCAP_CONFIG_TYPE_INFO	{			\
	  { "snaplen",		&ng_parse_int32_type	},	\
	  { NULL }						\
}

/* valid packet_types (although you can't set "<unset>") */
#define	HOOK_PKT_UNSET		"<unset>"
#define	HOOK_PKT_ETHER		"ether"
#define	HOOK_PKT_INET		"inet"
#define	HOOK_PKT_INET4		HOOK_PKT_INET
#define	HOOK_PKT_INET6		"inet6"

#define NG_PCAP_PKT_TYPE_LENGTH	16

struct ng_pcap_set_source_type {
	char	hook_name[NG_HOOKSIZ];
	char	packet_type[NG_PCAP_PKT_TYPE_LENGTH];
};

/* Keep this in sync with the above structure definition */
#define	NG_PCAP_SET_SOURCE_TYPE_FIELDS(pkttype) {	\
	{ "hook",	&ng_parse_hookbuf_type	},	\
	{ "type",	(pkttype)		}	\
}

/* Netgraph commands understood by this node type */
enum {
	NGM_PCAP_GET_CONFIG = 1,
	NGM_PCAP_SET_CONFIG,
	NGM_PCAP_GET_SOURCE_TYPE,
	NGM_PCAP_SET_SOURCE_TYPE,
};

/* Taken from "pcap.h", which is fortunately very stable. */ 
#ifdef _KERNEL
struct pcap_pkthdr {
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;	/* length of portion present */
	uint32_t len;		/* length of this packet (off wire) */
};
#endif /* _KERNEL */

#endif /* _NETGRAPH_NG_PCAP_H_ */
