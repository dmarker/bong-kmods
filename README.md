[10]: https://github.com/dmarker/bong-utils
[11]: https://github.com/dmarker/bong-patches
[20]: https://en.wikipedia.org/wiki/Unique_local_address
[30]: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=286717

# bong
The "bag o' netgraph" modules is a set of netgraph(4) nodes I maintain out of
tree.

There is another repo, [bong-utils][10], that provide easier ways to use some of
the nodes present here.

Some of these nodes require FreeBSD15 becuase they need changes made, some of
which are not yet (and who knows, may never be) in FreeBSD. I have a set of
patches for FreeBSD 14/stable and 15 (main) in a separate repo,
[bong-patches][11], along with a table of where those patches are in the
process.

Only once those have all landed (if they do) I plan to make `net/bong-kmod`
port for this repo. Its easier for me to maintain these out of tree and
netgraph(4) has been my favourite subsystem forever, and in fact got me to move
my firewall from OpenBSD to FreeBSD 15 years ago (but I still use pf(4) not
ipfw(4) which is maybe why I had to make some of these).

WARNING: This is all a work in progress. I'm still testing! Some nodes aren't
even far enough along yet to include.

Be advised, since [Bug 286717][30], on FreeBSD current you need to build with
`INVARIANTS`, like `# make INVARIANTS=1`.

## wormhole
The wormhole node allows you to connect any two netgraph(4) nodes that each
reside in separate vnet(9). While you can (and I do) use this to simply
attach an ng_eiface(4) created in a jail to an ng_bridge(4) on the system,
it does not care what data it shovels back and forth.

[bong-utils][10] provides `ngportal` specifically to simplify connecting
nodes with ng_wormhole(4).

## pcap
The pcap node is mostly for debugging. It expects either layer 2 or layer 3
nodes which you must configure after connecting to `source<N>` nodes. You
inform pcap what the hook provides: ethernet frames, IPv4, or IPv6. In the
case of IPv4 and IPv6, fake ethernet frames will be added. This allows you
to trace both layers at the same time. I don't know of any use for this
besides debugging netgraph(4) nodes.

[bong-utils][10] provides `ngpcap` specifically to simplify connecting
nodes with ng_pcap(4). But it requires you to plan in advance and place some
ng_tee(4) in your configuration. You don't have to connect to ng_tee(4) but
that is the expected case.

## ula4tag
This is an oddball for sure but I have to use it because my ISP only gives me
a /64 prefix for IPv6. That is a massive range, but Android will not do DHCPv6
(probably a good thing IMO) and only does SLAAC. That takes up my whole GUA
address space. And I want separate networks for my LAN and WiFi. That is where
ula4tag comes in, it allows you to VLAN tag [ULA][20] and IPv4 traffic coming in
while leaving GUA traffic untagged.

The idea is you connect ng_ether(4) to this, configure tags, and connect the
ula4tag to the ng_bridge(4). Additionally on the bridge you need an ng_vlan(4)
that has (in my case) 3 ng_eifaces(4). One for GUA, one for [ULA][20] from WiFi
and one for [ULA][20] from LAN. While the GUA are all just one big bridge WiFi
and LAN now have separate and routable [ULA][20] traffic (on my intranet). I do
this so my LAN can be DHCPv6, the reason I want that is for the next node...

There is an example script in bong-utils showing how I use this.

This is functionality I'm not aware of existing elsewhere, so there is a good
chance its a bad idea (but hey its working for me). I use it because my ISP
insists on a worse idea: giving out only /64 prefix.

## xlate64

This is not a netgraph(4) node. It is a helper module for translating IPv6 to
IPv4 and vice versa. It is lifted almost entirely from the ipfw(4) code. Even
function names pretty obviously map to what they are over in ipfw code. So yes,
obviously I know ipfw(4) can already do this and more.

This also has code lifted from ng_iface(4) for creating its virtual interfaces
that both of the next nodes require. This is also the one requiring `0005.patch`
from [bong-patches][11]. The next two nodes exploit this interface. You configure
one with exactly one IPv4 and one with exactly one IPv6. Which is why this needs
that patch (which means the next two do as well).

## siit
This is an implementation of SIIT, although not complete. In particular it only
allows a /96 (the simplest one) to be configured. It also creates 2 network
interfaces (akin to ng_iface(4) but not the same). One must be configured with
IPv4, the other with IPv6. I use this for my LAN so that hosts do not require
IPv4 at all.

## nat64
Similar to siit node, but it dynamically keeps mappings from 6 <-> 4 that time
out. You can't use siit with an Android but you can use this. This is what I
use for my WiFi so that anything connecting only uses IPv6.
