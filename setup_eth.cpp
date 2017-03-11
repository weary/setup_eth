#include <iostream>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <cstring>
#include <linux/rtnetlink.h>
#include <vector>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <functional>


struct cleanup_t {
    cleanup_t(std::function<void()> &&f) : d_f(std::move(f)) { }
    ~cleanup_t() { d_f(); }

    std::function<void()> d_f;
};

class sock_ops_t {
    nl_sock *sk = nullptr;
    rtnl_link *link = nullptr;

public:
    sock_ops_t(const char *interface) {
        sk = nl_socket_alloc();
        nl_connect(sk, NETLINK_ROUTE);

        if (rtnl_link_get_kernel(sk, 0, interface, &link) < 0)
            throw std::runtime_error("Failed to find interface " + std::string(interface));
    }

    ~sock_ops_t() {
        rtnl_link_put(link);
        nl_close(sk);
        nl_socket_free(sk);
        sk = nullptr;
    }

    std::string linkname() const {
        return rtnl_link_get_name(link);
    }

    std::string linkaddr() const {
        nl_addr *addr = rtnl_link_get_addr(link);
        if (!addr)
            throw std::runtime_error("failed to get address from link");

        char linkbuf[64];
        char *linkaddr = nl_addr2str(addr, linkbuf, sizeof(linkbuf));
        if (!linkaddr)
            throw std::runtime_error("Failed to fetch link address");
        return linkaddr;
    }

    void ip_addr_flush() {
        struct nl_cache *cache = nullptr;
        if (rtnl_addr_alloc_cache(sk, &cache) < 0)
            throw std::runtime_error("Could not get addr info");
        cleanup_t atexit([cache] { nl_cache_free(cache); });

        int ifidx = rtnl_link_get_ifindex(link);
        for (nl_object *addr = nl_cache_get_first(cache); addr; addr = nl_cache_get_next(addr)) {
            rtnl_addr * addrc = reinterpret_cast<rtnl_addr *>(addr);
            if (rtnl_addr_get_ifindex(addrc) == ifidx) {
                nl_addr *ip_addr = rtnl_addr_get_local(addrc);
                if (!ip_addr)
                    continue;
                int err = rtnl_addr_delete(sk, addrc, 0);
                if (err)
                    throw std::runtime_error("failed to delete " + ip_to_string(ip_addr) + ": " + nl_err(err));
            }
        }
    }

    void set_ip_addr(const std::string &new_ipv4, int prefix) {
        in_addr_t in_addr = inet_addr(new_ipv4.c_str());

        rtnl_addr *newaddr = rtnl_addr_alloc();
        if (!newaddr)
            throw std::runtime_error("failed to alloc new address");
        cleanup_t atexit1([newaddr]{ rtnl_addr_put(newaddr); });

        nl_addr *new_nl_addr = nl_addr_build(AF_INET, &in_addr, sizeof(in_addr));
        if (!new_nl_addr)
            throw std::runtime_error("failed to construct nl_addr");
        cleanup_t atexit2([new_nl_addr]{ nl_addr_put(new_nl_addr); });
        nl_addr_set_prefixlen(new_nl_addr, prefix);
        rtnl_addr_set_local(newaddr, new_nl_addr);

        int ifidx = rtnl_link_get_ifindex(link);
        rtnl_addr_set_ifindex(newaddr, ifidx);

        int err = rtnl_addr_add(sk, newaddr, 0);
        if (err)
            throw std::runtime_error("failed to set new address: " + nl_err(err));
    }

    void set_up_down(bool to_up) {
        rtnl_link *newstate = rtnl_link_alloc();
        if (!newstate)
            throw std::runtime_error("could not allocate newstate");
        cleanup_t atexit1([newstate]{ rtnl_link_put(newstate); });

        if (to_up)
            rtnl_link_set_flags(newstate, IFF_UP);
        else
            rtnl_link_unset_flags(newstate, IFF_UP);

        int err = rtnl_link_change(sk, link, newstate, 0);
        if (err)
            throw std::runtime_error("failed to change interface state: " + nl_err(err));
    }

    void add_route(const std::string &dest_ip_str, int prefix, const std::string &via) {
        // ip route add <to_ip>/<to_mask> via <via>

        rtnl_route *newroute = rtnl_route_alloc();
        // FIXME: cleaning up newroute at end gives double-free, but not cleaning gives leaked resources

        rtnl_route_set_iif(newroute, AF_INET);
        rtnl_route_set_scope(newroute, RT_SCOPE_UNIVERSE);
        rtnl_route_set_table(newroute, RT_TABLE_MAIN);
        rtnl_route_set_protocol(newroute, RTPROT_BOOT);

        // Set the destination.
        in_addr_t dest_ip = inet_addr(dest_ip_str.c_str());
        nl_addr *dest_addr = nl_addr_build(AF_INET, &dest_ip, sizeof(dest_ip));
        if (!dest_addr)
            throw std::runtime_error("invalid destination address in add_route");
        cleanup_t atexit2([dest_addr]{ nl_addr_put(dest_addr); });
        nl_addr_set_prefixlen(dest_addr, prefix);
        int err = rtnl_route_set_dst(newroute, dest_addr);
        if (err)
            throw std::runtime_error("failed to set destination: " + nl_err(err));

        in_addr_t gw_ip = inet_addr(via.c_str());
        nl_addr *gw_addr = nl_addr_build(AF_INET, &gw_ip, sizeof(gw_ip));
        if (!gw_addr)
            throw std::runtime_error("invalid gateway address in add_route");
        cleanup_t atexit3([gw_addr]{ nl_addr_put(gw_addr); });

        // Set the next hop.
        rtnl_nexthop *route_nexthop = rtnl_route_nh_alloc();
        if (!route_nexthop)
            throw std::runtime_error("could not allocate nexthop");
        cleanup_t atexit4([route_nexthop]{ rtnl_route_nh_free(route_nexthop); });

        rtnl_route_nh_set_gateway(route_nexthop, gw_addr);
        int ifidx = rtnl_link_get_ifindex(link);

        rtnl_route_nh_set_ifindex(route_nexthop, ifidx);
        rtnl_route_add_nexthop(newroute, route_nexthop);
        err = rtnl_route_add(sk, newroute, 0);
        if (err)
            throw std::runtime_error("failed to set new route: " + nl_err(err));
    }

protected:
    std::string ip_to_string(nl_addr *ip_addr) {
        char ip_buf[BUFSIZ] = {0};
        const char *str = nl_addr2str(ip_addr, ip_buf, sizeof(ip_buf));
        return str;
    }

    std::string nl_err(int err) {
            return std::string(nl_geterror(err));
}
};


int main() {
    sock_ops_t ops("eth10");
    printf("working on %s (%s)\n", ops.linkname().c_str(), ops.linkaddr().c_str());

    /*
    * ip addr flush eth10
    * ip addr add 10.0.0.1/24 dev eth10
    * ip link set dev eth10 up
    * ip route add 10.9.0.0/24 via 10.10.0.1
    *
    */

    ops.set_up_down(false);
    ops.ip_addr_flush();
    ops.set_ip_addr("10.0.0.1", 24);
    ops.set_up_down(true);

    ops.add_route("10.9.0.0", 24, "10.0.0.1");

    printf("done\n");

    return 0;
}