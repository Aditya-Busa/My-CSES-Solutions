#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpfil/pf/pf.h>

static int dropped_packets = 0;
static int total_bytes_dropped = 0;

static int
http_blocker_check(struct mbuf **m, struct ifnet *ifp, int dir, void *ruleset, struct inpcb *inp)
{
    struct ip *ip;
    struct tcphdr *tcp;
    char *http_data;
    int ip_len, tcp_len, http_len;
    
    if (!m || !*m)
        return PF_PASS;
        
    ip = mtod(*m, struct ip *);
    
    // Check if it's TCP
    if (ip->ip_p != IPPROTO_TCP)
        return PF_PASS;
        
    // Check if it's HTTP (port 80)
    ip_len = ip->ip_hl << 2;
    tcp = (struct tcphdr *)((char *)ip + ip_len);
    
    if (ntohs(tcp->th_dport) != 80)
        return PF_PASS;
        
    // Extract HTTP data
    tcp_len = tcp->th_off << 2;
    http_data = (char *)tcp + tcp_len;
    http_len = ntohs(ip->ip_len) - ip_len - tcp_len;
    
    if (http_len <= 0)
        return PF_PASS;
        
    // Check for "blocked.com" in HTTP header
    if (strnstr(http_data, "blocked.com", http_len) != NULL) {
        dropped_packets++;
        total_bytes_dropped += ntohs(ip->ip_len);
        printf("HTTP_BLOCKER: Dropped packet #%d, size: %d bytes, total dropped: %d bytes\n", 
               dropped_packets, ntohs(ip->ip_len), total_bytes_dropped);
        return PF_DROP;
    }
    
    return PF_PASS;
}

static int
http_blocker_load(module_t mod, int type, void *data)
{
    switch (type) {
    case MOD_LOAD:
        printf("HTTP Blocker module loaded\n");
        // Register the hook with pf
        return 0;
    case MOD_UNLOAD:
        printf("HTTP Blocker module unloaded. Total packets dropped: %d, Total bytes: %d\n", 
               dropped_packets, total_bytes_dropped);
        return 0;
    default:
        return EOPNOTSUPP;
    }
}

static moduledata_t http_blocker_mod = {
    "http_blocker",
    http_blocker_load,
    NULL
};

DECLARE_MODULE(http_blocker, http_blocker_mod, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY);
