#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

static int dropped_packets = 0;
static int total_bytes_dropped = 0;

/* Sysctl variables for monitoring */
SYSCTL_NODE(_net, OID_AUTO, http_blocker, CTLFLAG_RW, 0, "HTTP Blocker Module");
SYSCTL_INT(_net_http_blocker, OID_AUTO, dropped_packets, CTLFLAG_RD, 
           &dropped_packets, 0, "Number of dropped HTTP packets");
SYSCTL_INT(_net_http_blocker, OID_AUTO, total_bytes_dropped, CTLFLAG_RD,
           &total_bytes_dropped, 0, "Total bytes of dropped HTTP packets");

/* Function to search for string in data */
static char *
memmem_simple(const char *haystack, size_t haystacklen, const char *needle, size_t needlelen)
{
    const char *p;
    size_t plen;
    char needlechar;

    if (needlelen == 0)
        return (char *)haystack;
    
    needlechar = *needle;
    plen = haystacklen - needlelen + 1;
    
    for (p = haystack; plen > 0; p++, plen--) {
        if (*p == needlechar && memcmp(p, needle, needlelen) == 0)
            return (char *)p;
    }
    return NULL;
}

/* Pfil hook function for incoming packets */
static int
http_blocker_hook_in(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    struct mbuf *m = *mp;
    struct ip *ip;
    struct tcphdr *tcp;
    int ip_hlen, tcp_hlen, data_len;
    char *http_data;

    /* Ensure we have enough data for IP header */
    if (m->m_len < sizeof(struct ip)) {
        if ((m = m_pullup(m, sizeof(struct ip))) == NULL) {
            *mp = NULL;
            return PFIL_CONSUMED;
        }
        *mp = m;
    }

    ip = mtod(m, struct ip *);

    /* Only process TCP packets */
    if (ip->ip_p != IPPROTO_TCP)
        return PFIL_PASS;

    ip_hlen = ip->ip_hl << 2;
    
    /* Ensure we have enough data for TCP header */
    if (m->m_len < ip_hlen + sizeof(struct tcphdr)) {
        if ((m = m_pullup(m, ip_hlen + sizeof(struct tcphdr))) == NULL) {
            *mp = NULL;
            return PFIL_CONSUMED;
        }
        *mp = m;
        ip = mtod(m, struct ip *);
    }

    tcp = (struct tcphdr *)((char *)ip + ip_hlen);

    /* Only process HTTP traffic (port 80) */
    if (ntohs(tcp->th_dport) != 80)
        return PFIL_PASS;

    tcp_hlen = tcp->th_off << 2;
    data_len = ntohs(ip->ip_len) - ip_hlen - tcp_hlen;

    /* If there's no HTTP data, pass the packet */
    if (data_len <= 0)
        return PFIL_PASS;

    /* Ensure we have the HTTP data */
    if (m->m_len < ip_hlen + tcp_hlen + data_len) {
        if ((m = m_pullup(m, ip_hlen + tcp_hlen + data_len)) == NULL) {
            *mp = NULL;
            return PFIL_CONSUMED;
        }
        *mp = m;
        ip = mtod(m, struct ip *);
        tcp = (struct tcphdr *)((char *)ip + ip_hlen);
    }

    http_data = (char *)tcp + tcp_hlen;

    /* Check for HTTP request and "blocked.com" */
    if (data_len > 4 && 
        (strncmp(http_data, "GET ", 4) == 0 || 
         strncmp(http_data, "POST", 4) == 0 || 
         strncmp(http_data, "HEAD", 4) == 0)) {
        
        /* Look for "Host: blocked.com" in the HTTP header */
        if (memmem_simple(http_data, data_len, "blocked.com", 11) != NULL) {
            dropped_packets++;
            total_bytes_dropped += ntohs(ip->ip_len);
            
            printf("HTTP_BLOCKER: Dropped packet #%d, size: %d bytes, total dropped: %d bytes\n", 
                   dropped_packets, ntohs(ip->ip_len), total_bytes_dropped);
            
            /* Free the mbuf and return consumed */
            m_freem(*mp);
            *mp = NULL;
            return PFIL_CONSUMED;
        }
    }

    return PFIL_PASS;
}

/* Pfil hook function for outgoing packets (not used but required for registration) */
static int
http_blocker_hook_out(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    return PFIL_PASS;
}

static pfil_hook_t http_blocker_hook_ptr;

static int
http_blocker_load(module_t mod, int type, void *data)
{
    int error = 0;

    switch (type) {
    case MOD_LOAD:
        printf("HTTP Blocker module loading...\n");
        
        /* Register the pfil hook */
        http_blocker_hook_ptr = pfil_add_hook(http_blocker_hook_in, 
                                              http_blocker_hook_out, 
                                              PFIL_IN | PFIL_WAITOK, 
                                              &V_inet_pfil_hook);
        if (http_blocker_hook_ptr == NULL) {
            printf("HTTP Blocker: Failed to register pfil hook\n");
            error = ENOMEM;
        } else {
            printf("HTTP Blocker module loaded successfully\n");
            printf("HTTP Blocker: Monitoring HTTP traffic for 'blocked.com'\n");
        }
        break;
        
    case MOD_UNLOAD:
        printf("HTTP Blocker module unloading...\n");
        
        if (http_blocker_hook_ptr != NULL) {
            pfil_remove_hook(http_blocker_hook_ptr, &V_inet_pfil_hook);
        }
        
        printf("HTTP Blocker module unloaded. Statistics:\n");
        printf("  Total packets dropped: %d\n", dropped_packets);
        printf("  Total bytes dropped: %d\n", total_bytes_dropped);
        break;
        
    default:
        error = EOPNOTSUPP;
        break;
    }
    
    return error;
}

static moduledata_t http_blocker_mod = {
    "http_blocker",
    http_blocker_load,
    NULL
};

DECLARE_MODULE(http_blocker, http_blocker_mod, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY);
