/* Simple block_http.c for FreeBSD 13.4 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

static volatile u_long dropped_pkts = 0;
static volatile u_long dropped_bytes = 0;

static pfil_return_t
simple_block_hook(pfil_packet_t *packet, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp)
{
    struct mbuf *m, **mp;
    struct ip *ip;
    struct tcphdr *th;
    char *data;
    int ip_len, tcp_len, data_len;

    printf("simple_block_hook: packet received, dir=%d\n", dir);

    if (dir != PFIL_IN)
        return (PFIL_PASS);

    mp = pfil_packet_to_mbuf(packet);
    if (mp == NULL || *mp == NULL)
        return (PFIL_PASS);
    m = *mp;

    /* Basic IP header check */
    if (m->m_len < sizeof(struct ip)) {
        m = m_pullup(m, sizeof(struct ip));
        if (m == NULL)
            return (PFIL_PASS);
        *mp = m;
    }

    ip = mtod(m, struct ip *);
    if (ip->ip_v != 4 || ip->ip_p != IPPROTO_TCP)
        return (PFIL_PASS);

    printf("simple_block_hook: TCP packet found\n");

    ip_len = ip->ip_hl << 2;
    
    /* Get TCP header */
    if (m->m_len < ip_len + sizeof(struct tcphdr)) {
        m = m_pullup(m, ip_len + sizeof(struct tcphdr));
        if (m == NULL)
            return (PFIL_PASS);
        *mp = m;
        ip = mtod(m, struct ip *);
    }

    th = (struct tcphdr *)((char *)ip + ip_len);
    
    /* Check if it's HTTP (port 80) */
    if (ntohs(th->th_dport) != 80)
        return (PFIL_PASS);

    printf("simple_block_hook: HTTP packet to port 80\n");

    tcp_len = th->th_off << 2;
    data_len = ntohs(ip->ip_len) - ip_len - tcp_len;

    if (data_len <= 0)
        return (PFIL_PASS);

    printf("simple_block_hook: HTTP packet has %d bytes payload\n", data_len);

    /* Try to get some payload data */
    int needed = ip_len + tcp_len + 100; /* Just get first 100 bytes of payload */
    if (needed > ntohs(ip->ip_len))
        needed = ntohs(ip->ip_len);

    if (m->m_len < needed) {
        m = m_pullup(m, needed);
        if (m == NULL)
            return (PFIL_PASS);
        *mp = m;
        ip = mtod(m, struct ip *);
        th = (struct tcphdr *)((char *)ip + ip_len);
    }

    data = (char *)th + tcp_len;
    int search_len = (needed - ip_len - tcp_len) < data_len ? (needed - ip_len - tcp_len) : data_len;

    /* Simple string search for blocked.com */
    if (search_len > 10) {
        for (int i = 0; i < search_len - 10; i++) {
            if (strncmp(data + i, "blocked.com", 11) == 0) {
                dropped_pkts++;
                dropped_bytes += ntohs(ip->ip_len);  /* Total packet size */
                printf("simple_block: DROPPED packet #%lu for blocked.com - packet size: %d bytes, total dropped: %lu packets, %lu bytes\n",
                       dropped_pkts, ntohs(ip->ip_len), dropped_pkts, dropped_bytes);
                return (PFIL_DROPPED);
            }
        }
    }

    printf("simple_block_hook: HTTP request allowed\n");
    return (PFIL_PASS);
}

static struct pfil_hook_args pha = {
    .pa_version = PFIL_VERSION,
    .pa_flags   = PFIL_IN,
    .pa_type    = PFIL_TYPE_IP4,
    .pa_func    = simple_block_hook,
    .pa_modname = "simple_block",
    .pa_rulname = "block_rule",
};

static pfil_hook_t hook;

static int
simple_block_handler(module_t mod, int what, void *arg)
{
    switch (what) {
    case MOD_LOAD:
        printf("simple_block: Loading...\n");
        hook = pfil_add_hook(&pha);
        if (hook == NULL) {
            printf("simple_block: Failed to add hook!\n");
            return (ENOMEM);
        }
        printf("simple_block: Loaded successfully!\n");
        break;
    case MOD_UNLOAD:
        if (hook)
            pfil_remove_hook(hook);
        printf("simple_block: Unloaded (drops=%lu)\n", dropped_pkts);
        break;
    default:
        return (EOPNOTSUPP);
    }
    return (0);
}

static moduledata_t simple_block_mod = {
    "simple_block",
    simple_block_handler,
    NULL
};

DECLARE_MODULE(simple_block, simple_block_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(simple_block, 1);
