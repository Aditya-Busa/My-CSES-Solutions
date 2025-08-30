/* block_http.c — FreeBSD 13.4 pfil (pa_func variant) */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in_pcb.h>

#include <net/pfil.h>

#define TARGET_HOST "Host: blocked.com"
#define TARGET_HOST_LEN (sizeof(TARGET_HOST) - 1)

static volatile u_long dropped_pkts = 0;
static volatile u_long dropped_bytes = 0;

/* const-safe memmem */
static const void *
k_memmem(const void *h, size_t hlen, const void *n, size_t nlen)
{
    const unsigned char *hay = (const unsigned char *)h;
    const unsigned char *nee = (const unsigned char *)n;

    if (nlen == 0 || hlen < nlen)
        return NULL;

    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == nee[0] && bcmp(hay + i, nee, nlen) == 0)
            return (const void *)(hay + i);
    }
    return NULL;
}

static int
pullup_headers(struct mbuf **mp, int len_needed)
{
    if ((*mp)->m_len < len_needed) {
        struct mbuf *m2 = m_pullup(*mp, len_needed);
        if (m2 == NULL)
            return (ENOMEM);
        *mp = m2;
    }
    return (0);
}

/* pfil_func_t order */
static pfil_return_t
block_http(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    // A printf here should now work when the module is loaded and traffic flows.
    // printf("block_http: Hook function called!\n");
    
    struct mbuf *m = *mp;
    struct ip *ip;
    struct tcphdr *th;
    int ip_hlen, tcp_hlen;
    int tot_len, l4_off, payload_len;
    unsigned char *payload;

    if (dir != PFIL_IN || m == NULL)
        return (PFIL_PASS);

    if (m->m_len < (int)sizeof(struct ip)) {
        if (pullup_headers(mp, sizeof(struct ip)) != 0)
            return (PFIL_PASS);
        m = *mp;
    }

    ip = mtod(m, struct ip *);
    if (ip->ip_v != 4 || ip->ip_p != IPPROTO_TCP)
        return (PFIL_PASS);

    ip_hlen = ip->ip_hl << 2;
    tot_len = ntohs(ip->ip_len);
    if (tot_len < ip_hlen + (int)sizeof(struct tcphdr))
        return (PFIL_PASS);

    if (pullup_headers(mp, ip_hlen + (int)sizeof(struct tcphdr)) != 0)
        return (PFIL_PASS);
    m = *mp;
    ip = mtod(m, struct ip *);
    th = (struct tcphdr *)((caddr_t)ip + ip_hlen);
    tcp_hlen = th->th_off << 2;

    if (tcp_hlen < (int)sizeof(struct tcphdr))
        return (PFIL_PASS);
    if (tot_len < ip_hlen + tcp_hlen)
        return (PFIL_PASS);

    if (ntohs(th->th_dport) != 80)
        return (PFIL_PASS);

    l4_off = ip_hlen + tcp_hlen;
    payload_len = tot_len - l4_off;
    if (payload_len <= 0)
        return (PFIL_PASS);

    int scan_len = payload_len > 2048 ? 2048 : payload_len;
    if (m->m_len < l4_off + scan_len) {
        if (pullup_headers(mp, l4_off + scan_len) != 0)
            return (PFIL_PASS);
        m = *mp;
        ip = mtod(m, struct ip *);
        th = (struct tcphdr *)((caddr_t)ip + ip_hlen);
    }
    payload = (unsigned char *)((caddr_t)ip + l4_off);

    if (k_memmem(payload, scan_len, TARGET_HOST, TARGET_HOST_LEN) != NULL) {
        dropped_pkts++;
        dropped_bytes += payload_len;
        printf("block_http: dropped HTTP packet for blocked.com; payload=%d bytes (drops=%lu, bytes=%lu)\n",
               payload_len, dropped_pkts, dropped_bytes);
        m_freem(*mp);
        *mp = NULL;
        return (PFIL_DROPPED);
    }

    return (PFIL_PASS);
}

static struct pfil_hook *hook;

static struct pfil_hook_args pha = {
    .pa_version = PFIL_VERSION,
    .pa_flags   = PFIL_IN,
    .pa_type    = PFIL_TYPE_IP4,
    .pa_func    = (pfil_func_t) block_http,
    .pa_ruleset = NULL,
    .pa_modname = "block_http",
    .pa_rulname = "drop_blocked_host",
};

/*
 * MINIMAL CHANGE #3: Add the pfil_link_args struct to link the hook.
 */
static struct pfil_link_args pla = {
    .pa_version = PFIL_VERSION,
    .pa_flags   = PFIL_IN | PFIL_HOOKPTR,
    .pa_headname = "inet", /* Link to the IPv4 stack */
    .pa_hook     = &pha,
};


static int
mod_handler(module_t mod, int what, void *arg)
{
    switch (what) {
    case MOD_LOAD:
        /*
         * MINIMAL CHANGE #4: Call pfil_link() after adding the hook.
         * This attaches the hook to the network stack so it will be called.
         */
        if (pfil_link(&pla) != 0) {
            printf("block_http: failed to link hook\n");
            return (ENODEV);
        }
        dropped_pkts = dropped_bytes = 0;
        printf("block_http: module loaded (tracking Host: blocked.com)\n");
        break;
    case MOD_UNLOAD:
        /* MINIMAL CHANGE #5: Unlink the hook before removing it. */
        pfil_unlink(&pla);
        printf("block_http: module unloaded (drops=%lu, bytes=%lu)\n",
               dropped_pkts, dropped_bytes);
        break;
    default:
        return (EOPNOTSUPP);
    }
    return (0);
}

static moduledata_t block_http_mod = {
    "block_http",
    mod_handler,
    NULL
};

DECLARE_MODULE(block_http, block_http_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(block_http, 1);

