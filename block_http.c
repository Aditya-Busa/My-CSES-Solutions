/* myfirewall.c - FreeBSD 13.4 kernel module
 * Blocks inbound HTTP packets with "Host: blocked.com"
 * Logs drop count + total bytes
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/counter.h>
#include <sys/systm.h>     /* kernel printf(), uprintf() */

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* --- config --- */
#define HTTP_PORT   80
#define SCAN_BYTES  2048
#define NEEDLE1     "Host: blocked.com"
#define NEEDLE2     "host: blocked.com"

MALLOC_DEFINE(M_MYFIREWALL, "myfirewall", "MyFirewall temp buffers");

/* counters */
static counter_u64_t drop_count;
static counter_u64_t drop_bytes;

/* hook handle */
static pfil_hook_t *pfh_in = NULL;

/* simple memsearch */
static __inline bool
memfind(const char *hay, int hlen, const char *needle, int nlen)
{
    if (nlen <= 0 || hlen < nlen) return false;
    for (int i = 0; i <= hlen - nlen; i++) {
        if (bcmp(hay + i, needle, nlen) == 0)
            return true;
    }
    return false;
}

static int
myfirewall_func(void *arg, struct mbuf **mp, struct ifnet *ifp,
                int dir, struct inpcb *inp)
{
    struct mbuf *m = *mp;
    struct ip *ip;
    struct tcphdr *th;
    int ip_hl, tcp_hl, total_len, payload_off, payload_len;

    if (dir != PFIL_IN || m == NULL)
        return (0);

    /* IPv4 header */
    if (m->m_len < (int)sizeof(struct ip)) {
        m = m_pullup(m, sizeof(struct ip));
        if (m == NULL) { *mp = NULL; return (0); }
        *mp = m;
    }
    ip = mtod(m, struct ip *);

    if (ip->ip_v != IPVERSION || ip->ip_p != IPPROTO_TCP)
        return (0);

    /* skip fragments */
    if (ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK))
        return (0);

    ip_hl = ip->ip_hl << 2;
    if (ip_hl < (int)sizeof(struct ip))
        return (0);

    if (m->m_len < ip_hl + (int)sizeof(struct tcphdr)) {
        m = m_pullup(m, ip_hl + (int)sizeof(struct tcphdr));
        if (m == NULL) { *mp = NULL; return (0); }
        *mp = m;
        ip = mtod(m, struct ip *);
    }
    th = (struct tcphdr *)((caddr_t)ip + ip_hl);

    if (ntohs(th->th_dport) != HTTP_PORT)
        return (0);

    tcp_hl = th->th_off << 2;
    if (tcp_hl < (int)sizeof(struct tcphdr))
        return (0);

    if (m->m_len < ip_hl + tcp_hl) {
        m = m_pullup(m, ip_hl + tcp_hl);
        if (m == NULL) { *mp = NULL; return (0); }
        *mp = m;
        ip = mtod(m, struct ip *);
        th = (struct tcphdr *)((caddr_t)ip + ip_hl);
    }

    total_len = ntohs(ip->ip_len);
    payload_off = ip_hl + tcp_hl;
    payload_len = total_len - payload_off;
    if (payload_len <= 0)
        return (0);

    int to_copy = payload_len < SCAN_BYTES ? payload_len : SCAN_BYTES;
    char *buf = (char *)malloc(to_copy, M_MYFIREWALL, M_NOWAIT);
    if (buf == NULL)
        return (0);

    m_copydata(m, payload_off, to_copy, buf);

    bool blocked = false;
    if (memfind(buf, to_copy, NEEDLE1, (int)sizeof(NEEDLE1) - 1) ||
        memfind(buf, to_copy, NEEDLE2, (int)sizeof(NEEDLE2) - 1)) {
        blocked = true;
    }

    if (blocked) {
        counter_u64_add(drop_count, 1);
        counter_u64_add(drop_bytes, payload_len);

        printf("MyFirewall: DROP Host: blocked.com size=%d total_drops=%ju bytes=%ju\n",
               payload_len,
               (uintmax_t)counter_u64_fetch(drop_count),
               (uintmax_t)counter_u64_fetch(drop_bytes));

        m_freem(m);
        *mp = NULL;
        free(buf, M_MYFIREWALL);
        return (EACCES);
    }

    free(buf, M_MYFIREWALL);
    return (0);
}

static int
load(struct module *m, int cmd, void *arg)
{
    int error = 0;

    switch (cmd) {
    case MOD_LOAD: {
        struct pfil_hook_args pha;
        memset(&pha, 0, sizeof(pha));
        pha.pa_version = PFIL_VERSION;
        pha.pa_type    = PFIL_TYPE_AF;
        pha.pa_af      = AF_INET;
        pha.pa_func    = myfirewall_func;
        pha.pa_modname = "myfirewall";

        drop_count = counter_u64_alloc(M_WAITOK);
        drop_bytes = counter_u64_alloc(M_WAITOK);

        pfh_in = pfil_add_hook(&pha);
        if (pfh_in == NULL) {
            printf("MyFirewall: failed to register hook\n");
            counter_u64_free(drop_count);
            counter_u64_free(drop_bytes);
            return (ENOMEM);
        }
        printf("MyFirewall module loaded.\n");
        break;
    }
    case MOD_UNLOAD:
        if (pfh_in != NULL) {
            pfil_remove_hook(pfh_in);
            pfh_in = NULL;
        }
        printf("MyFirewall unloaded. drops=%ju bytes=%ju\n",
               (uintmax_t)counter_u64_fetch(drop_count),
               (uintmax_t)counter_u64_fetch(drop_bytes));
        counter_u64_free(drop_count);
        counter_u64_free(drop_bytes);
        break;

    default:
        error = EOPNOTSUPP;
        break;
    }
    return (error);
}

static moduledata_t myfirewall_mod = {
    "myfirewall",
    load,
    NULL
};

DECLARE_MODULE(myfirewall, myfirewall_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
