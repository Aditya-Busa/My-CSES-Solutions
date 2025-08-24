#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/pfil.h>

static pfil_return_t
block_http(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    struct ip *ip;
    struct tcphdr *tcp;
    char *payload;
    int ip_hlen, tcp_hlen, payload_len;

    if (dir != PFIL_IN) return (PFIL_PASS);  // Only inbound packets

    ip = mtod(*mp, struct ip *);
    if (ip->ip_p != IPPROTO_TCP) return (PFIL_PASS);

    ip_hlen = ip->ip_hl << 2;
    tcp = (struct tcphdr *)((caddr_t)ip + ip_hlen);
    tcp_hlen = tcp->th_off << 2;
    payload_len = ntohs(ip->ip_len) - (ip_hlen + tcp_hlen);

    if (ntohs(tcp->th_dport) == 80 && payload_len > 0) {
        payload = (char *)tcp + tcp_hlen;

        if (memmem(payload, payload_len, "Host: blocked.com", 17) != NULL) {
            printf("Dropped HTTP packet for blocked.com, size=%d bytes\n", payload_len);
            return (PFIL_DROPPED);
        }
    }

    return (PFIL_PASS);
}

static struct pfil_hook *hook;
static struct pfil_hook_args pha = {
    .pha_version = PFIL_VERSION,
    .pha_type = PFIL_TYPE_IP4,
    .pha_hook = block_http,
    .pha_ruleset = NULL,
    .pha_flags = PFIL_IN,
};

static int
load_module(struct module *m, int event, void *arg)
{
    switch (event) {
    case MOD_LOAD:
        hook = pfil_add_hook(&pha);
        printf("HTTP blocking module loaded\n");
        break;
    case MOD_UNLOAD:
        pfil_remove_hook(hook);
        printf("HTTP blocking module unloaded\n");
        break;
    default:
        return (EOPNOTSUPP);
    }
    return (0);
}

MODULE_VERSION(block_http, 1);
DECLARE_MODULE(block_http, load_module, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
