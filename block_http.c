#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/pfil.h>

static int myfirewall_func(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp) {
    struct mbuf *m = *mp;

    // Ensure packet is TCP over IP
    struct ip *ip = mtod(m, struct ip *);
    if (ip->ip_p != IPPROTO_TCP) return 0;

    // Access TCP header
    int ip_len = ip->ip_hl << 2;
    struct tcphdr *th = (struct tcphdr *)((caddr_t)ip + ip_len);

    // Check if destination port is HTTP (80)
    if (ntohs(th->th_dport) == 80) {
        // Extract payload
        int hdr_len = th->th_off << 2;
        char *payload = (char *)((caddr_t)th + hdr_len);
        int payload_len = ntohs(ip->ip_len) - ip_len - hdr_len;

        if (payload_len > 0 && payload != NULL) {
            // Look for "Host: blocked.com"
            if (memmem(payload, payload_len, "Host: blocked.com", 16) != NULL) {
                printf("Blocked HTTP packet (size: %d)\n", payload_len);
                m_freem(m);  // free packet buffer
                *mp = NULL;
                return (EACCES); // drop
            }
        }
    }
    return 0; // accept
}

static struct pfil_head *pfh_inet;
static int load(struct module *m, int cmd, void *arg) {
    switch (cmd) {
    case MOD_LOAD:
        pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
        if (pfh_inet == NULL) return (EINVAL);
        pfil_add_hook(myfirewall_func, NULL, PFIL_IN, pfh_inet);
        printf("MyFirewall module loaded.\n");
        break;
    case MOD_UNLOAD:
        pfil_remove_hook(myfirewall_func, NULL, PFIL_IN, pfh_inet);
        printf("MyFirewall module unloaded.\n");
        break;
    }
    return 0;
}

static moduledata_t myfirewall_mod = {
    "myfirewall", load, NULL
};
DECLARE_MODULE(myfirewall, myfirewall_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
