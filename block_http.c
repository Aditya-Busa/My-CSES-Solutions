#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>

static pfil_hook_t pfh_in = NULL;

/* Hook function */
static pfil_return_t
block_http_func(pfil_packet_t pkt, struct ifnet *ifp, int dir, void *ctx, struct inpcb *inp)
{
    struct mbuf *m = (struct mbuf *)pkt;
    if (m == NULL)
        return (0);

    if (dir & PFIL_IN) {
        printf("BlockHTTP(minimal): packet seen on %s\n", ifp->if_xname);
    }

    return (0);  /* always allow */
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
        pha.pa_flags   = PFIL_IN;
        pha.pa_type    = PFIL_TYPE_IFNET;   /* inbound interface hook */
        pha.pa_func    = block_http_func;
        pha.pa_ruleset = NULL;
        pha.pa_modname = "block_http";
        pha.pa_rulname = "blockhttp";

        pfh_in = pfil_add_hook(&pha);
        if (pfh_in == NULL) {
            printf("BlockHTTP(minimal): failed to register hook\n");
            return (ENOMEM);
        }
        printf("BlockHTTP(minimal): module loaded.\n");
        break;
    }
    case MOD_UNLOAD:
        if (pfh_in != NULL) {
            pfil_remove_hook(pfh_in);
            pfh_in = NULL;
        }
        printf("BlockHTTP(minimal): module unloaded.\n");
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }
    return (error);
}

static moduledata_t block_http_mod = {
    "block_http",
    load,
    NULL
};

DECLARE_MODULE(block_http, block_http_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
