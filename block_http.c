#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/types.h>     /* uintptr_t */

#include <net/if.h>
#include <net/if_var.h>    /* if_xname */
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>

/* ---- Compatibility shims ---- */
#ifndef PFIL_IN
#define PFIL_IN 0x0001
#endif

/* Choose an available pa_type at compile time */
#if defined(PFIL_TYPE_AF)
#  define BLOCKHTTP_PFIL_TYPE PFIL_TYPE_AF
#elif defined(PFIL_TYPE_IFNET)
#  define BLOCKHTTP_PFIL_TYPE PFIL_TYPE_IFNET
#else
/* Fallback: some trees accept 0 for pa_type */
#  define BLOCKHTTP_PFIL_TYPE 0
#endif

/* Convert pfil_packet_t to struct mbuf* safely across typedef variants */
#ifndef PKT_TO_MBUF
#  define PKT_TO_MBUF(p) ((struct mbuf *)(uintptr_t)(p))
#endif
/* ----------------------------- */

static pfil_hook_t pfh_in = NULL;

/* Hook function */
static pfil_return_t
block_http_func(pfil_packet_t pkt, struct ifnet *ifp, int dir, void *ctx, struct inpcb *inp)
{
    struct mbuf *m = PKT_TO_MBUF(pkt);   /* works whether pfil_packet_t is ptr or int */
    if (m == NULL)
        return 0;

    if (dir & PFIL_IN) {
        /* ifp may be opaque in some configs; if_xname is fine with <net/if_var.h> */
        printf("BlockHTTP(minimal): packet seen on %s\n", ifp ? ifp->if_xname : "(null-ifp)");
    }
    return 0; /* always allow */
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
        pha.pa_type    = BLOCKHTTP_PFIL_TYPE;
        pha.pa_func    = block_http_func;
        pha.pa_ruleset = NULL;
        pha.pa_modname = "block_http";
        pha.pa_rulname = "blockhttp";

        pfh_in = pfil_add_hook(&pha);
        if (pfh_in == NULL) {
            printf("BlockHTTP(minimal): failed to register hook (pa_type=%d)\n", (int)BLOCKHTTP_PFIL_TYPE);
            return ENOMEM;
        }
        printf("BlockHTTP(minimal): module loaded (PFIL_VERSION=%d, pa_type=%d)\n",
               (int)PFIL_VERSION, (int)BLOCKHTTP_PFIL_TYPE);
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
    return error;
}

static moduledata_t block_http_mod = {
    "block_http",
    load,
    NULL
};

DECLARE_MODULE(block_http, block_http_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
