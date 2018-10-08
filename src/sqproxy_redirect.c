#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netpoll.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/gfp.h>
#include <linux/slab.h>  // kmalloc

#include "utils.h"
#include "hooks.h"

#include "uthash.h"

#undef uthash_malloc
#undef uthash_free
#undef uthash_fatal

#define uthash_malloc(sz) kmalloc(sz, GFP_KERNEL)
#define uthash_free(ptr,sz) kfree(ptr)
#define uthash_fatal(msg) printk(KERN_ERR "%s", msg)


/* Used to describe our Netfilter hooks */
struct nf_hook_ops nf_pre_hook;  /* Incoming */
struct nf_hook_ops nf_post_hook;  /* Outgoing */


/* Initialisation routine */
int init_module()
{
	/* Fill in our hook structure */
	nf_pre_hook.pf = PF_INET;
	nf_pre_hook.hook = pre_hook;  /* Handler function */
	nf_pre_hook.priority = NF_IP_PRI_FIRST;  /* Make our function first */
	nf_pre_hook.hooknum  = NF_INET_PRE_ROUTING;  /* First hook for IPv4 */

	nf_register_hook(&nf_pre_hook);

	nf_post_hook.pf = PF_INET;
	nf_post_hook.hook = post_hook;  /* Handler function */
	nf_post_hook.priority = NF_IP_PRI_FIRST;  /* Make our function first */
	nf_post_hook.hooknum  = NF_INET_POST_ROUTING;  /* First hook for IPv4 */

	nf_register_hook(&nf_post_hook);

	return 0;
}

/* Cleanup routine */
void cleanup_module()
{
	nf_unregister_hook(&nf_pre_hook);
	nf_unregister_hook(&nf_post_hook);

}


MODULE_LICENSE("GPL");
