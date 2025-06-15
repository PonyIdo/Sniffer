#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


static unsigned int drop_google(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    /*struct iphdr *ip_header;
    struct udphdr *udp_header;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    //if (ip_header->protocol == IPPROTO_UDP)*/
    printk(KERN_DEBUG "caught!\n");
    return NF_DROP;
}

struct nf_hook_ops *netfilter_hook;

static int __init EntryFunction(void){
    printk(KERN_DEBUG "Hello!\n");
    netfilter_hook = kmalloc(sizeof(const struct nf_hook_ops), GFP_KERNEL | __GFP_ZERO);
    netfilter_hook->hook = drop_google;
    netfilter_hook->hooknum = NF_INET_PRE_ROUTING;
    netfilter_hook->pf = PF_INET;
    netfilter_hook->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, netfilter_hook);
    
    
    return 0;
}

static void __exit ExitFunction(void){
    nf_unregister_net_hook(&init_net, netfilter_hook);
    kfree(netfilter_hook);
    printk(KERN_DEBUG "Bye!\n");
}

module_init(EntryFunction);
module_exit(ExitFunction);
MODULE_LICENSE("Dual BSD/GPL");