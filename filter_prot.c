#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>         //by llh
/*struct that is used for register hook*/
static struct nf_hook_ops nfho;


/* definition of hook function */
unsigned int hook_func(unsigned int hooknum,   //where to put the filter
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct sk_buff *pskb=skb;
    struct iphdr *ip_header=ip_hdr(pskb);
    switch(ip_header->protocol/*pskb->nh.iph->protocol*/)   //check the protocol
    {
	case IPPROTO_ICMP:
	    {
		printk("ICMP Packet: DROP\n");
		return NF_DROP;
	    }
	case IPPROTO_TCP:
	    {
		printk("TCP Packet: ACCEPT\n");
		return NF_ACCEPT;
	    }
	case IPPROTO_UDP:
	    {
		printk("UDP Packet: ACCEPT\n");
		return NF_ACCEPT;
	    }
	default:
	    {
		printk("Unknown Packet: DROP\n");
		return NF_DROP;
	    }
    }
}

/* module initial function */
int init_module()
{
   /* init the struct */
    nfho.hook     = (nf_hookfn *)hook_func;         /* hook function */
    nfho.hooknum  = NF_INET_PRE_ROUTING;  /* the hook point */
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;    /* priority */

    nf_register_hook(&nfho);            /* register the hook */
   
    return 0;
}
   
/* module clean function */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("llh");
