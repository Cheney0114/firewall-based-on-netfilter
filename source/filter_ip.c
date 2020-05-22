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
//#include <linux/netfilter.h>   //by llh
/*struct that is used for register hook*/
static struct nf_hook_ops nfho;


/* definition of hook function */
unsigned int hook_func(unsigned int hooknum,      //where to put the filter
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct sk_buff *pskb=skb;

    struct iphdr *ip_header = ip_hdr(pskb);
   /* printk("package from %d.%d.%d.%d\n",ip_header->saddr&0x000000FF,
    (ip_header->saddr&0x0000FF00)>>8,
    (ip_header->saddr&0x00FF0000)>>16,
    (ip_header->saddr&0xFF000000)>>24);*/
    if((ip_header->saddr/*nh.iph->saddr by llh*/)==in_aton("192.168.0.103")) //check the source
    {
	printk("<0>""A Packet from 192.168.0.103: DROP\n");
	return NF_DROP;
    }
    else
    {
	return NF_ACCEPT;
    }

}

/* module initial function */
int init_module()
{
    /* init the struct */
    nfho.hook     = (nf_hookfn *)hook_func;         /* hook function */
    nfho.hooknum  = NF_INET_PRE_ROUTING;/*NF_IP_PRE_ROUTING;by llh  the hook point */
    nfho.pf       = PF_INET;           /* potocol family */
    nfho.priority = NF_IP_PRI_FIRST;   /* priority */

    nf_register_hook(&nfho);           /* register the hook */

    return 0;
}

/* module clean function */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
    printk("<0>""exit!\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("llh");
