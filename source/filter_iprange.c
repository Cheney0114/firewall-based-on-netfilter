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
//#include <arpa/inet.h>
#include <linux/inet.h>         //by llh
//#include <linux/netfilter.h>   //by llh
/*struct that is used for register hook*/
static struct nf_hook_ops nfho;


unsigned int ip2num(unsigned int ip)
{
	unsigned int num;
	unsigned int a, b, c, d;
	a = ip >> 0 & 0xff;
	num = a;
	b = ip >> 8 & 0xff;
	num = num * 0x100 + b;
	c = ip >> 16 & 0xff;
	num = num * 0x100 + c;
	d = ip >> 24 & 0xff;
	num = num * 0x100 + d;
	printk("ip: %d.%d.%d.%d\n", a, b, c, d);

	return num;
}

unsigned int ipstr2num(char* ipstr)
{
	unsigned int num;
	num = ip2num(in_aton(ipstr));

	return num;
}


/* definition of hook function */
unsigned int hook_func(unsigned int hooknum,     		 //where to put the filter
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

	//printk("%x\n", ip2num(ip_header->saddr));
	//printk("%x\n", ipstr2num("192.168.1.102"));
    if(ip2num(ip_header->saddr) < ipstr2num("192.168.1.102")) //check the source
    {
		printk("<0>A Packet from 192.168.1.102: DROP\n");
		return NF_DROP;
    }
	else
    {
		printk("################  enter  #################\n");
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
