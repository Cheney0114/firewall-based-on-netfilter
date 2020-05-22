#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>         //by llh
/*struct that is used for register hook*/
static struct nf_hook_ops nfho;

unsigned short in_pton(const char * port_str)
{
unsigned short p,i;

for(p =0,i=0;port_str[i]<='9'&&port_str[i]>='0';i++)
{
p = p *10 + (port_str[i] - '0');
}

i = (p >> 8) & 0x0000ff;
i |= (p << 8) & 0x00ff00;

return(i);
}


/* definition of hook function */
unsigned int hook_func(unsigned int hooknum,     //where to put the filter
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct sk_buff *pskb=skb;
    //struct tcphdr *thdr=(struct tcphdr *)(pskb->data + (pskb->nh.iph->ihl * 4));
    struct iphdr *ip_header=ip_hdr(pskb);
    struct tcphdr *thdr=tcp_hdr(pskb);
    //printk("%u %u  %u\n",(thdr->source),htons(ntohs(thdr->dest)),htons(23));
    if((ip_header->protocol/*pskb->nh.iph->protocol*/)!=IPPROTO_TCP) //check the protocol
    {
	printk("<0>""Not A TCP Packet: ACCEPT\n");
	return NF_ACCEPT;
    }
    else
    {
	if(thdr->dest == htons(23)/*in_pton("23")*/) //check the port
	{
	    //printk("%u DROP\n",in_pton("23"));
	    //printk("%d DROP\n",thdr->dest);
	    printk("<0>""000000000A TCP Packet PORT 23: DROP\n");
	    return NF_DROP;
	}
	else
	{
           printk("<0>""PORT Number is not 23: ACCEPT\n");
	   //printk("%u %u  -----------\n",thdr->source,thdr->dest);
           return NF_ACCEPT;
        }

    }
}

/* module initial function */
int init_module()
{
    /* init the struct */
    nfho.hook     = (nf_hookfn *)hook_func;         /* hook function */
    nfho.hooknum  = NF_INET_PRE_ROUTING; /* the hook point */
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;   /* priority */

    nf_register_hook(&nfho);           /* register the hook */

    return 0;
}

/* module clean function */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
    printk("<0>""exit 0!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("llh");
