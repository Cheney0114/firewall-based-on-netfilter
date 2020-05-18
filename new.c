#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

#include "rule.h"
int rtarget2nf(int); /*将rule中定义的target转换成netfiliter中定义的target,便于hook_func的return*/

struct rule ruleList[1000];
int ruleNum;

struct nf_hook_ops myhook;

struct rule *ruleNow;
struct sk_buff *skbNow;
struct iphdr *iphdrNow;

int chkBase()
{
}

int chkTime()
{
}

int chkStr()
{
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    skbNow = skb;
    iphdr = ip_hdr(skb);
    for (int i = 0; i < ruleNum; i++)
    {
        ruleNow = ruleList + i;
        int flag = chkBase();
        if (ruleNow->timeFlag)
        {
            flag &= chkTime();
        }
        if (ruleNow->strFlag)
        {
            flag &= chkStr();
        }
        if (flag)
        {
            ruleNow->pkgs += 1;
            return rtarget2nf(ruleNow->target);
        }
    }
    return NF_ACCEPT;
}

static ssize_t write_controlinfo(struct file *fd, const char __user *buf, size_t len, loff_t *ppos)
{

    if (len == 0)
    {
        return len;
    }
    if (copy_from_user(ruleList, buf, len) != 0)
    {
        printk("Can't get the control rule! \n");
        printk("Something may be wrong, please check it! \n");
        return 0;
    }
    ruleNum = len / RULESIZE;
    return len;
}

struct file_operations fops = {
    .owner = THIS_MODULE,
    .write = write_controlinfo,
};

static int __init initmodule(void)
{
    int ret;
    printk("Init Module\n");
    myhook.hook = hook_func;
    myhook.hooknum = NF_INET_POST_ROUTING;
    myhook.pf = PF_INET;
    myhook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&myhook);
    ret = register_chrdev(124, "/dev/controlinfo", &fops);
    if (ret != 0)
        printk("Can't register device file! \n");
    return 0;
}

static void __exit cleanupmodule(void)
{
    nf_unregister_hook(&myhook);
    unregister_chrdev(124, "controlinfo");
    printk("CleanUp\n");
}

int rtarget2nf(int rtarget)
{
    if (rtarget == RU_ACCEPT)
        return NF_ACCEPT;
    if (rtarget == RU_DROP)
        return NF_DROP;
    printk("error: user target does not exist\n");
    return NF_ACCEPT;
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("WJ_Yuan");