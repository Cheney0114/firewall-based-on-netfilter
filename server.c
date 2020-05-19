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

struct ctrlheader ctrlhdr;
struct rule ruleList[51];
int ruleNum;

int defaultTarget = RU_ACCEPT;
struct rule *ruleDefault = &ruleList[0];

struct nf_hook_ops myhook;

struct rule *ruleNow;
struct sk_buff *skbNow;
struct iphdr *iphdrNow;

int chkBase()
{
    return 0;
}

int chkTime()
{
    return 0;
}

int chkStr()
{
    return 0;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    skbNow = skb;
    iphdrNow = ip_hdr(skb);
    for (int i = 1; i <= ruleNum; i++)
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
    ruleDefault->pkgs += 1;
    return rtarget2nf(defaultTarget);
}

static ssize_t read_info(struct file *fd, const char __user *buf, size_t len, loff_t *ppos)
{
    if (len < (ruleNum + 1) * RULESIZE)
    {
        printk("error: not enough space in read\n");
        return -1;
    }
    if (copy_to_user((void *)ruleList, buf, (ruleNum + 1) * RULESIZE))
    {
        printk("error: copy to uesr failed in read\n");
        return -1;
    }
    printk("info: read_info successfully\n");
    return (ruleNum + 1) * RULESIZE;
}

static ssize_t write_info(struct file *fd, const char __user *buf, size_t len, loff_t *ppos)
{
    if (copy_from_user((void *)(&ctrlhdr), buf, CTRLHDRSIZE))
    {
        printk("error: copy header failed in write\n");
        return -1;
    }
    printk("info: write_info:: copy header successfully\n");
    switch (ctrlhdr.ctrlType)
    {
    case CT_INSERT:
        for (int i = ruleNum; i >= 1; i--)
        {
            ruleList[i + ctrlhdr.len] = ruleList[i];
        }
        if (copy_from_user((void *)(ruleList + 1), buf, len - CTRLHDRSIZE))
        {
            printk("error: copy insert failed in write\n");
            return -1;
        }
        ruleNum += ctrlhdr.len;
        printk("info: write_info:: insert successfully\n");
        break;
    case CT_APPEND:
        if (copy_from_user((void *)(ruleList + 1 + ruleNum), buf, len - CTRLHDRSIZE))
        {
            printk("error: copy append failed in write\n");
            return -1;
        }
        ruleNum += ctrlhdr.len;
        printk("info: write_info:: append successfully\n");
        break;
    case CT_DELETE:
        if (ctrlhdr.len >= 1 && ctrlhdr.len <= ruleNum)
        {
            for (int i = ctrlhdr.len + 1; i <= ruleNum; i++)
            {
                ruleList[i - 1] = ruleList[i];
            }
            ruleNum -= 1;
            printk("info: write_info:: delete successfully\n");
        }
        else
        {
            printk("warning: write_info:: delete index overflow\n");
        }
        break;
    case CT_FLUSH:
        ruleNum = 0;
        printk("info: write_info:: flush successfully\n");
        break;
    case CT_DTAGET:
        if (defaultTarget != ctrlheader.len)
        {
            defaultTarget = ctrlhdr.len;
            ruleDefault->pkgs = 0;
            ruleDefault->bytes = 0;
            ruleDefault->target = defaultTarget;
            printk("info: write_info:: set default target successfully\n");
        }
        else
        {
            printk("info: write_info:: default target unchanged\n");
        }
        break;
    default:
        printk("error: unrecognized ctrl header\n");
        break;
    }
}

struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_info,
    .write = write_info,
};

static int __init initmodule(void)
{
    int ret;
    printk("Init Module\n");
    myhook.hook = hook_func;
    myhook.hooknum = NF_INET_PRE_ROUTING;
    myhook.pf = PF_INET;
    myhook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&myhook);
    ret = register_chrdev(124, devName, &fops);
    if (ret != 0)
        printk("Can't register device file! \n");
    ruleDefault->target = RU_ACCEPT;
    ruleDefault->pkgs = 0;
    ruleDefault->bytes = 0;
    printk("register successfully\n");
    return 0;
}

static void __exit cleanupmodule(void)
{
    nf_unregister_hook(&myhook);
    unregister_chrdev(124, devName);
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
MODULE_AUTHOR("GMQ.XXJ.XTF.CKQ");