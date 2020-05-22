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

int chkBase(void)
{
    return 1;
}

int chkTime(void)
{
    struct timex txc;
    struct rtc_time tm;
    struct rtc_time *p;

    do_gettimeofday(&txc.time); //获取当前UTC时间
    // txc.time.tv_sec += 8 * 60 * 60;
    txc.time.tv_sec -= sys_tz.tz_minuteswest * 60; //把UTC时间调整为本地时间
    rtc_time_to_tm(txc.time.tv_sec, &tm);          //算出时间中的年月日等数值到tm中
    p = &tm;

    printk("%d %d %d ", (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday);
    printk("%d %d:%d:%d\n", p->tm_wday, p->tm_hour, p->tm_min, p->tm_sec);

    if (ruleNow->timeFlag & TIME)
    {
        int timeSec;
        printk("into TIME\n");
        timeSec = (p->tm_hour) * 3600 + (p->tm_min) * 60 + p->tm_sec;
        if (timeSec >= ruleNow->timeStart && timeSec <= ruleNow->timeEnd)
        {
            return 1;
        }
        return 0;
    }
    else if ((ruleNow->timeFlag & DATESTART) || (ruleNow->timeFlag & DATEEND))
    {
        int flag;
        flag = 1;
        printk("into DATESTART DATEEND\n");
        if (ruleNow->timeFlag & DATESTART)
        {
            int monthStart;
            int dayStart;
            monthStart = ruleNow->dateStart / 100;
            dayStart = ruleNow->dateStart % 100;
            printk("DATESTART:%d %d\n", monthStart, dayStart);
            if (!(p->tm_mon >= monthStart && p->tm_mday >= dayStart))
            {
                flag &= 0;
            }
        }
        if (ruleNow->timeFlag & DATEEND)
        {
            int monthEnd;
            int dayEnd;
            monthEnd = ruleNow->dateEnd / 100;
            dayEnd = ruleNow->dateEnd % 100;
            printk("DATEEND:%d %d\n", monthEnd, dayEnd);
            if (!(p->tm_mon <= monthEnd && p->tm_mday <= dayEnd))
            {
                flag &= 0;
            }
        }
        return flag;
    }
    else if (ruleNow->timeFlag & WEEKDAYS)
    {
        int timeWeek;
        int flag;
        printk("into WEEKDAYS\n");
        timeWeek = 1 << p->tm_wday;
        printk("%d,%d,%d\n", timeWeek, ruleNow->weekdays, timeWeek & ruleNow->weekdays);
        flag = ((timeWeek & ruleNow->weekdays) ? 1 : 0);
        if (ruleNow->timeFlag & WEEKNOT)
        {
            flag = 1 - flag;
        }
        return flag;
    }
    else if (ruleNow->timeFlag & MONTHDAYS)
    {
        int timeDay;
        int flag;

        printk("into MONTHDAYS\n");
        timeDay = 1 << p->tm_mday;
        printk("%x,%x,%x\n", timeDay, ruleNow->monthdays, timeDay & ruleNow->monthdays);
        flag = ((timeDay & ruleNow->monthdays) ? 1 : 0);
        if (ruleNow->timeFlag & MONTHNOT)
        {
            flag = 1 - flag;
        }
        return flag;
    }
    return 1;
}

int chkStr(void)
{
    return 1;
}

unsigned int hook_func(unsigned int hooknum, //where to put the filter
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    int i;
    skbNow = skb;
    iphdrNow = ip_hdr(skb);
    for (i = 1; i <= ruleNum; i++)
    {
        int flag;
        ruleNow = ruleList + i;
        flag = chkBase();
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
    if (copy_to_user(buf, (void *)ruleList, (ruleNum + 1) * RULESIZE))
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
    {
        int i;
        for (i = ruleNum; i >= 1; i--)
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
    }
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
            int i;
            for (i = ctrlhdr.len + 1; i <= ruleNum; i++)
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
        if (defaultTarget != ctrlhdr.len)
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
    return len;
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
    myhook.hook = (nf_hookfn *)hook_func;
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
