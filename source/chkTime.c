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
#include <linux/inet.h> //by llh
//#include <linux/netfilter.h>   //by llh
/*struct that is used for register hook*/
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

#include "/home/cheney/firewall/firewall-based-on-netfilter/mymod/rule.h"

static struct nf_hook_ops nfho;

int timeFlag = 0;
int timeStart;
int timeEnd;
int dateStart;
int dateEnd;
int weekdays;
int monthdays;

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

    if (timeFlag & TIME)
    {
        int timeSec;
        printk("into TIME\n");
        timeSec = (p->tm_hour) * 3600 + (p->tm_min) * 60 + p->tm_sec;
        if (timeSec >= timeStart && timeSec <= timeEnd)
        {
            return 1;
        }
        return 0;
    }
    else if ((timeFlag & DATESTART) || (timeFlag & DATEEND))
    {
        int flag;
        flag = 1;
        printk("into DATESTART DATEEND\n");
        if (timeFlag & DATESTART)
        {
            int monthStart;
            int dayStart;
            monthStart = dateStart / 100;
            dayStart = dateStart % 100;
            printk("DATESTART:%d %d\n", monthStart, dayStart);
            if (!(p->tm_mon >= monthStart && p->tm_mday >= dayStart))
            {
                flag &= 0;
            }
        }
        if (timeFlag & DATEEND)
        {
            int monthEnd;
            int dayEnd;
            monthEnd = dateEnd / 100;
            dayEnd = dateEnd % 100;
            printk("DATEEND:%d %d\n", monthEnd, dayEnd);
            if (!(p->tm_mon <= monthEnd && p->tm_mday <= dayEnd))
            {
                flag &= 0;
            }
        }
        return flag;
    }
    else if (timeFlag & WEEKDAYS)
    {
        int timeWeek;
        int flag;
        printk("into WEEKDAYS\n");
        timeWeek = 1 << p->tm_wday;
        printk("%d,%d,%d\n", timeWeek, weekdays, timeWeek & weekdays);
        flag = ((timeWeek & weekdays) ? 1 : 0);
        if (timeFlag & WEEKNOT)
        {
            flag = 1 - flag;
        }
        return flag;
    }
    else if (timeFlag & MONTHDAYS)
    {
        int timeDay;
        int flag;

        printk("into MONTHDAYS\n");
        timeDay = 1 << p->tm_mday;
        printk("%x,%x,%x\n", timeDay, monthdays, timeDay & monthdays);
        flag = ((timeDay & monthdays) ? 1 : 0);
        if (timeFlag & MONTHNOT)
        {
            flag = 1 - flag;
        }
        return flag;
    }
    return 1;
}

/* definition of hook function */
unsigned int hook_func(unsigned int hooknum, //where to put the filter
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    if (chkTime())
        return NF_DROP;
    return NF_ACCEPT;
}

/* module initial function */
int init_module()
{
    /* init the struct */
    nfho.hook = (nf_hookfn *)hook_func; /* hook function */
    nfho.hooknum = NF_INET_PRE_ROUTING; /*NF_IP_PRE_ROUTING;by llh  the hook point */
    nfho.pf = PF_INET;                  /* potocol family */
    nfho.priority = NF_IP_PRI_FIRST;    /* priority */

    nf_register_hook(&nfho); /* register the hook */

    return 0;
}

/* module clean function */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
    printk("<0>"
           "exit!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("llh");
