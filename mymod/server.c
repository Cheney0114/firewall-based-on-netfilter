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
#include <linux/inet.h>

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

void display(struct rule *item)
{
    printk("%d%d,%d%d,%d%d%d,%d%d%d\n", item->pkgs, item->bytes, item->protocol, item->target, item->saddr, item->smark, item->sport, item->daddr, item->dmark, item->dport);
    printk("timeflag:%d,%d%d,%d%d,%d,%d\n", item->timeFlag, item->timeStart, item->timeEnd, item->dateStart, item->dateEnd, item->weekdays, item->monthdays);
    printk("strFlag:%d,%s\n",item->strFlag,item->strPattern);
    printk("\n");
}


int chkBase(void) //检查基础功能——IP,端口,掩码,协议
{
    int flag = 1;

    if((iphdrNow->saddr & ruleNow->smark)==in_aton(ruleNow->saddr) >> (32 - ruleNow->smark) << (32 - ruleNow->smark)) //check the saddr
        flag &= 1;
    else
	    flag &= 0;
   
    if((iphdrNow->daddr & ruleNow->dmark)==in_aton(ruleNow->daddr) >> (32 - ruleNow->dmark) << (32 - ruleNow->dmark))
        flag &= 1;
    else
	    flag &= 0; 

    if(iphdrNow->protocol == IPPROTO_ICMP && !strncasecmp(ruleNow->protocol, "icmp", 4))
        flag &= 1;
    else if(iphdrNow->protocol == IPPROTO_TCP && !strncasecmp(ruleNow->protocol, "tcp", 3))
        flag &= 1;
    else if(iphdrNow->protocol == IPPROTO_UDP && !strncasecmp(ruleNow->protocol, "udp", 3))
        flag &= 1;
    else if(!strncasecmp(ruleNow->protocol, "all", 3))
        flag &= 1;
    else
        flag &= 0;
    

    if(ruleNow->dport >= 0 && (iphdrNow->protocol)!=IPPROTO_TCP && (iphdrNow->protocol)!=IPPROTO_UDP) 
        flag &= 0;
    else if(ruleNow->dport >= 0)
    {
        if(iphdrNow->protocol == IPPROTO_TCP){
            struct tcphdr *thdr = tcp_hdr(skbNow);
            if(thdr->dest == htons(ruleNow->dport)) //check the dport
                flag &= 1;
	        else    
                flag &= 0;
        }
        else{ 
            struct udphdr *uhdr = udp_hdr(skbNow);
            if(uhdr->dest == htons(ruleNow->dport)) //check the dport
                flag &= 1;
	        else    
                flag &= 0;
        }
    }

    if(ruleNow->sport >= 0 && (iphdrNow->protocol)!=IPPROTO_TCP && (iphdrNow->protocol)!=IPPROTO_UDP) 
        flag &= 0;
    else if(ruleNow->sport >= 0)
    {
        if(iphdrNow->protocol == IPPROTO_TCP){
            struct tcphdr *thdr = tcp_hdr(skbNow);
            if(thdr->source == htons(ruleNow->sport)) //check the dport
                flag &= 1;
	        else    
                flag &= 0;
        }
        else{ 
            struct udphdr *uhdr = udp_hdr(skbNow);
            if(uhdr->source == htons(ruleNow->sport)) //check the dport
                flag &= 1;
	        else    
                flag &= 0;
        }
    }

    //check flag
    if(ruleNow->flags[0] && (iphdrNow->protocol)!=IPPROTO_TCP)
        flag &= 0;
    else if(ruleNow->flags[0]){
        struct tcphdr *thdr = tcp_hdr(skbNow);
        if(ruleNow->flags[1])
            flag &= thdr->fin;
        if(ruleNow->flags[2])
            flag &= thdr->syn;
        if(ruleNow->flags[3])
            flag &= thdr->rst;
        if(ruleNow->flags[4])
            flag &= thdr->psh;
        if(ruleNow->flags[5])
            flag &= thdr->ack;
        if(ruleNow->flags[6])
            flag &= thdr->urg;
        
    }

    return flag;
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

    // printk("%d %d %d ", (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday);
    // printk("%d %d:%d:%d\n", p->tm_wday, p->tm_hour, p->tm_min, p->tm_sec);

    if (ruleNow->timeFlag & TIME)
    {
        int timeSec;
        // printk("into TIME\n");
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
        // printk("into DATESTART DATEEND\n");
        if (ruleNow->timeFlag & DATESTART)
        {
            int monthStart;
            int dayStart;
            monthStart = ruleNow->dateStart / 100;
            dayStart = ruleNow->dateStart % 100;
            // printk("DATESTART:%d %d\n", monthStart, dayStart);
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
            // printk("DATEEND:%d %d\n", monthEnd, dayEnd);
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
        // printk("into WEEKDAYS\n");
        timeWeek = 1 << p->tm_wday;
        // printk("%d,%d,%d\n", timeWeek, ruleNow->weekdays, timeWeek & ruleNow->weekdays);
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

        // printk("into MONTHDAYS\n");
        timeDay = 1 << p->tm_mday;
        // printk("%x,%x,%x\n", timeDay, ruleNow->monthdays, timeDay & ruleNow->monthdays);
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
    //return 1表示可以规则匹配
    //return 0表示不能规则不匹配
    //使用ruleNow->strFlag 和 ruleNow->strPattern[STRPATSIZE + 1];

    int i, j, k; //循环变量

    struct sk_buff *pskb = skbNow; //pskb就是skbNow，只不过是前期写的代码用的pskb，移植过来就依然用pskb了

    char *datap = pskb->data;                    //取出包中的数据
    int pskblen = pskb->len;                     //包长度
    int stringlen = strlen(ruleNow->strPattern); //匹配串长度
    int allmatch = 0;                            //匹配次数
    int match = 0;                               //单次的匹配的状态
    char ch1, ch2;

    if (ruleNow->strFlag == 0) //strFlag设置为0表示没有设置包内容匹配规则，非零表示要接收包，字符串最多出现的次数
        return 1;

    for (i = 0; i <= pskb->len - stringlen; i++)
    {
        match = 1;
        ch1 = pskb->data[i];
	for (k = i, j = 0; j < stringlen && ruleNow->strPattern[j]==pskb->data[k];j++,k++) {}

        if (j==stringlen)
        {
            //说明匹配了整个串
            allmatch += 1;
        }

        //检测allmatch
        if (allmatch >= ruleNow->strFlag)
        {
            printk("<0> A Packet match the strRule\n");
            return 1;
        }
    }
    return 0;
}

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

int chkIprange(void)
{
	if (ruleNow->iprangeFlag & ruleNow->iprange_in) { // 1 means out is band
		if(ip2num(iphdrNow->saddr) <= ip2num(in_aton(ruleNow->ipstart))) { // 去掉小于start的ip
			printk("<0>A Packet DROP\n");
			return 0;
		} else if(ip2num(iphdrNow->saddr) >= ip2num(in_aton(ruleNow->ipend))) { // 去掉大于end的ip
			printk("<0>A Packet DROP\n");
			return 0;
		} else {
			printk("################  enter  #################\n");
			return 1;
		}
	} else if (ruleNow->iprangeFlag & ~ruleNow->iprange_in) {
		if(ip2num(iphdrNow->saddr) <= ip2num(in_aton(ruleNow->ipstart))) { // 允许小于start的ip
			printk("################  enter  #################\n");
			return 1;
		} else if(ip2num(iphdrNow->saddr) >= ip2num(in_aton(ruleNow->ipend))) { // 允许大于end的ip
			printk("################  enter  #################\n");
			return 1;
		} else {
			printk("<0>A Packet DROP\n");
			return 0;
		}
	}
    return 1;
}


uint32_t get_nowtime(void){
	struct timeval tv;
	do_gettimeofday(&tv);
	uint32_t t = tv.tv_sec*1000+tv.tv_usec/1000;
	printk("millisecond:%ld\n", t);
	return t;
}

uint32_t parse_rate(const char* rate, uint32_t* val){
	char *delim;
	uint32_t r;	
	uint32_t mult = 1;
	
	delim = strchr(rate, '/');
	if(delim){
		if(strlen(delim+1) == 0)
			return 0;

		if(strncasecmp(delim+1, "second", strlen(delim + 1)) == 0)
			mult = 1;
		else if(strncasecmp(delim+1, "minute", strlen(delim + 1)) == 0)
			mult = 60;
		else if(strncasecmp(delim+1, "hour", strlen(delim + 1)) == 0)
			mult = 60*60;
		else if(strncasecmp(delim+1, "day", strlen(delim + 1)) == 0)
			mult = 60*60*24;
		else
			return 0;
	}
	r = simple_strtol(rate, &delim, 10);
	if(!r)
		return 0;
	*val = 1000 * mult / r;
	return 1;
}

int chkLimit(void){
	if(ruleNow->limitFlag == 1){
        ruleNow->limitFlag = -1;
        if(!parse_rate(ruleNow->rateStr, &(ruleNow->rate))){
            printk("sry, limit format is illegal.\n");
        }
        printk("this rule rate is %d\n", ruleNow->rate);
        ruleNow->lastTime = get_nowtime();
        return 1;
    }
	uint32_t t = get_nowtime();
    uint32_t tmp = (t - ruleNow->lastTime) / ruleNow->rate;
	ruleNow->token += tmp;
	ruleNow->lastTime += tmp * ruleNow->rate;
    
	if(ruleNow->token > ruleNow->maxToken) {
        ruleNow->token = ruleNow->maxToken; 
        ruleNow->lastTime = t;
    }
	printk("new now_time_ms %ld\n", ruleNow->lastTime);
	printk("now token num is %d\n", ruleNow->token);
	if(ruleNow->token){
		ruleNow->token-=1;
		return 1;
	}
	return 0;
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
        if (ruleNow->iprangeFlag)
        {
            flag &= chkIprange();
        }
        if (ruleNow->limitFlag)
        {
            flag &= chkLimit();
        }
        if (flag)
        {
            ruleNow->pkgs += 1;
            if (ruleNow->target == RU_DROP)
            {
                printk("pkg dropped according to rule %d\n", i);
            }
            else
            {
                printk("pkg accepted according to rule %d\n", i);
            }
            return rtarget2nf(ruleNow->target);
        }
    }
    if (ruleDefault->target == RU_DROP)
    {
        printk("pkg dropped according to rule Default\n");
    }
    else
    {
        printk("pkg accepted according to rule Default\n");
    }
    ruleDefault->pkgs += 1;
    return rtarget2nf(defaultTarget);
}

static ssize_t read_info(struct file *fd, const char __user *buf, size_t len, loff_t *ppos)
{
    int copySize;
    if (len < (ruleNum + 1) * RULESIZE)
    {
        printk("error: not enough space in read\n");
        return -1;
    }
    copySize = (ruleNum + 1) * RULESIZE;
    if (copy_to_user(buf, (void *)(ruleList), copySize))
    {
        printk("error: copy to uesr failed in read\n");
        return -1;
    }
    printk("info: read_info:: read successfully\n");
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
        if (copy_from_user((void *)(ruleList + 1), buf + CTRLHDRSIZE, len - CTRLHDRSIZE))
        {
            printk("error: copy insert failed in write\n");
            return -1;
        }
        ruleNum += ctrlhdr.len;
        printk("info: write_info:: insert successfully\n");
        break;
    }
    case CT_APPEND:
        if (copy_from_user((void *)(ruleList + 1 + ruleNum), buf + CTRLHDRSIZE, len - CTRLHDRSIZE))
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
    //int i;
    //for(i=1;i<=ruleNum;i++)
    //    display(&ruleList[i]);
    ruleDefault->bytes = ruleNum;
    printk("info: write_info:: total rule num:%d\n", ruleNum);
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
