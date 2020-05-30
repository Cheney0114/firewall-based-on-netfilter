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
    printk("%d%d,%s%d,%s%d%d,%s%d%d\n", item->pkgs, item->bytes, item->protocol, item->target, item->saddr, item->smask, item->sport, item->daddr, item->dmask, item->dport);
    printk("timeflag:%d,%d%d,%d%d,%d,%d\n", item->timeFlag, item->timeStart, item->timeEnd, item->dateStart, item->dateEnd, item->weekdays, item->monthdays);
    printk("strFlag:%d,%s\n",item->strFlag,item->strPattern);
    printk("\n");
}


unsigned int get_mask(int maskbit){
	if (maskbit == 0) return 0;
	unsigned int mask = 0xFFFFFFFF;
	char* m = &mask;
	mask = mask >> (unsigned int)(32-maskbit) << (32-maskbit);
	char tmp1, tmp2;
	tmp1 = m[0];
	tmp2 = m[1];
	m[0] = m[3];
	m[1] = m[2];
	m[2] = tmp2;
	m[3] = tmp1;	
	printk("%d mask:%x\n", maskbit, mask);
	return mask;
}


int chkBase(void) //检查基础功能——IP,端口,掩码,协议
{    
	int flag = 1;
	 printk("package from %d.%d.%d.%d\n",iphdrNow->saddr&0x000000FF,
    (iphdrNow->saddr&0x0000FF00)>>8,
    (iphdrNow->saddr&0x00FF0000)>>16,
    (iphdrNow->saddr&0xFF000000)>>24);
	unsigned int smask = get_mask(ruleNow->smask);

	if((iphdrNow->saddr & smask) == (in_aton(ruleNow->saddr) & smask))
        flag &= 1;
    else
	    flag &= 0;
	
	printk("package to %d.%d.%d.%d\n",iphdrNow->daddr&0x000000FF,
    (iphdrNow->daddr&0x0000FF00)>>8,
    (iphdrNow->daddr&0x00FF0000)>>16,
    (iphdrNow->daddr&0xFF000000)>>24);
	unsigned int dmask = get_mask(ruleNow->dmask);
    if((iphdrNow->daddr & dmask) == (in_aton(ruleNow->daddr) & dmask))
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
	printk("chkBase:%d\n", flag);
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



#define REGEX_LENGTH 40
 
//typedef unsigned char int;
 
typedef enum
{
	IS_LETTER_OR_NUMBER = 0x11, //字母或数字
	IS_NUMBER = 0x22,           //数字
	IS_RANGE = 0x33,            //范围
	IS_SPECIAL_VALUE = 0x44,    //指定值
	IS_ERROR_TYPE = 0XAA,       //错误类型
}valueType;
 
typedef struct _STRUCT_VALUE_TYPE_INFOR
{
	valueType uType;
	int uRange[2];
}STRUCT_VALUE_TYPE_INFOR;




enum COMPILE_ERROR
{
	REGEX_SUCCESS = 0,
	REGEX_ERROR,
	REGEX_LENGTH_ERROR
};


static STRUCT_VALUE_TYPE_INFOR g_stValueTypeInfor[REGEX_LENGTH];
 
void init_value_type_infor(void)
{
	int i = 0;
 
	for(; i < REGEX_LENGTH; i++)
	{
		g_stValueTypeInfor[i].uType = IS_SPECIAL_VALUE;
		g_stValueTypeInfor[i].uRange[0] = 0;
		g_stValueTypeInfor[i].uRange[1] = 0;
	}
}
 

int isalnum(char p)
{
    //int res = 1;
    //while(*p != 0)
    //{
	//int t = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9');
	//res = res && t;
    //}
    return (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') || (p >= '0' && p <= '9');
}


//这里会把“编译”后的值信息放到g_stValueTypeInfor数组中
int compile_regex(int * regex)
{
	char *pRegex = regex;
	int uVINCount = 0;
	int uOffset = 0;
	int uOffsetSum = 0;
 
	if(pRegex == NULL)
	return REGEX_ERROR;
 
	init_value_type_infor();
 
	//printk("%s \n", pRegex);
	while(*pRegex != '\0')
	{
		switch(*pRegex)
		{
			//printk("ss    %c \n", *pRegex);
			case '\\':
			{
				if((pRegex[1] != 'w') && (pRegex[1] != 'd'))
				return REGEX_ERROR;
 
				if (pRegex[1] == 'w')
				{
					g_stValueTypeInfor[uVINCount].uType = IS_LETTER_OR_NUMBER;
				}
				else if (pRegex[1] == 'd')
				{
					g_stValueTypeInfor[uVINCount].uType = IS_NUMBER;
				}
 
				uVINCount += 1;
				uOffset = 2;
			}
			break;
			case '{':
			{
				int n = 0;
				int i = 0;
 
				if((!(pRegex[1]>='0' &&pRegex[1]<='9')) || (pRegex[2] != '}'))//若{n}中不是数字则认为是错误的
				return REGEX_ERROR;
 
				if(uOffsetSum == 0)//{n}写在表达式的开头是错误的
				return REGEX_ERROR;
 
				if(regex[uOffsetSum - 1] == '}')//{n}{m}这样写是错误的
				return REGEX_ERROR;
 
				n = pRegex[1] - 0x30;
 
				if(n == 0)
				return REGEX_ERROR;
 
				for (; i < n - 1; i++)
				{
					g_stValueTypeInfor[uVINCount - 1 + i + 1] = g_stValueTypeInfor[uVINCount - 1];//复制前一个
				}
 
				uVINCount += n - 1;
				uOffset = 3;
 
			}
			break;
			case '[':
			{
				if( !isalnum(pRegex[1]) ||(pRegex[2] != '-')
				|| !isalnum(pRegex[3]) ||(pRegex[4] != ']'))//[A-Z] OR [0-9] or [a-z] 并不严格判断 [0-z] is ok
				return REGEX_ERROR;
 
 
				g_stValueTypeInfor[uVINCount].uType = IS_RANGE;
				g_stValueTypeInfor[uVINCount].uRange[0] = pRegex[1];
				g_stValueTypeInfor[uVINCount].uRange[1] = pRegex[3];
 
				uVINCount += 1;
				uOffset = 5;
			}
			break;
			default:
			{
				//if( !isprint(pRegex[0]) )//可打印字符[0x20-0x7e]
				//return REGEX_ERROR;
 				//printk("!!!!!!!!!!!!!!%c \n",*pRegex);
				g_stValueTypeInfor[uVINCount].uType = IS_SPECIAL_VALUE;
				g_stValueTypeInfor[uVINCount].uRange[0] = pRegex[0];
 
				uVINCount += 1;
				uOffset = 1;
			}
			//break;
 
		}//end switch
 
		uOffsetSum += uOffset;
		pRegex += uOffset;
	}//end while
 
	if(uVINCount > REGEX_LENGTH)
	return REGEX_LENGTH_ERROR;
 
	return REGEX_SUCCESS;
}

//正则表达式比较操作 data:待比较的数据源 uSum:待比较的数据长度
//true:ok false:fail
bool match_regex(const char * data, int uSum)
{
	int i = 0;
 
	if(data == NULL)
	return false;
 
	while(i < uSum)
	{
		switch(g_stValueTypeInfor[i].uType)
		{
			case IS_LETTER_OR_NUMBER:
			{
				if( !isalnum(data[i]) )
				{
				//printk("111\n");
				return false;
				}
			}
			break;
			case IS_NUMBER:
			{
				//if(!isdigit(data[i]))
				if (data[i] > '9' || data[i] < '0')
			{
				//printk("is spes \n");
				return false;
			}
			}
			break;
			case IS_RANGE:
			{
				if((data[i] < g_stValueTypeInfor[i].uRange[0]) 
				|| (data[i] > g_stValueTypeInfor[i].uRange[1]))
			{
				//printk("is range \n");
				return false;
			}
			}
			break;
			case IS_SPECIAL_VALUE:
			{
				if((char)data[i] != (char)g_stValueTypeInfor[i].uRange[0])
			{
				//printk(" %d  %c %c\n", i, data[i], g_stValueTypeInfor[i].uRange[0]);
				//printk("is spes \n");
				return false;
			}
			}
			break;
			default:
			{
				//printk("%d %X  defa\n", i,g_stValueTypeInfor[i].uType);
				return false;
			}
 
		}//end switch
 
		i += 1;
 
		if(i == REGEX_LENGTH - 1)
 
		return true;
	}//end while
 
	return true;  //weishu not match
}


int chkRegex(void)
{
    //return 1表示通过检查
    //return 0表示不通过检查
    //使用ruleNow->regFlag 和 ruleNow->regPattern[STRPATSIZE + 1];

    //printk("******************************%d %s %d \n",ruleNow->regFlag, ruleNow->regPattern, strlen(ruleNow->regPattern));

    int i, j; //循环变量

    struct sk_buff *pskb = skbNow; //pskb就是skbNow，只不过是前期写的代码用的pskb，移植过来就依然用pskb了

    char *datap = pskb->data;                    //取出包中的数据
    int pskblen = pskb->len;                     //包长度
    int stringlen = strlen(ruleNow->regPattern); //匹配串长度
    int allmatch = 0;                            //匹配次数
    int match = 0;                               //单次的匹配的状态

    //if (ruleNow->regFlag == 0) //strFlag设置为0表示没有设置包内容匹配规则
        //return 0;

    compile_regex(ruleNow->regPattern);
    //printk("compile success!\n");


    for (i = 0; i <= pskb->len - 1; i++)
    {
		//printk(" pskb->len: %d\n",  pskb->len);
		//printk(" stringlen: %d\n",  stringlen);
		for (j = i + 1; j <= pskb->len - 1; j++)
		{
			char temp[1000];
			strncpy(temp, pskb->data + i, j-i+1);
			temp[j-i+1] = 0;
			//printk("%d %s\n", j-i+1, temp);
			if(match_regex(temp, j-i+1))
			{
				allmatch += 1;
				//printk("one match\n");
				break;
		    }
		}
    }
	//printk("%x %x %x %x\n",g_stValueTypeInfor[0].uType,g_stValueTypeInfor[1].uType,g_stValueTypeInfor[2].uType,g_stValueTypeInfor[3].uType);
    //printk("detect over \n");

	
	compile_regex(ruleNow->strPattern);

    //检测allmatch
    if (allmatch >= ruleNow->regFlag)
    {
        printk("<0> A Packet match the regexRule\n");
        return 1;
    }

    return 0;
}


int chkStr(void)
{
    //return 1表示匹配规则
    //return 0表示不匹配规则
    //使用ruleNow->strFlag 和 ruleNow->strPattern[STRPATSIZE + 1];

    int i, j, k; //循环变量

    struct sk_buff *pskb = skbNow; //pskb就是skbNow，只不过是前期写的代码用的pskb，移植过来就依然用pskb了

    char *datap = pskb->data;                    //取出包中的数据
    int pskblen = pskb->len;                     //包长度
    int stringlen = strlen(ruleNow->strPattern); //匹配串长度
    int allmatch = 0;                            //匹配次数
    int match = 0;                               //单次的匹配的状态

    //if (ruleNow->strFlag == 0) //strFlag设置为0表示没有设置包内容匹配规则
        //return 0;

    for (i = 0; i <= pskb->len - stringlen; i++)
    {
        match = 1;
        //ch1 = pskb->data[i];
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


unsigned int ip2num(unsigned int ip, char* name)
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
	printk("%s ip: %d.%d.%d.%d\n", name, a, b, c, d);

	return num;
}

int chkIprange(void)
{
	unsigned int ip_src, ip_dst, ip_start, ip_end, mask_start, mask_end, tmp;
	ip_src = ip2num(iphdrNow->saddr, "src");
	ip_dst = ip2num(iphdrNow->daddr, "dst");
	ip_start = ip2num(in_aton(ruleNow->ipstart), "start");
	ip_end = ip2num(in_aton(ruleNow->ipend), "end");
	
	
	mask_start = 0xffffffff << (32 - ruleNow->mask_start_bit);
	ip_start = ip_start & mask_start;
	mask_end = 0xffffffff << (32 - ruleNow->mask_end_bit);
	tmp = 0xffffffff >> (ruleNow->mask_end_bit);
	if (ruleNow->mask_end_bit != 32) {
		ip_end = ip_end & mask_end + tmp + 1;
	}

	if (ruleNow->iprangeFlag) {
		if (ruleNow->src == 1) {
			if(  ip_src <= ip_start  ) {
				return 0;
			} else if(ip_src >= ip_end) {
				return 0;
			} else {
				return 1;
			}
		}
		if (ruleNow->dst == 1) {
			if(  ip_dst <= ip_start  ) {
				return 0;
			} else if(ip_dst >= ip_end) {
				return 0;
			} else {
				return 1;
			}
		}
	}
    return 0;
}

int chkMultip(void) {
	unsigned int ip_src, ip_dst, ip_ban;
	ip_src = ip2num(iphdrNow->saddr, "src");
	ip_dst = ip2num(iphdrNow->daddr, "dst");
	
	if (ruleNow->multipFlag) {
		char ip[15];
		int i = 0;
		strcpy(ip, ruleNow->iplist[i]);
		while ((strlen(ip) > 0) & (i < 10)) {
			ip_ban = ip2num(in_aton(ip), "ban");
			if (ruleNow->mult_src) {
				if (ip_src == ip_ban) {
					return 1;
				}
			}
			if (ruleNow->mult_dst) {
				if (ip_dst == ip_ban) {
					return 1;
				}
			}
			i++;
			strcpy(ip, ruleNow->iplist[i]);
		}
	}
	return 0;
}

int chkPortrange(void){
    int flag = 1;
    if(ruleNow->sportrangeFlag){
        if((iphdrNow->protocol)!=IPPROTO_TCP && (iphdrNow->protocol)!=IPPROTO_UDP) 
            flag &= 0;
        else
        {
            if(iphdrNow->protocol == IPPROTO_TCP){
                struct tcphdr *thdr = tcp_hdr(skbNow);
                if((thdr->source >= htons(ruleNow->sportStart)) && (thdr->source <= htons(ruleNow->sportEnd))) //check the dport
                    flag &= 1;
                else    
                    flag &= 0;
            }
            else{ 
                struct udphdr *uhdr = udp_hdr(skbNow);
                if((uhdr->source >= htons(ruleNow->sportStart)) && (uhdr->source <= htons(ruleNow->sportEnd))) //check the dport
                    flag &= 1;
                else    
                    flag &= 0;
            }
        }
    }
    else if(ruleNow->dportrangeFlag){
        if((iphdrNow->protocol)!=IPPROTO_TCP && (iphdrNow->protocol)!=IPPROTO_UDP) 
            flag &= 0;
        else
        {
            if(iphdrNow->protocol == IPPROTO_TCP){
                struct tcphdr *thdr = tcp_hdr(skbNow);
                if((thdr->dest >= htons(ruleNow->dportStart)) && (thdr->dest <= htons(ruleNow->dportEnd))) //check the dport
                    flag &= 1;
                else    
                    flag &= 0;
            }
            else{ 
                struct udphdr *uhdr = udp_hdr(skbNow);
                if((uhdr->dest >= htons(ruleNow->dportStart)) && (uhdr->dest <= htons(ruleNow->dportEnd))) //check the dport
                    flag &= 1;
                else    
                    flag &= 0;
            }
        }        
    }
    return flag;
}

uint32_t get_nowtime(void){
	struct timeval tv;
	do_gettimeofday(&tv);
	uint32_t t = tv.tv_sec*1000+tv.tv_usec/1000;
	//printk("millisecond:%d\n", t);
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
        if (ruleNow->regFlag)
        {
            flag &= chkRegex();
        }
        if (ruleNow->iprangeFlag)
        {
            flag &= chkIprange();
        }
        if (ruleNow->multipFlag)
        {
            flag &= chkMultip();
		}
        if(ruleNow->sportrangeFlag || ruleNow->dportrangeFlag){
            flag &= chkPortrange();
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
        for (i = ruleNum; i >= ctrlhdr.idx; i--)
        {
            ruleList[i + ctrlhdr.len] = ruleList[i];
        }
        if (copy_from_user((void *)(ruleList + ctrlhdr.idx), buf + CTRLHDRSIZE, len - CTRLHDRSIZE))
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
