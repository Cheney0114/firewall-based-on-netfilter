#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "rule.h"
#define RULEMAXNUM 51
#define BUFSIZE (CTRLHDRSIZE + RULESIZE * RULEMAXNUM)

struct rule ruleList[RULEMAXNUM];
char buf[BUFSIZE];

struct ctrlheader *ctrlhdr;
struct rule *ruleInbuf;

void initConst()
{
    ctrlhdr = (struct ctrlheader *)buf;
    ruleInbuf = (struct rule *)(buf + CTRLHDRSIZE);
}

void initRule(struct rule *item)
{
    item->pkgs = 0;
    item->bytes = 0;

    strcpy(item->saddr, "");
    item->smask = 0;
    item->sport = -1;

    strcpy(item->daddr, "");
    item->dmask = 0;
    item->dport = -1;

    strcpy(item->protocol, "all");
    item->flags[0] = 0;
    item->target = RU_ACCEPT;

    item->timeFlag = 0;

    item->strFlag = 0;
    item->regFlag = 0;

    item->iprangeFlag = 0;
    item->mask_bit = 0;
    item->src = 0;
    item->dst = 0;

    item->multipFlag = 0;
    item->mult_src = 0;
    item->mult_dst = 0;

    item->sportrangeFlag = 0;
    item->dportrangeFlag = 0;

    item->limitFlag = 0;
    item->maxToken = 7;
}

int writeCtrlInfo(int size)
{
    int fd = open(devName, O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        printf("failed in open dev\n");
        return 0;
    }
    int ret;
    if ((ret = write(fd, (void *)buf, size)) < 0)
    {
        printf("error: failed in writeCtrlInfo\n");
        close(fd);
        return 0;
    }
    close(fd);
    return 1;
}

// 用户态接口
int readRuleInfo()
{
    int fd = open(devName, O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        printf("failed in open dev\n");
        return 0;
    }
    int ret;
    if ((ret = read(fd, (void *)ruleList, RULESIZE * RULEMAXNUM)) < 0)
    {
        printf("error: failed in readRuleInfo\n");
        close(fd);
        return 0;
    }
    close(fd);
    return 1;
}

int insertRule(int len, int idx)
{
    ctrlhdr->ctrlType = CT_INSERT;
    ctrlhdr->idx = idx;
    ctrlhdr->len = len;
    int size = CTRLHDRSIZE + len * RULESIZE;
    memcpy((void *)ruleInbuf, (void *)ruleList, len * RULESIZE);
    return writeCtrlInfo(size);
}

int appendRule(int len)
{
    ctrlhdr->ctrlType = CT_APPEND;
    ctrlhdr->len = len;
    int size = CTRLHDRSIZE + len * RULESIZE;
    memcpy((void *)ruleInbuf, (void *)ruleList, len * RULESIZE);
    return writeCtrlInfo(size);
}

int deleteRule(int index)
{
    ctrlhdr->ctrlType = CT_DELETE;
    ctrlhdr->len = index;
    return writeCtrlInfo(CTRLHDRSIZE);
}

int flushRule()
{
    ctrlhdr->ctrlType = CT_FLUSH;
    ctrlhdr->len = 0;
    return writeCtrlInfo(CTRLHDRSIZE);
}

int setDefaultRule(int utarget)
{
    ctrlhdr->ctrlType = CT_DTAGET;
    ctrlhdr->len = utarget;
    return writeCtrlInfo(CTRLHDRSIZE);
}

void displayTimeExt(struct rule *item)
{
    if (item->timeFlag & TIME)
    {
        int hourStart, minStart, secStart;
        int hourEnd, minEnd, secEnd;
        hourStart = item->timeStart / 3600;
        minStart = (item->timeStart % 3600) / 60;
        secStart = item->timeStart % 60;
        printf("\t--timeStart %d:%d:%d", hourStart, minStart, secStart);
        hourEnd = item->timeEnd / 3600;
        minEnd = (item->timeEnd % 3600) / 60;
        secEnd = item->timeEnd % 60;
        printf("\t--timeEnd %d:%d:%d", hourEnd, minEnd, secEnd);
    }
    else if ((item->timeFlag & DATESTART) || (item->timeFlag & DATEEND))
    {
        if (item->timeFlag & DATESTART)
        {
            int monthStart;
            int dayStart;
            monthStart = item->dateStart / 100;
            dayStart = item->dateStart % 100;
            printf("\t--dateStart %d/%d", monthStart, dayStart);
        }
        if (item->timeFlag & DATEEND)
        {
            int monthEnd;
            int dayEnd;
            monthEnd = item->dateEnd / 100;
            dayEnd = item->dateEnd % 100;
            printf("\t--dateEnd %d/%d", monthEnd, dayEnd);
        }
    }
    else if (item->timeFlag & WEEKDAYS)
    {
        int i;
        if (item->timeFlag & WEEKNOT)
        {
            printf("\t--weekdays! ");
        }
        else
        {
            printf("\t--weekdays ");
        }
        for (i = 0; i <= 6; i++)
        {
            if ((1 << i) & item->weekdays)
            {
                printf("%d", i);
            }
        }
    }
    else if (item->timeFlag & MONTHDAYS)
    {
        int i;
        if (item->timeFlag & WEEKNOT)
        {
            printf("\t--monthdays! ");
        }
        else
        {
            printf("\t--monthdays ");
        }
        for (i = 1; i <= 31; i++)
        {
            if ((1 << i) & item->monthdays)
            {
                printf("%d ", i);
            }
        }
    }
}

void displayStrMatch(struct rule *item)
{
    printf("\t--strMaxNum %d --strPat %s", item->strFlag, item->strPattern);
}

void displayHeader()
{
    printf("pkgs\tbytes\t target\tprot\t saddr\tsport\t daddr\tdport\n");
}

void displayIprangeMatch(struct rule *item)
{
    if (item->mask_bit == 0)
    {
        printf("iprange: %d, (%s - %s)", item->iprangeFlag, item->ipstart, item->ipend);
    }
    else
    {
        printf("iprange: %d, (%s / %d)", item->iprangeFlag, item->ipstart, item->mask_bit);
    }
}

void displayMultipMatch(struct rule *item)
{
    char ip[15];
    int i = 0;
    strcpy(ip, item->iplist[i]);
    printf("multip: ");
    while ((strlen(ip) > 0) & (i < 10))
    {
        printf("%s, ", ip);
        i++;
        strcpy(ip, item->iplist[i]);
    }
}

void displayLimitMatch(struct rule *item)
{
    printf("\t--limit %s --maxToken %d", item->rateStr, item->maxToken);
}

void displayPortrangeMatch(struct rule *item)
{
    if (item->sportrangeFlag)
        printf("\t--sport_start %d --sport_end %d", item->sportStart, item->sportEnd);
    if (item->dportrangeFlag)
        printf("\t--dport_start %d --dport_end %d", item->dportStart, item->dportEnd);
}

void display(struct rule *item)
{
    printf("%d\t%d\t %s\t%s\t %s/%d\t%d\t %s/%d\t%d", item->pkgs, item->bytes, ((item->target == 1) ? "ACCEPT" : "DROP"), item->protocol, item->saddr, item->smask, item->sport, item->daddr, item->dmask, item->dport);
    if (item->timeFlag)
        displayTimeExt(item);
    if (item->strFlag)
        displayStrMatch(item);
    printf("\n");
    if (item->iprangeFlag)
        displayIprangeMatch(item);
    printf("\n");
    if (item->multipFlag)
        displayMultipMatch(item);
    printf("\n");
    if (item->sportrangeFlag || item->dportrangeFlag)
        displayPortrangeMatch(item);
    if (item->limitFlag)
        displayLimitMatch(item);

    printf("\n");
}

int xxj_test_base(void)
{
    initRule(&ruleList[0]);
    ruleList[0].target = RU_DROP;
    strcpy(ruleList[0].saddr, "192.168.247.1");
    ruleList[0].smask = 0;
    //strcpy(ruleList[0].daddr, "192.168.247.130");
    ruleList[0].dmask = 0;
    ruleList[0].sport = -1;
    ruleList[0].dport = -1;
    strcpy(ruleList[0].protocol, "icmp");
    return appendRule(1);
}

// int main()
// {
// 	int i;
//     initConst();
//     initRule(&ruleList[0]);
//     ruleList[0].target = RU_DROP;

// 	/*
//     ruleList[0].iprangeFlag = 1;
// 	ruleList[0].mask_bit = 8;
// 	ruleList[0].src = 1;
//     strcpy(ruleList[0].ipstart, "192.168.1.102");
//     strcpy(ruleList[0].ipend, "61.135.169.122");
// 	*/

//     ruleList[0].multipFlag = 1;
// 	ruleList[0].mult_src = 1;
//     strcpy(ruleList[0].iplist[0], "192.168.1.102");
//     strcpy(ruleList[0].iplist[1], "61.135.169.121");
//     strcpy(ruleList[0].iplist[2], "61.135.169.125");

// 	//ruleList[0].strFlag = 1;
//     //strcpy(ruleList[0].strPattern, "xtfx");

//     initRule(&ruleList[1]);
//     ruleList[1].target = RU_DROP;
// 	/*
//     ruleList[1].strFlag = 3;
//     strcpy(ruleList[1].strPattern, "ckqc");
//     */

//     int ret = appendRule(1);
//     /*-----------------------------------
//     initConst();
//     initRule(&ruleList[0]);
// 	ruleList[0].target = RU_ACCEPT;
//     ruleList[0].limitFlag = 1;
// 	strcpy(ruleList[0].rateStr, "6/minute");
//     int ret = appendRule(1);
// 	------------------------------------*/
// 	//int ret = xxj_test_base();

//     /*
//     //str测试代码
//     initRule(&ruleList[0]);
//     ruleList[0].target = RU_DROP;
//     ruleList[0].strFlag = 2;
//     strcpy(ruleList[0].strPattern, "hiddjk");

//     //regex测试代码
//     initRule(&ruleList[1]);
//     ruleList[1].target = RU_DROP;
//     ruleList[1].regFlag = 1;
//     strcpy(ruleList[1].regPattern, "[a-z][a-z]");
//     */

//     printf("insert: %d\n", ret);
//     printf("inserted rules:\n");
//     displayHeader();

//     ret = readRuleInfo();

//     printf("read: %d\n", ret);
//     if (ruleList[0].target == 1)
//     {
//         printf("default strategy: ACCEPT pkg:%d", ruleList[0].pkgs);
//     }
//     else
//     {
//         printf("default strategy: DROP pkg:%d", ruleList[0].pkgs);
//     }
//     printf("\trule nums: %d\n", ruleList[0].bytes);
//     displayHeader();
//     for (i = 1; i <= ruleList[0].bytes /*rule总个数*/; i++)
//         display(&ruleList[i]);
// }
