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

    item->saddr = 0;
    item->smark = 0;
    item->sport = 0;

    item->daddr = 0;
    item->dmark = 0;
    item->dport = 0;

    item->protocol = 0;
    item->target = RU_ACCEPT;

    item->timeFlag = 0;
    item->strFlag = 0;
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

int insertRule(int len)
{
    ctrlhdr->ctrlType = CT_INSERT;
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
    printf("\t--strMaxNum %d --strPat %s",item->strFlag,item->strPattern);
}

void displayHeader()
{
    printf("pkgs\tbytes\t target\tprot\t saddr\tsport\t daddr\tdport\n");
}

void display(struct rule *item)
{
    printf("%d\t%d\t %s\t%d\t %d/%d\t%d\t %d/%d\t%d", item->pkgs, item->bytes, ((item->target == 1) ? "ACCEPT" : "DROP"), item->protocol, item->saddr, item->smark, item->sport, item->daddr, item->dmark, item->dport);
    if (item->timeFlag)
        displayTimeExt(item);
    if(item->strFlag)
        displayStrMatch(item);
    printf("\n");
}

int main()
{
    int i;
    initConst();
    initRule(&ruleList[0]);
    ruleList[0].target = RU_DROP;
    ruleList[0].strFlag = 1;
    strcpy(ruleList[0].strPattern, "xtfx");

    initRule(&ruleList[1]);
    ruleList[1].target = RU_DROP;
    ruleList[1].strFlag = 3;
    strcpy(ruleList[1].strPattern, "ckqc");
    
    
    int ret = appendRule(2);
    printf("insert: %d\n", ret);
    printf("inserted rules:\n");
    displayHeader();

    ret = readRuleInfo();
    printf("read: %d\n", ret);
    if (ruleList[0].target == 1)
    {
        printf("default strategy: ACCEPT pkg:%d", ruleList[0].pkgs);
    }
    else
    {
        printf("default strategy: DROP pkg:%d", ruleList[0].pkgs);
    }
    printf("\trule nums: %d\n", ruleList[0].bytes);
    displayHeader();
    for (i = 1; i <= ruleList[0].bytes /*rule总个数*/; i++)
        display(&ruleList[i]);
}
