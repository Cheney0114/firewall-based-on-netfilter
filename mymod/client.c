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

void display(struct rule *item)
{
    printf("%d%d,%d%d,%d%d%d,%d%d%d\n", item->pkgs, item->bytes, item->protocol, item->target, item->saddr, item->smark, item->sport, item->daddr, item->dmark, item->dport);
    printf("%d,%d%d,%d%d,%d,%d\n",item->timeFlag,item->timeStart,item->timeEnd,item->dateStart,item->dateEnd,item->weekdays,item->monthdays);
    printf("\n");
}

int main()
{
    initConst();
    initRule(&ruleList[0]);
    ruleList[0].target = RU_DROP;
    ruleList[0].timeFlag = DATEEND;
    ruleList[0].dateEnd = 5 * 100 + 22;
    int ret = appendRule(1);
    printf("insert: %d\n", ret);

     display(&ruleList[0]);

     initRule(&ruleList[0]);
     initRule(&ruleList[1]);

     display(&ruleList[0]);
     display(&ruleList[1]);

     ret = readRuleInfo();
     printf("read: %d\n", ret);
     display(&ruleList[0]);
     display(&ruleList[1]);
}
