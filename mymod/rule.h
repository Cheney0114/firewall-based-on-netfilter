#ifndef RULE_H
#define RULE_H

// *************
// * rule info *
// *************
// 可匹配字符串长度
#define STRPATSIZE 10
// target 标记
#define RU_ACCEPT 1
#define RU_DROP 0
// time 标记
#define TIME (1 << 0)
#define DATESTART (1 << 1)
#define DATEEND (1 << 2)
#define WEEKDAYS (1 << 5)
#define WEEKNOT (1 << 6)
#define MONTHDAYS (1 << 3)
#define MONTHNOT (1 << 4)

struct rule
{
    //total pkg num and total size
    int pkgs;
    int bytes;

    // base model
    int saddr;
    int smark;
    int sport;

    int daddr;
    int dmark;
    int dport;

    int protocol;
    int target;

    //extension model
    int timeFlag;
    int timeStart;
    int timeEnd;
    int dateStart;
    int dateEnd;
    int weekdays;
    int monthdays;

    int strFlag;
    char strPattern[STRPATSIZE + 1];

	int iprangeFlag;
	char ipstart[15];
	char ipend[15];
};
#define RULESIZE (sizeof(struct rule))

// ***************
// *  ctrlHeader *
// ***************
#define CT_INSERT 1 // len为处理个数，后面跟len大小的rule数组。在头部一次性插入多条。不会把数组逆序。
#define CT_APPEND 2 // len为处理个数，后面跟len大小的rule数组
#define CT_DELETE 3 // len表示要删除的序号
#define CT_FLUSH 4  // 内核处理时忽略len
#define CT_DTAGET 5 // 默认黑白名单。len取值为RU_ACCEPT或RU_DROP

struct ctrlheader
{
    int ctrlType;
    int len;
};
#define CTRLHDRSIZE (sizeof(struct ctrlheader))


// **************
// * other info *
// **************
#define devName "/dev/ckq"
#endif
