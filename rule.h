#ifndef RULE_H
#define RULE_H

// 可匹配字符串长度
#define STRPATSIZE 10
// target 标记
#define RU_ACCEPT 1
#define RU_DROP 0
// time 标记
#define TIME (1 << 0)
#define DATASTART (1 << 1)
#define DATAEND (1 << 2)
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
};

#define RULESIZE (sizeof(struct rule))
#endif