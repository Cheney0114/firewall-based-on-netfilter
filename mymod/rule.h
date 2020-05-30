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
    char saddr[20]; //"xxx.xxx.xxx.xxx"
    int smask;      //24
    int sport;      //23,其中-1表示不检查端口

    char daddr[20];
    int dmask;
    int dport;

    char protocol[10]; //"tcp",其中"all"表示不检查协议类型
    int flags[7]; //首位为是否检查标志位,后续fin, syn, rst, psh, ack, urg六个标志位

    int target;

    //extension model
    int timeFlag;
    int timeStart;
    int timeEnd;
    int dateStart;
    int dateEnd;
    int weekdays;
    int monthdays;

    //match string
    int strFlag;  //strFlag表示要接收包中字符串至少出现的次数
    char strPattern[STRPATSIZE + 1];  //检测的字符串
	
    //match regex
    int regFlag;  //regFlag表示要接收包中正则匹配至少出现的次数
    char regPattern[STRPATSIZE + 1];   //正则表达式

	int iprangeFlag;
	char ipstart[15];
	char ipend[15];
	int mask_start_bit;
	int mask_end_bit;
	int src;
	int dst;

	int multipFlag;
	char iplist[10][15]; // 可以储存10个不连续的ip
	int mult_src;
	int mult_dst;
    
	int sportrangeFlag;
    int sportStart;
    int sportEnd;
    int dportrangeFlag;
    int dportStart;
    int dportEnd;

    int limitFlag;
    unsigned int lastTime;
    unsigned int token;
    unsigned int rate;
    char rateStr[20];
    unsigned int maxToken;
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
