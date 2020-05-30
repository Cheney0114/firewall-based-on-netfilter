#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rule.h"
#include "client.h"
// #include <sys/types.h>
#define RULEMAXNUM 51

extern struct rule ruleList[RULEMAXNUM];

void remove_extra_space(char *str)
{
    char *sp = str;
    char *prev = 0;
    while (*str && (*str == ' ' || *str == '\n' || *str == '\t'))
        ++str;

    for (; *str; ++str)
    {
        switch (*str)
        {
        case '\t':
            *str = ' ';
        case ' ':
            if (*prev == '\n' || *prev == ' ')
                continue;
            break;

        case '\n':
            if (*prev == '\n')
                continue;
            else if (*prev == ' ')
            {
                *prev = '\n';
                continue;
            }
            break;
        }

        prev = sp;
        *sp++ = *str;
    }
    if (prev && *prev && (*prev == ' ' || *prev == '\n'))
        --sp;
    *sp = 0;
}

void split(char *src, const char *separator, char **dest, int *num)
{
    char *pNext;
    int count = 0;
    if (src == NULL || strlen(src) == 0)
        return;
    if (separator == NULL || strlen(separator) == 0)
        return;
    pNext = strtok(src, separator);
    while (pNext != NULL)
    {
        *dest++ = pNext;
        ++count;
        pNext = strtok(NULL, separator);
    }
    *num = count;
}

void showHelp()
{
    system("cat help.txt");
}

void showRuleTables()
{
    int i;
    if (readRuleInfo() <= 0)
    {
        printf("read data from kernel failed\n");
        return;
    }
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

int parseRule(int, char **);
int tryParseBase(int, int, char **);
int tryParseStr(int, int, char **);
int tryParseTime(int, int, char **);

int main(int argc, char *argv[])
{
    initConst();

    if (argc <= 1)
    {
        showHelp();
        return 0;
    }
    if (argc >= 2)
    {
        if (!strcmp(argv[1], "-h"))
        {
            showHelp();
            return 0;
        }
        else if (!strcmp(argv[1], "-F"))
        {
            flushRule();
            return 0;
        }
        else if (!strcmp(argv[1], "-L"))
        {
            showRuleTables();
            return 0;
        }
    }
    if (argc >= 3)
    {
        if (!strcmp(argv[1], "-D"))
        {
            deleteRule(atoi(argv[2]));
            return 0;
        }
        else if (!strcmp(argv[1], "-defaultStratagy"))
        {
            if (!strcmp(argv[2], "drop"))
                setDefaultRule(RU_DROP);
            else if (!strcmp(argv[2], "accpet"))
                setDefaultRule(RU_ACCEPT);
            return 0;
        }
    }
    if (argc >= 4)
    {
        int ret;
        if (strncmp(argv[2], "-", 1))
            ret = parseRule(argc - 3, &argv[3]);
        else
            ret = parseRule(argc - 2, &argv[2]);
        if (ret < 0)
        {
            printf("can't parseRule. please input the correct command\n");
            return 0;
        }
        if (!strcmp(argv[1], "-A"))
        {
            appendRule(1);
            return 0;
        }
        else if (!strcmp(argv[1], "-I"))
        {
            if (strncmp(argv[2], "-", 1))
                insertRule(1, atoi(argv[2]));
            else
                insertRule(1, 1);
            return 0;
        }
        else if (!strcmp(argv[1], "-R"))
        {
            if (strncmp(argv[2], "-", 1))
            {
                deleteRule(atoi(argv[2]));
                insertRule(1, atoi(argv[2]));
                return 0;
            }
            else
            {
                printf("wrong format: -R need a idx");
                return -1;
            }
        }
    }
    printf("unrecongnized command\n");
    showHelp();
    return 0;
}

int parseRule(int argc, char *argv[])
{
    initRule(&ruleList[0]);

    printf("%d\n", argc);

    int i = 0;
    while (i < argc)
    {
        int ret;
        // tryPrase类函数
        // 作用：尝试解析，若有
        // 输入：当前位置i，总共数目argc，字符串列表argv
        // 输出：若成功解析：      下一次解析应该向后移动的位数
        //      若解析不了：       返回 0
        //      若解析时发生错误： 返回 -1
        ret = tryParseBase(i, argc, argv);
        if (ret < 0)
        {
            return -1;
        }
        else if (ret > 0)
        {
            i += ret;
            continue;
        }

        ret = tryParseStr(i, argc, argv);
        if (ret < 0)
        {
            return -1;
        }
        else if (ret > 0)
        {
            i += ret;
            continue;
        }

        ret = tryParseMuti(i, argc, argv);
        if (ret < 0)
        {
            return -1;
        }
        else if (ret > 0)
        {
            i += ret;
            continue;
        }

        ret = tryParseTime(i, argc, argv);
        if (ret < 0)
        {
            return -1;
        }
        if (ret > 0)
        {
            i += ret;
            continue;
        }

        // 最后尝试完所有可能都解析不出来，说明输入有问题，解析不成功
        if (ret <= 0)
            return -1;
    }
    return 0;
}

int tryParseBase(int i, int argc, char *argv[])
{
    if (i + 1 >= argc)
        return 0;
    if (!strcmp(argv[i], "-p"))
    {
        strcpy(ruleList[0].protocol, argv[i + 1]);
        return 2;
    }
    else if (!strcmp(argv[i], "-s"))
    {
        char *addr[5] = {0};
        int n = 0;
        split(argv[i + 1], "/", addr, &n);
        if (n == 1)
        {
            strcpy(ruleList[0].saddr, addr[0]);
            ruleList[0].smask = 32;
        }
        else
        {
            strcpy(ruleList[0].saddr, addr[0]);
            ruleList[0].smask = atoi(addr[1]);
        }
        return 2;
    }
    else if (!strcmp(argv[i], "-d"))
    {
        char *addr[5] = {0};
        int n = 0;
        split(argv[i + 1], "/", addr, &n);
        if (n == 1)
        {
            strcpy(ruleList[0].daddr, addr[0]);
            ruleList[0].dmask = 32;
        }
        else
        {
            strcpy(ruleList[0].daddr, addr[0]);
            ruleList[0].dmask = atoi(addr[1]);
        }
        return 2;
    }
    else if (!strcmp(argv[i], "-P"))
    {
        if (!strcmp(argv[i + 1], "drop"))
            ruleList[0].target = RU_DROP;
        else if (!strcmp(argv[i + 1], "accpet"))
            ruleList[0].target = RU_ACCEPT;
        return 2;
    }
    else if (!strcmp(argv[i], "--sport"))
    {
        ruleList[0].sport = atoi(argv[i + 1]);
        return 2;
    }
    else if (!strcmp(argv[i], "--dport"))
    {
        ruleList[0].dport = atoi(argv[i + 1]);
        return 2;
    }
    return 0;
}

int tryParseTime(int i, int argc, char *argv[])
{
    if (i + 1 > argc)
        return -1;
    if (!strcmp(argv[i], "--time"))
    {
        // --time hour:min:sec hour:min:sec
        int hour = 0, min = 0, sec = 0, ret;
        if (i + 2 > argc)
            return -1;
        ruleList[0].timeFlag = TIME;

        if ((ret = sscanf(argv[i + 1], "%d:%d:%d", &hour, &min, &sec)) < 3)
        {
            return -1;
        }
        ruleList[0].timeStart = hour * 3600 + min * 60 + sec;
        if ((ret = sscanf(argv[i + 2], "%d:%d:%d", &hour, &min, &sec)) < 3)
        {
            return -1;
        }
        ruleList[0].timeEnd = hour * 3600 + min * 60 + sec;
        return 3;
    }
    else if (!strcmp(argv[i], "--dateStart"))
    {
        //--dateStart 01/01
        int month = 0, day = 0, ret = 0;
        ruleList[0].timeFlag |= DATESTART;
        if (ret = sscanf(argv[i + 1], "%d/%d", &month, &day) < 2)
        {
            return -1;
        }
        ruleList[0].dateStart = month * 100 + day;
        return 2;
    }
    else if (!strcmp(argv[i], "--dateEnd"))
    {
        int month = 0, day = 0, ret = 0;
        ruleList[0].timeFlag |= DATEEND;
        if (ret = sscanf(argv[i + 1], "%d/%d", &month, &day) < 2)
        {
            return -1;
        }
        ruleList[0].dateEnd = month * 100 + day;
        return 2;
    }
    else if ((!strcmp(argv[i], "--weekdays")) || (!strcmp(argv[i], "--weekdays!")))
    {
        int j = 1;
        ruleList[0].timeFlag |= WEEKDAYS;
        if (!strcmp(argv[i], "--weekdays!"))
            ruleList[0].timeFlag |= WEEKNOT;

        while (i + j < argc && strncmp(argv[i + j], "-", 1))
        {
            int x = atoi(argv[i + j]);
            if (x <= 0 || x >= 8) // 只接受 1-7
            {
                return -1;
            }
            if (x == 7) // 内核中7用0表示
                x = 0;
            ruleList[0].weekdays |= 1 << x;
            j += 1;
        }

        return j;
    }
    else if (!strcmp(argv[i], "--monthdays") || (!strcmp(argv[i], "--monthdays!")))
    {
        int j = 1;
        ruleList[0].timeFlag |= MONTHDAYS;
        if (!strcmp(argv[i], "--monthdays!"))
            ruleList[0].timeFlag |= MONTHNOT;

        while (i + j < argc && strncmp(argv[i + j], "-", 1))
        {
            int x = atoi(argv[i + j]);
            if (x <= 0 || x >= 32) // 只接受 1-31
            {
                return -1;
            }
            ruleList[0].monthdays |= 1 << x;
            j += 1;
        }

        return j;
    }
    return 0;
}

int tryParseStr(int i, int argc, char *argv[])
{
    if (i + 1 > argc)
        return -1;
    if (!strcmp(argv[i], "--strMaxNum"))
    {
        ruleList[0].strFlag = atoi(argv[i + 1]);
        return 2;
    }
    else if (!strcmp(argv[i], "--strPat"))
    {
        strcpy(ruleList[0].strPattern, argv[i + 1]);
        return 2;
    }
    else if (!strcmp(argv[i], "--regMaxNum"))
    {
        ruleList[0].regFlag = atoi(argv[i + 1]);
        return 2;
    }
    else if (!strcmp(argv[i], "--regPat"))
    {
        strcpy(ruleList[0].regPattern, argv[i + 1]);
        return 2;
    }
    return 0;
}

int tryParseMuti(int i, int argc, char *argv[])
{
    if (!strcmp(argv[i], "iprange_src"))
    {
        if (i + 1 > argc)
            return -1;

        char *ip[5] = {0};
        int n = 0;
        split(argv[i + 1], ":", ip, &n);
        ruleList[0].target = RU_DROP;
        ruleList[0].iprangeFlag = 1;
        ruleList[0].src = 1;
        strcpy(ruleList[0].ipstart, ip[0]);
        strcpy(ruleList[0].ipend, ip[1]);

        return 2;
    }
    else if (!strcmp(argv[i], "iprange_dst"))
    {
        if (i + 1 > argc)
            return -1;

        char *ip[5] = {0};
        int n = 0;
        split(argv[i + 1], ":", ip, &n);
        ruleList[0].target = RU_DROP;
        ruleList[0].iprangeFlag = 1;
        ruleList[0].dst = 1;
        strcpy(ruleList[0].ipstart, ip[0]);
        strcpy(ruleList[0].ipend, ip[1]);

        return 2;
    }
    else if (!strcmp(argv[i], "iprange"))
    {
        if (i + 1 > argc)
            return -1;

        char *ip[5] = {0};
        int n = 0;
        split(argv[i + 1], ":", ip, &n);
        ruleList[0].target = RU_DROP;
        ruleList[0].iprangeFlag = 1;
        ruleList[0].dst = 1;
        ruleList[0].src = 1;
        strcpy(ruleList[0].ipstart, ip[0]);
        strcpy(ruleList[0].ipend, ip[1]);

        return 2;
    }
    else if (!strcmp(argv[i], "multip_src"))
    {
        if (i + 1 > argc)
            return -1;

        ruleList[0].target = RU_DROP;
        ruleList[0].multipFlag = 1;
        ruleList[0].mult_src = 1;
        char *ip[5] = {0};
        int n = 0;
        split(argv[i + 1], ",", ip, &n);
        if (n > 10)
        {
            printf("the num of IP is too much (more than 10)!");
            return -1;
        }
        int i;
        for (i = 0; i < n; i++)
        {
            strcpy(ruleList[0].iplist[i], ip[i]);
        }

        return 2;
    }
    else if (!strcmp(argv[i], "multip_dst"))
    {
        if (i + 1 > argc)
            return -1;

        ruleList[0].target = RU_DROP;
        ruleList[0].multipFlag = 1;
        ruleList[0].mult_dst = 1;
        char *ip[5] = {0};
        int n = 0;
        split(argv[i + 1], ",", ip, &n);
        if (n > 10)
        {
            printf("the num of IP is too much (more than 10)!");
            return -1;
        }
        int i;
        for (i = 0; i < n; i++)
        {
            strcpy(ruleList[0].iplist[i], ip[i]);
        }

        return 2;
    }
    else if (!strcmp(argv[i], "multip"))
    {
        if (i + 1 > argc)
            return -1;

        ruleList[0].target = RU_DROP;
        ruleList[0].multipFlag = 1;
        ruleList[0].mult_src = 1;
        ruleList[0].mult_dst = 1;
        char *ip[5] = {0};
        int n = 0;
        split(argv[i + 1], ",", ip, &n);
        if (n > 10)
        {
            printf("the num of IP is too much (more than 10)!");
            return -1;
        }
        int i;
        for (i = 0; i < n; i++)
        {
            strcpy(ruleList[0].iplist[i], ip[i]);
        }

        return 2;
    }
    return 0;
}
