#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rule.h"
#include "client.h"
// #include <sys/types.h>
#define RULEMAXNUM 51

extern struct rule ruleList[RULEMAXNUM];
char *rev_cmd[20] = {0};


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

int tryParseTime(int i, int argc, char *argv[])
{
    // tryPrase类函数
    // 作用：尝试按照时间模块解析
    // 输入：当前位置i，总共数目argc，字符串列表argv
    // 输出：若成功解析：      下一次解析应该向后移动的位数
    //      若解析不了：       返回 0
    //      若解析时发生错误： 返回 -1
    if (i + 1 > argc)
        return -1;
    printf("argv[%d]:%s", i, argv[i]);
    if (!strcmp(argv[i], "time"))
    {
        printf("into time\n");
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
    else if (!strcmp(argv[i], "dateStart"))
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
    else if (!strcmp(argv[i], "dateEnd"))
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
    else if ((!strcmp(argv[i], "weekdays")) || (!strcmp(argv[i], "weekdays!")))
    {
        int j = 1;
        ruleList[0].timeFlag |= WEEKDAYS;
        if (!strcmp(argv[i], "weekdays!"))
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
    else if (!strcmp(argv[i], "monthdays") || (!strcmp(argv[i], "monthdays!")))
    {
        int j = 1;
        ruleList[0].timeFlag |= MONTHDAYS;
        if (!strcmp(argv[i], "monthdays!"))
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


void parse_rule(int begin, int num){
	int i;
    for (i = begin; i < num; i++)
            {
                char command[200];
                strcpy(command, rev_cmd[i]);
                char *rev[5] = {0};
                int n = 0;
                split(command, " ", rev, &n);
                if (!strlen(rev[0]))
                    continue;
                //******************************************
                int ret;
                ret = tryParseTime(0, n, rev);
                if (ret < 0)
                {
                    printf("wrong format found in ParseTime\n");
                }
                //******************************************
                if (!strcmp(rev[0], "p"))
                {
                    strcpy(ruleList[0].protocol, rev[1]);
                }
                else if (!strcmp(rev[0], "s"))
                {
                    char *addr[5] = {0};
                    int n = 0;
                    split(rev[1], "/", addr, &n);
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
                }
                else if (!strcmp(rev[0], "d"))
                {
                    char *addr[5] = {0};
                    int n = 0;
                    split(rev[1], "/", addr, &n);
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
                }
                else if (!strcmp(rev[0], "P"))
                {
                    if (!strcmp(rev[1], "drop"))
                        ruleList[0].target = RU_DROP;
                    else if (!strcmp(rev[1], "accpet"))
                        ruleList[0].target = RU_ACCEPT;
                }
                else if (!strcmp(rev[0], "sport"))
                {
                    ruleList[0].sport = atoi(rev[1]);
                }
                else if (!strcmp(rev[0], "dport"))
                {
                    ruleList[0].dport = atoi(rev[1]);
                }
                else if (!strcmp(rev[0], "iprange_src"))
                {
                    ruleList[0].target = RU_DROP;
                    ruleList[0].iprangeFlag = 1;
                    ruleList[0].src = 1;
                    char *ip[5] = {0};
                    int n = 0;
                    split(rev[1], ":", ip, &n);

                    char *ip_item[5] = {0};
					split(ip[0], "/", ip_item, &n);
					if (n == 1) {
						strcpy(ruleList[0].ipstart, ip_item[0]);
					} else {
						strcpy(ruleList[0].ipstart, ip_item[0]);
						ruleList[0].mask_start_bit = atoi(ip_item[1]);
					}
					split(ip[1], "/", ip_item, &n);
					if (n == 1) {
						strcpy(ruleList[0].ipend, ip_item[0]);
					} else {
						strcpy(ruleList[0].ipend, ip_item[0]);
						ruleList[0].mask_end_bit = atoi(ip_item[1]);
					}
                }
                else if (!strcmp(rev[0], "iprange_dst"))
                {
                    ruleList[0].target = RU_DROP;
                    ruleList[0].iprangeFlag = 1;
                    ruleList[0].dst = 1;
                    char *ip[5] = {0};
                    int n = 0;
                    split(rev[1], ":", ip, &n);

                    char *ip_item[5] = {0};
					split(ip[0], "/", ip_item, &n);
					if (n == 1) {
						strcpy(ruleList[0].ipstart, ip_item[0]);
					} else {
						strcpy(ruleList[0].ipstart, ip_item[0]);
						ruleList[0].mask_start_bit = atoi(ip_item[1]);
					}
					split(ip[1], "/", ip_item, &n);
					if (n == 1) {
						strcpy(ruleList[0].ipend, ip_item[0]);
					} else {
						strcpy(ruleList[0].ipend, ip_item[0]);
						ruleList[0].mask_end_bit = atoi(ip_item[1]);
					}
                }
                else if (!strcmp(rev[0], "iprange"))
                {
                    ruleList[0].target = RU_DROP;
                    ruleList[0].iprangeFlag = 1;
                    ruleList[0].dst = 1;
                    ruleList[0].src = 1;
                    char *ip[5] = {0};
                    int n = 0;
                    split(rev[1], ":", ip, &n);

                    char *ip_item[5] = {0};
					split(ip[0], "/", ip_item, &n);
					if (n == 1) {
						strcpy(ruleList[0].ipstart, ip_item[0]);
					} else {
						strcpy(ruleList[0].ipstart, ip_item[0]);
						ruleList[0].mask_start_bit = atoi(ip_item[1]);
					}
					split(ip[1], "/", ip_item, &n);
					if (n == 1) {
						strcpy(ruleList[0].ipend, ip_item[0]);
					} else {
						strcpy(ruleList[0].ipend, ip_item[0]);
						ruleList[0].mask_end_bit = atoi(ip_item[1]);
					}
                }
                else if (!strcmp(rev[0], "multip_src"))
                {
                    ruleList[0].target = RU_DROP;
                    ruleList[0].multipFlag = 1;
                    ruleList[0].mult_src = 1;
                    char *ip[5] = {0};
                    int n = 0;
                    split(rev[1], ",", ip, &n);
                    if (n > 10)
                    {
                        printf("the num of IP is too much (more than 10)!");
                    }
                    int i;
                    for (i = 0; i < n; i++)
                    {
                        strcpy(ruleList[0].iplist[i], ip[i]);
                    }
                }
                else if (!strcmp(rev[0], "multip_dst"))
                {
                    ruleList[0].target = RU_DROP;
                    ruleList[0].multipFlag = 1;
                    ruleList[0].mult_dst = 1;
                    char *ip[5] = {0};
                    int n = 0;
                    split(rev[1], ",", ip, &n);
                    if (n > 10)
                    {
                        printf("the num of IP is too much (more than 10)!");
                    }
                    int i;
                    for (i = 0; i < n; i++)
                    {
                        strcpy(ruleList[0].iplist[i], ip[i]);
                    }
                }
                else if (!strcmp(rev[0], "multip"))
                {
                    ruleList[0].target = RU_DROP;
                    ruleList[0].multipFlag = 1;
                    ruleList[0].mult_src = 1;
                    ruleList[0].mult_dst = 1;
                    char *ip[5] = {0};
                    int n = 0;
                    split(rev[1], ",", ip, &n);
                    if (n > 10)
                    {
                        printf("the num of IP is too much (more than 10)!");
                    }
                    int i;
                    for (i = 0; i < n; i++)
                    {
                        strcpy(ruleList[0].iplist[i], ip[i]);
                    }
                }
                else if (!strcmp(rev[0], "strMaxNum"))
                {
                    ruleList[0].strFlag = atoi(rev[1]);
                }
                else if (!strcmp(rev[0], "strPat"))
                {
                    strcpy(ruleList[0].strPattern, rev[1]);
                }
                else if (!strcmp(rev[0], "regMaxNum"))
                {
                    ruleList[0].regFlag = atoi(rev[1]);
                }
                else if (!strcmp(rev[0], "regPat"))
                {
                    int i = 0;
                    for(i = 0; i < strlen(rev[1]); i++){
                        if(rev[1][i] == ':')
                            rev[1][i] = '-';
                    }
                    strcpy(ruleList[0].regPattern, rev[1]);
                }
                else if (!strcmp(rev[0], "limit"))
                {
                    ruleList[0].limitFlag = 1;
                    strcpy(ruleList[0].rateStr, rev[1]);
                }
                else if (!strcmp(rev[0], "limit_burst"))
                {
                    if(ruleList[0].limitFlag == 0){
                        printf("please -limit first\n");
                    }
                    ruleList[0].maxToken = atoi(rev[1]);
                }
                else{
                    printf("wrong format!/n");
                }
            }
}


int main()
{
    char cmd[1000];
    while (1)
    {
    	initConst();
        printf("[wallfire filter command]:");
        gets(cmd);
        remove_extra_space(cmd);
        if (!strcmp(cmd, "exit"))
        {
			flushRule();
            break;
        }
        if (strncmp(cmd, "myiptables ", 11))
        {
            printf("wrong format\n");
            continue;
        }
        int i = 0;
        for(i = 0; i < strlen(cmd); i++){
            if(cmd[i] == '-' && cmd[i - 1] != ' ' && cmd[i-1] != '-'){
                cmd[i] = ':';
            }
        }
        int num = 0;
        split(cmd, "-", rev_cmd, &num);

        if (rev_cmd[1][0] == 'h')
        {
            system("cat help.txt");
        }
        else if (rev_cmd[1][0] == 'A')
        {
            
            initRule(&ruleList[0]);
            parse_rule(2, num);
            appendRule(1);
            displayHeader();
            printf("read: %d\n", readRuleInfo());
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
        else if (rev_cmd[1][0] == 'D'){
            char command[200];
            strcpy(command, rev_cmd[1]);
            char *rev[5] = {0};
            int n = 0;
            split(command, " ", rev, &n);
            int rule_num = atoi(rev[1]);
            deleteRule(rule_num);
        }
        else if(rev_cmd[1][0] == 'I'){
            char command[200];
            strcpy(command, rev_cmd[1]);
            char *rev[5] = {0};
            int n = 0;
            split(command, " ", rev, &n);
            int rule_num = atoi(rev[1]);
            initConst();
            initRule(&ruleList[0]);
            parse_rule(2, num);

            insertRule(1, rule_num);
            
        }
        else if(rev_cmd[1][0] == 'L'){
            displayHeader();
            printf("read: %d\n", readRuleInfo());
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
        else if(rev_cmd[1][0] == 'R'){
            char command[200];
            strcpy(command, rev_cmd[1]);
            char *rev[5] = {0};
            int n = 0;
            split(command, " ", rev, &n);
            int rule_num = atoi(rev[1]);
            initConst();
            initRule(&ruleList[0]);
            parse_rule(2, num);
            deleteRule(rule_num);
            insertRule(1, rule_num);
        }
        else if(!strncmp(rev_cmd[1], "default", 7)){
            char command[200];
            strcpy(command, rev_cmd[1]);
            char *rev[5] = {0};
            int n = 0;
            split(command, " ", rev, &n);
            if(!strcmp(rev[1], "drop"))
                setDefaultRule(RU_DROP);
            else if(!strcmp(rev[1], "accept"))
                setDefaultRule(RU_ACCEPT);
        }
    }
}
