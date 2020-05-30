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
    while(*str && (*str == ' ' || *str == '\n' || *str =='\t'))
        ++str;

    for(; *str; ++str)
    {
        switch (*str)
        {
        case '\t':  *str = ' ';
        case ' ' :
            if (*prev == '\n' || *prev ==' ')
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
    if(prev && *prev && (*prev == ' ' || *prev == '\n'))
        --sp;
    *sp = 0;
}

void split(char *src,const char *separator,char **dest,int *num) {
     char *pNext;
     int count = 0;
     if (src == NULL || strlen(src) == 0)
        return;
     if (separator == NULL || strlen(separator) == 0)
        return;
     pNext = strtok(src,separator);
     while(pNext != NULL) {
          *dest++ = pNext;
          ++count;
         pNext = strtok(NULL,separator);
    }
    *num = count;
}


int main(){
    char cmd[100];
    while(1){
        printf("[filter command]:");
        gets(cmd);
        remove_extra_space(cmd);
        if(!strcmp(cmd, "exit")){
            break;
        }
        if(strncmp(cmd, "myiptables ", 11)){
            printf("wrong format\n");
			continue;
        }

        char *rev_cmd[20] = {0};
        int num = 0;

        split(cmd,"-",rev_cmd,&num);
		if(rev_cmd[1][0] == 'h'){
			system("cat help.txt");
		}        
		else if(rev_cmd[1][0] == 'A'){
            initConst();
            initRule(&ruleList[0]);
			int i = 0;      
			for(i = 2;i < num; i ++) {
                char command[20];
				strcpy(command, rev_cmd[i]);
                char *rev[5] = {0};
                int n = 0;
                split(command, " ", rev, &n);
                if(!strlen(rev[0]))
                    continue;
                else if(!strcmp(rev[0], "p")){
                    strcpy(ruleList[0].protocol, rev[1]);
                }
                else if(!strcmp(rev[0], "s")){
                    char *addr[5] = {0};
                    int n = 0;
                    split(rev[1], "/", addr, &n);
                    if(n == 1){
                        strcpy(ruleList[0].saddr, addr[0]);
                        ruleList[0].smask = 32;
                    }
                    else{
                        strcpy(ruleList[0].saddr, addr[0]);
                        ruleList[0].smask = atoi(addr[1]);
                    }
                }
                else if(!strcmp(rev[0], "d")){
                    char *addr[5] = {0};
                    int n = 0;
                    split(rev[1], "/", addr, &n);
                    if(n == 1){
                        strcpy(ruleList[0].daddr, addr[0]);
                        ruleList[0].dmask = 32;
                    }
                    else{
                        strcpy(ruleList[0].daddr, addr[0]);
                        ruleList[0].dmask = atoi(addr[1]);
                    }
                }
                else if(!strcmp(rev[0], "P")){
                    if(!strcmp(rev[1], "drop"))
                        ruleList[0].target = RU_DROP;
                    else if(!strcmp(rev[1], "accpet"))
                        ruleList[0].target = RU_ACCEPT;
                }
                else if(!strcmp(rev[0], "sport")){
                    ruleList[0].sport = atoi(rev[1]);
                }
                else if(!strcmp(rev[0], "dport")){
                    ruleList[0].dport = atoi(rev[1]);
                }
                else if(!strcmp(rev[0], "iprange")){
                    char *ip[5] = {0};
                    int n = 0;
                    split(rev[1], "-", ip, &n);
                    strcpy(ruleList[0].ipstart, ip[0]);
                    strcpy(ruleList[0].ipend, ip[1]);
                }

            }
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

	}

}
