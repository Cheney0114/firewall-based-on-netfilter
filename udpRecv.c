#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("usage: ./a.out port\n");
        return 0;
    }
    char *port = argv[1];
    int iRecvLen = 0;
    int iSocketFD = 0;
    char acBuf[4096] = {0};
    struct sockaddr_in stLocalAddr = {0};

    struct sockaddr_in stRemoteAddr = {0};
    socklen_t iRemoteAddrLen = 0;

    /* 创建socket */
    iSocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (iSocketFD < 0)
    {
        printf("创建socket失败!\n");
        return 0;
    }

    /* 填写地址 */
    stLocalAddr.sin_family = AF_INET;
    stLocalAddr.sin_port = htons(atoi(port));
    stLocalAddr.sin_addr.s_addr = 0;

    /* 绑定地址 */
    if (0 > bind(iSocketFD, (void *)&stLocalAddr, sizeof(stLocalAddr)))
    {
        printf("绑定地址失败!\n");
        close(iSocketFD);
        return 0;
    }

    //循环监听
    while (1)
    {
        iRecvLen = recvfrom(iSocketFD, acBuf, sizeof(acBuf), 0, (void *)&stRemoteAddr, &iRemoteAddrLen);

        printf("iRecvLen: %d\n", iRecvLen);
        printf("acBuf:%s\n", acBuf);
    }

    close(iSocketFD);
    return 0;
}