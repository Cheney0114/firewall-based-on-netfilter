#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<arpa/inet.h>

int main(int argc,char **argv)
{
	if(argc<2)
	{	
		printf("usage1: ./a.out ip_addr port str\n");
		printf("usage2: cat testfile | xargs -0 -I {} ./a.out ip_addr port {}\n");
		return 0;
	}
	char *addr = argv[1];
	char *port = argv[2];
	char *str = argv[3];

	struct sockaddr_in addr_in;
	int remoteAddr;
	
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{	
		printf("create socket failed\n");
		return 0;
	}

	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(atoi(port));
	if(inet_pton(AF_INET, addr, &addr_in.sin_addr) < 0)
	{
		printf("ip addr error:%s\n", addr);
		return 0;
	}

	int ret = sendto(fd, str,strlen(str),0,(void*)&addr_in,sizeof(addr_in));
	printf("ret:%d\n",ret);
	return 0;
}
