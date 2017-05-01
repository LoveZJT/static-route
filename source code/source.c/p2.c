#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <net/if.h>
 
#define PACKET_SIZE 4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  10000
 
 
char recvpacket[PACKET_SIZE];
int sockfd,datalen = 56;
int nsend = 0, nreceived = 0;
 
struct sockaddr_ll dest_addr;
struct sockaddr_in from;
struct timeval tvrecv;
pid_t pid;
 
/****接受所有ICMP报文****/
void recv_packet()
{
    int n,fromlen;
    extern int error;
    fromlen = sizeof(from);
	if(1)
    {   
        //接收数据报
        if((n = recvfrom(sockfd,recvpacket,sizeof(recvpacket),0,NULL,NULL))<0)
        {
            perror("recvfrom error");
        }
		unsigned char *p=recvpacket;
		printf("%u.%u.%u.%u==>%u.%u.%u.%u\n",p[26],p[27],p[28],p[29],p[30],p[31],p[32],p[33]);
		unsigned char temp;
		int i=0;
		for(i=0;i<6;++i)
		{
			temp=p[i];
			p[i]=p[i+6];
			p[i+6]=temp;
		}
		for(i=26;i<30;++i)
		{
			temp=p[i];
			p[i]=p[i+4];
			p[i+4]=temp;
		}
		if(sendto(sockfd,recvpacket,94,0,(struct sockaddr*)&dest_addr,sizeof(dest_addr))<0)
			printf("error\n");
        //gettimeofday(&tvrecv,NULL);     //记录接收时间
        nreceived++;
    }
}

/*主函数*/
int main(int argc,char *argv[])
{
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr = 0;
//  int waittime = MAX_WAIT_TIME;
    int size = 50 * 1024;
    //不是ICMP协议
    if((protocol = getprotobyname("icmp")) == NULL)
    {
        perror("getprotobyname");
        exit(1);
    }
 
    //生成使用ICMP的原始套接字，只有root才能生成
    if((sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
    {
        perror("socket error");
        exit(1);
    }
 
    //回收root权限，设置当前权限
    setuid(getuid());

	memset((char *)&dest_addr,0,sizeof(struct sockaddr));
	dest_addr.sll_family=AF_PACKET;
	dest_addr.sll_protocol=htons(ETH_P_ALL);
	dest_addr.sll_ifindex=if_nametoindex("eth0");
	dest_addr.sll_halen=htons(6);

	//当按下ctrl+c时发出中断信号，并开始执行统计函数
    while(nsend < MAX_NO_PACKETS){
        //sleep(1);       
        recv_packet();      //接收ICMP报文
    }
    return 0;
}
