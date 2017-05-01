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
#define MAX_ROUTE_INFO 100
#define MAX_ARP_SIZE 100
#define MAX_DEVICE 100

struct route_item
{
	char dest[16];
	char gw[16];
	char netmask[16];
	char interface[16];
}route_info[MAX_ROUTE_INFO];
int route_item_index=0;

struct arp_table_item
{
	char ip[16];
	char mac[18];
}arp_table[MAX_ARP_SIZE];
int arp_item_index =0;

struct device_item
{
	char interface[14];
	char mac[18];
}device[MAX_DEVICE];
int device_index=0;

char recvpacket[PACKET_SIZE];
int sockfd,datalen=56;
int nsend = 0, nreceived = 0;
 
struct sockaddr_ll dest_addr;
struct sockaddr_in from;
struct timeval tvrecv;
pid_t pid;

void init_arp_table()
{
	FILE *fp=fopen("arp_table","r");
	if(!fp)
	{
		printf("can't open arp_table!\n");
		exit(0);
	}
	fscanf(fp,"%s",arp_table[0].ip);
	fscanf(fp,"%s",arp_table[0].mac);
	++arp_item_index;
	while(!feof(fp))
	{
		fscanf(fp,"%s",arp_table[arp_item_index].ip);
		fscanf(fp,"%s",arp_table[arp_item_index].mac);
		++arp_item_index;
	}
}

void init_device()
{
	FILE *fp=fopen("device","r");
	if(!fp)
	{
		printf("can't open the device!\n");
		exit(0);
	}
	fscanf(fp,"%s",device[device_index].interface);
	fscanf(fp,"%s",device[device_index].mac);
	++device_index;
	while(!feof(fp))
	{
		fscanf(fp,"%s",device[device_index].interface);
		fscanf(fp,"%s",device[device_index].mac);
		++device_index;
	}
}

void init_route_info()
{
	FILE *fp=fopen("route_info","r");
	if(!fp)
	{
		printf("can't open route_info\n");
		exit(0);
	}
	fscanf(fp,"%s",route_info[route_item_index].dest);
	fscanf(fp,"%s",route_info[route_item_index].gw);
	fscanf(fp,"%s",route_info[route_item_index].netmask);
	fscanf(fp,"%s",route_info[route_item_index].interface);
	++route_item_index;
	while(!feof(fp))
	{
		fscanf(fp,"%s",route_info[route_item_index].dest);
		fscanf(fp,"%s",route_info[route_item_index].gw);
		fscanf(fp,"%s",route_info[route_item_index].netmask);
		fscanf(fp,"%s",route_info[route_item_index].interface);
		++route_item_index;
	}
}

void recv_packet()
{
    int n,fromlen;
    extern int error;
    fromlen = sizeof(from);
	bzero(recvpacket,sizeof(recvpacket));
	if(1)
    {   
        if((n = recvfrom(sockfd,recvpacket,sizeof(recvpacket),0,NULL,NULL))<0)
        {
            perror("recvfrom error");
        }
		unsigned char *p=recvpacket;
		int i=0;
		/*printf("%x",p[0]);
		for(;i<n;++i)
			printf("%x ",p[i]);*/
		char temp[4];
		for(i=0;i<route_item_index;++i)
		{
			int j=0,k=0;
			char *dest=route_info[i].dest;
			for(j=0;j<strlen(dest)&&dest[j]!='.';++j,++k)
				temp[k]=dest[j];
			temp[k]='\0';
			//printf("\ntemp:%s.",temp);
			if(p[30]!=atoi(temp))
				continue;
			for(++j,k=0;j<strlen(dest)&&dest[j]!='.';++j,++k)
				temp[k]=dest[j];
			temp[k]='\0';
			//printf("%s.",temp);
			if(p[31]!=atoi(temp))
				continue;
			for(++j,k=0;j<strlen(dest)&&dest[j]!='.';++j,++k)
				temp[k]=dest[j];
			temp[k]='\0';
			//printf("%s.\n",temp);
			if(p[32]!=atoi(temp))
				continue;
			break;
		}
		//printf("%d\n",i);
		if(i==route_item_index)
		{
			//printf("not find\n");
			return ;
		}
		printf("%d.%d.%d.%d==>%d.%d.%d.%d\n",p[26],p[27],p[28],p[29],p[30],p[31],p[32],p[33]);
		//else
		//	printf("get!!!\n");
		int index=i;
		struct sockaddr_ll dest_addr;
		memset((char *)&dest_addr,0,sizeof(struct sockaddr_ll));
		dest_addr.sll_family=AF_PACKET;
		dest_addr.sll_protocol=htons(ETH_P_ALL);
		dest_addr.sll_ifindex=if_nametoindex(route_info[index].interface);
		dest_addr.sll_halen=htons(6);
		int len=sizeof(dest_addr);
		//p[0]=0x00;p[1]=0x0c;p[2]=0x29;p[3]=0x44;p[4]=0x7a;p[5]=0xdc;
		int j=0,k=0;
		for(i=0;i<arp_item_index;++i)
		{
			for(k=0,j=0;j<strlen(arp_table[i].ip)&&arp_table[i].ip[j]!='.';++j,++k)
				temp[k]=arp_table[i].ip[j];
			temp[k]='\0';
			//printf("temp:%s.",temp);
			if(p[30]!=atoi(temp))
				continue;
			for(++j,k=0;j<strlen(arp_table[i].ip)&&arp_table[i].ip[j]!='.';++j,++k)
				temp[k]=arp_table[i].ip[j];
			temp[k]='\0';
			//printf("%s.",temp);
			if(p[31]!=atoi(temp))
				continue;
			for(++j,k=0;j<strlen(arp_table[i].ip)&&arp_table[i].ip[j]!='.';++j,++k)
				temp[k]=arp_table[i].ip[j];
			temp[k]='\0';
			//printf("%s.",temp);
			if(p[32]!=atoi(temp))
				continue;
			for(++j,k=0;j<strlen(arp_table[i].ip)&&arp_table[i].ip[j]!='.';++j,++k)
				temp[k]=arp_table[i].ip[j];
			temp[k]='\0';
			//printf("%s\n",temp);
			if(p[33]!=atoi(temp))
				continue;
			break;
		}
		if(i==arp_item_index)
		{
			printf("can't find in arp_table\n");
			return ;
		}
		for(j=0;j<6;++j)
		{
			//for(k=0;k<strlen(arp_table[i].mac)&&arp_table[i].mac[k]!=':';++k
			int sum=0;
			if(arp_table[i].mac[j*3]>='0'&&arp_table[i].mac[j*3]<='9')
				sum=arp_table[i].mac[j*3]-'0';
			else if(arp_table[i].mac[j*3]>='a'&&arp_table[i].mac[j*3]<='f')
				sum=arp_table[i].mac[j*3]-'a'+10;
			sum*=16;
			if(arp_table[i].mac[j*3+1]>='0'&&arp_table[i].mac[j*3+1]<='9')
				sum+=arp_table[i].mac[j*3+1]-'0';
			else if(arp_table[i].mac[j*3+1]>='a'&&arp_table[i].mac[j*3+1]<='f')
				sum+=arp_table[i].mac[j*3+1]-'a'+10;
			p[j]=sum;
			//printf("%x:",p[j]);
		}
		//printf("\n");
		for(i=0;i<device_index;++i)
		{
			if(strcmp(route_info[index].interface,device[i].interface)==0)
				break;
		}
		if(i==device_index)
		{
			printf("can't find in device\n");
			return ;
		}
		for(j=0;j<6;++j)
		{
			//for(k=0;k<strlen(arp_table[i].mac)&&arp_table[i].mac[k]!=':';++k
			int sum=0;
			if(device[i].mac[j*3]>='0'&&device[i].mac[j*3]<='9')
				sum=device[i].mac[j*3]-'0';
			else if(device[i].mac[j*3]>='a'&&device[i].mac[j*3]<='f')
				sum=device[i].mac[j*3]-'a'+10;
			sum*=16;
			if(device[i].mac[j*3+1]>='0'&&device[i].mac[j*3+1]<='9')
				sum+=device[i].mac[j*3+1]-'0';
			else if(device[i].mac[j*3+1]>='a'&&device[i].mac[j*3+1]<='f')
				sum+=device[i].mac[j*3+1]-'a'+10;
			p[j+6]=sum;
		}
		//p[6]=0x00;p[7]=0x0c;p[8]=0x29;p[9]=0x7b;p[10]=0x68;p[11]=0x32;
		//printf("%x:%x:%x:%x:%x:%x==>%x:%x:%x:%x:%x:%x\n",p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
		if(sendto(sockfd,recvpacket,94,0,(struct sockaddr *)&dest_addr,sizeof(dest_addr))<0)
			printf("error");
        gettimeofday(&tvrecv,NULL);    
        nreceived++;
    }
}

int main()
{
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr = 0;
    int size = 50 * 1024;
    if((protocol = getprotobyname("icmp")) == NULL)
    {
        perror("getprotobyname");
        exit(1);
    }
    if((sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
    {
        perror("socket error");
        exit(1);
    }
 
	init_route_info();
	init_arp_table();
	init_device();

    while(nsend < MAX_NO_PACKETS){
        //sleep(1);      
        recv_packet();      
    }
    return 0;
}
