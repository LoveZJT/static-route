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
#include <string.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/time.h>
 
#define PACKET_SIZE 4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  10000
#define MAX_ARP_SIZE 100
 
 
char *addr[2];
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
int sockfd,datalen = 56;
int nsend = 0, nreceived = 0;
double temp_rtt[MAX_NO_PACKETS];
double all_time = 0;
double min = 0;
double max = 0;
double avg = 0;
double mdev = 0;
char local_mac[18];

struct sockaddr_ll dest_addr;
struct sockaddr_in from;
struct timeval tvrecv;
struct timeval tval;
pid_t pid;
 
struct arp_table_item
{
	char ip_addr[16];
	char mac_addr[18];
}arp_table[MAX_ARP_SIZE];
int arp_item_index=0;


void statistics(int sig);
void send_packet(char *dest);
void recv_packet(char *dest);
void computer_rtt(void);
void tv_sub(struct timeval *out,struct timeval *in);
int pack(char *dest);
int unpack(char *buf,int len);
unsigned short cal_checksum(unsigned short *addr,int len);
 
void init_arp()
{
	FILE *fp=fopen("arp_table","r");
	if(!fp)
	{
		printf("can't open arp_table!\n");
		exit(0);
	}
	fscanf(fp,"%s",arp_table[0].ip_addr);
	fscanf(fp,"%s",arp_table[0].mac_addr);
	++arp_item_index;
	while(!feof(fp))
	{
		fscanf(fp,"%s",arp_table[arp_item_index].ip_addr);
		fscanf(fp,"%s",arp_table[arp_item_index].mac_addr);
		++arp_item_index;
	}
}

init_device()
{
	FILE *fp=fopen("device","r");
	if(!fp)
	{
		printf("can't open the device!\n");
		exit(0);
	}
	fscanf(fp,"%s",local_mac);
	fscanf(fp,"%s",local_mac);
}

/*����rtt��С����ֵ��ƽ��ֵ������ƽ������*/
void computer_rtt()
{
    double sum_avg = 0;
    int i;
    min = max = temp_rtt[0];
    avg = all_time/nreceived;
 
    for(i=0; i<nreceived; i++){
        if(temp_rtt[i] < min)
            min = temp_rtt[i];
        else if(temp_rtt[i] > max)
            max = temp_rtt[i];
 
        if((temp_rtt[i]-avg) < 0)
            sum_avg += avg - temp_rtt[i];
        else
            sum_avg += temp_rtt[i] - avg; 
        }
    mdev = sum_avg/nreceived;
}
 
/****ͳ�����ݺ���****/
void statistics(int sig)
{
    computer_rtt();     //����rtt
    printf("\n------ %s ping statistics ------\n",addr[0]);
    printf("%d packets transmitted,%d received,%d%% packet loss,time %.f ms\n",
        nsend,nreceived,(nsend-nreceived)/nsend*100,all_time);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
        min,avg,max,mdev);
    close(sockfd);
    exit(1);
}
 
/****������㷨****/
unsigned short cal_chksum(unsigned short *addr,int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short check_sum = 0;
 
    while(nleft>1)       //ICMP��ͷ���֣�2�ֽڣ�Ϊ��λ�ۼ�
    {
        sum += *w++;
        nleft -= 2;
    }
 
    if(nleft == 1)      //ICMPΪ�����ֽ�ʱ��ת�����һ���ֽڣ������ۼ�
    {
        *(unsigned char *)(&check_sum) = *(unsigned char *)w;
        sum += check_sum;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    check_sum = ~sum;   //ȡ���õ�У���
    return check_sum;
}
 
/*����ICMP��ͷ*/
int pack(char *dest)
{
    /*int i,packsize;
    struct icmp *icmp;
    struct timeval *tval;
    icmp = (struct icmp*)sendpacket;
    icmp->icmp_type = ICMP_ECHO; //ICMP_ECHO���͵����ͺ�Ϊ0
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;    //���͵����ݱ����
    icmp->icmp_id = pid;
 
    packsize = 8 + datalen;     //���ݱ���СΪ64�ֽ�
    tval = (struct timeval *)icmp->icmp_data;
    gettimeofday(tval,NULL);        //��¼����ʱ��
    //У���㷨
    icmp->icmp_cksum =  cal_chksum((unsigned short *)icmp,packsize); 
    return packsize;*/

	int i=0,index=-1;
	for(i=0;i<arp_item_index;++i)
	{
		if(strcmp(dest,arp_table[i].ip_addr)==0)
		{
			index=i;
			break;
		}
	}
	if(index==-1)
	{
		printf("can't not patch the ip!\n");
		exit(0);
	}
	//printf("%d\n",index);
	unsigned char src_mac[6]={0x00,0x0c,0x29,0x83,0xcf,0x3e};
	unsigned char dest_mac[6]={0x00,0x0c,0x29,0x7b,0x68,0x28};
	unsigned char *p=sendpacket;
	for(i=0;i<94;++i)
		p[i]=0;
	for(i=0;i<6;++i)
	{
		//p[i]=dest_mac[i];
		//char *temp=arp_table[index].mac_addr;
		int sum=0;
		if(arp_table[index].mac_addr[3*i]>='0'&&arp_table[index].mac_addr[3*i]<='9')
			sum=arp_table[index].mac_addr[3*i]-'0';
		else if(arp_table[index].mac_addr[3*i]>='a'&&arp_table[index].mac_addr[3*i]<='f')
			sum=arp_table[index].mac_addr[3*i]-'a'+10;
		sum*=16;
		if(arp_table[index].mac_addr[3*i+1]>='0'&&arp_table[index].mac_addr[3*i+1]<='9')
			sum+=arp_table[index].mac_addr[3*i+1]-'0';
		else if(arp_table[index].mac_addr[3*i+1]>='a'&&arp_table[index].mac_addr[3*i+1]<='f')
			sum+=arp_table[index].mac_addr[3*i+1]-'a'+10;
		p[i]=sum;
	}
	for(i=0;i<6;++i)
	{
		//p[i+6]=src_mac[i];
		int sum=0;
		if(local_mac[3*i]>='0'&&local_mac[3*i]<='9')
			sum=local_mac[3*i]-'0';
		else if(local_mac[3*i]>='a'&&local_mac[3*i]<='f')
			sum=local_mac[3*i]-'a'+10;
		sum*=16;
		if(local_mac[3*i+1]>='0'&&local_mac[3*i+1]<='9')
			sum+=local_mac[3*i+1]-'0';
		else if(local_mac[3*i+1]>='a'&&local_mac[3*i+1]<='f')
			sum+=local_mac[3*i+1]-'a'+10;
		p[i+6]=sum;
	}
	p[12]=0x08;p[13]=0x00;
	p[14]=0x45;
	p[15]=0x00;
	p[16]=0x00;p[17]=0x54;
	p[18]=0x00;p[19]=0x00;
	p[20]=0x40;p[21]=0x00;
	p[22]=0x40;
	p[23]=0x01;
	p[24]=0x00;p[25]=0x00;
	p[26]=192;p[27]=168;p[28]=1;p[29]=1;
	p[40]=nsend/256;p[41]=nsend%256;
	//p[30]=192;p[31]=168;p[32]=2;p[33]=1;
	int j=0;
	for(i=30;i<34;++i)
	{
		char temp[4];
		int k=0;
		for(k=0;j<strlen(dest)&&dest[j]!='.';++j,++k)
			temp[k]=dest[j];
		temp[k]='\0';
		++j;
		p[i]=atoi(temp);
	}

	return 94;
}
 
/****��������ICMP����****/
void send_packet(char *dest)
{
    int packetsize;
    if(nsend < MAX_NO_PACKETS)
    {
        nsend++;
        packetsize = pack(dest);   //����ICMP��ͷ
        //�������ݱ�
        if(sendto(sockfd,sendpacket,packetsize,0,
            (struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0)
        {
            perror("sendto error");
        }
		gettimeofday(&tval,NULL);
    }
 
}
 
 
/****��������ICMP����****/
void recv_packet(char *dest)
{
    int n,fromlen;
    extern int error;
    fromlen = sizeof(from);
    if(nreceived < nsend)
    {   
        //�������ݱ�
        if((n = recvfrom(sockfd,recvpacket,sizeof(recvpacket),0,
            (struct sockaddr *)&from,&fromlen)) < 0)
        {
            perror("recvfrom error");
        }
        gettimeofday(&tvrecv,NULL);     //��¼����ʱ��
        //unpack(recvpacket,n);       //��ȥICMP��ͷ
        //tv_sub(&tvrecv,&tval); //���պͷ��͵�ʱ���
        //�Ժ���Ϊ��λ����rtt
        //double rtt = tvrecv.tv_sec*1000 + tvrecv.tv_usec/1000;
		double rtt=(tvrecv.tv_sec-tval.tv_sec)*1000000+(tvrecv.tv_usec-tval.tv_usec);
		rtt/=10;
        printf("64 bytes from %s: icmp_seq=%d ttl=64 time=%lf ms\n",
                dest,nreceived,rtt);
		all_time+=rtt;
		//printf("%ld,%ld\n",tvrecv.tv_sec,tvrecv.tv_usec);
		//printf("%ld,%ld\n",tval.tv_sec,tval.tv_usec);
		nreceived++;
    }
}
 
 
/******��ȥICMP��ͷ******/
int unpack(char *buf,int len)
{
    int i;
    int iphdrlen;       //ipͷ����
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
 
 
    ip = (struct ip *)buf;
    iphdrlen = ip->ip_hl << 2; //��IP����ͷ���ȣ���IP��ͷ���ȳ�4
    icmp = (struct icmp *)(buf + iphdrlen); //Խ��IPͷ��ָ��ICMP��ͷ
    len -= iphdrlen;    //ICMP��ͷ�����ݱ����ܳ���
    if(len < 8)      //С��ICMP��ͷ�ĳ����򲻺���
    {
        printf("ICMP packet\'s length is less than 8\n");
        return -1;
    }
    //ȷ�������յ���������ICMP�Ļ�Ӧ
    //if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
    {
        tvsend = (struct timeval *)icmp->icmp_data;
        tv_sub(&tvrecv,&tval); //���պͷ��͵�ʱ���
        //�Ժ���Ϊ��λ����rtt
        rtt = tvrecv.tv_sec*1000 + tvrecv.tv_usec/1000;
        temp_rtt[nreceived] = rtt;
        all_time += rtt;    //��ʱ��
        //��ʾ��ص���Ϣ
    }
    //else return -1;
}
 
 
//����timeval���
void tv_sub(struct timeval *recvtime,struct timeval *sendtime)
{
    long sec = recvtime->tv_sec - sendtime->tv_sec;
    long usec = recvtime->tv_usec - sendtime->tv_usec;
    if(usec >= 0){
        recvtime->tv_sec = sec;
        recvtime->tv_usec = usec;
    }else{
        recvtime->tv_sec = sec - 1;
        recvtime->tv_usec = -usec;
    }
}
 
/*������*/
main(int argc,char *argv[])
{
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr = 0;
//  int waittime = MAX_WAIT_TIME;
    int size = 50 * 1024;
    addr[0] = argv[1];
    //����С������
    if(argc < 2)     
    {
        printf("usage:%s hostname/IP address\n",argv[0]);
        exit(1);
    }
    //����ICMPЭ��
    if((protocol = getprotobyname("icmp")) == NULL)
    {
        perror("getprotobyname");
        exit(1);
    }
 
    //����ʹ��ICMP��ԭʼ�׽��֣�ֻ��root��������
    if((sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
    {
        perror("socket error");
        exit(1);
    }
 
    //����rootȨ�ޣ����õ�ǰȨ��
    setuid(getuid());
 
    /*�����׽��ֵĽ��ջ�������50K����������Ϊ�˼�С���ջ����������
      �����ԣ���������pingһ���㲥��ַ��ಥ��ַ����������������Ӧ��
    setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
    //bzero(&dest_addr,sizeof(dest_addr));    //��ʼ��
    //dest_addr.sin_family = AF_INET;     //�׽�������AF_INET(�����׽���)
 
    //�ж��������Ƿ���IP��ַ
    if(inet_addr(argv[1]) == INADDR_NONE)
    {
        if((host = gethostbyname(argv[1])) == NULL) //��������
        {
            perror("gethostbyname error");
            exit(1);
        }
        memcpy((char *)&dest_addr.sin_addr,host->h_addr,host->h_length);
    }
    else{ //��IP ��ַ
        dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
    }*/

	init_arp();
	init_device();

	memset((char *)&dest_addr,0,sizeof(struct sockaddr_ll));
	dest_addr.sll_family=AF_PACKET;
	dest_addr.sll_protocol=htons(ETH_P_ALL);
	dest_addr.sll_ifindex=if_nametoindex("eth0");
	dest_addr.sll_halen=htons(6);

    pid = getpid();
    //printf("PING %s(%s):%d bytes of data.\n",argv[1],
      //      inet_ntoa(dest_addr.sin_addr),datalen);
 
    //������ctrl+cʱ�����ж��źţ�����ʼִ��ͳ�ƺ���
    signal(SIGINT,statistics);  
    while(nsend < MAX_NO_PACKETS){
        sleep(1);       //ÿ��һ�뷢��һ��ICMP����
        send_packet(argv[1]);      //����ICMP����
        recv_packet(argv[1]);      //����ICMP����
    }
    return 0;
}
