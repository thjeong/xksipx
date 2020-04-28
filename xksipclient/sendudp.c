/* Write a udp packet and send it through
* a raw socket.
* Thamer Al-Herbish shadows@whitefang.com
*/

#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/in_systm.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/tcp.h>

#include <string.h>  //memset()
#include <unistd.h>

#define BUFLEN 1470	// MTU로 바꿀 것
#define MY_PORT 5060

//-------  함수의 헤더를 선언한다.
// in_cksum --Checksum routine for Internet Protocol family headers (C Version)      

unsigned short in_cksum(unsigned short *addr, int len);

void ip_gen(char *packet,
                  unsigned char protocol,
                  struct in_addr saddr,          
                  struct in_addr daddr,
                  unsigned short length) ;                      

void udp_gen(char *packet,
             unsigned short sport,
             unsigned short dport,
             unsigned short length);
                
//int sendto_raw(int argc, char *argv[])
int sendto_raw(int dest_port, char* dest_address, char* message, int len)
{
  unsigned char packet[
          sizeof(struct iphdr) +
        sizeof(struct udphdr) +
        len];
  struct in_addr saddr, daddr;  // 근원지 주소와 목적지 주소
  unsigned short sport, dport;  // 근원지 포트와 목적지 포트
  struct sockaddr_in mysocket;  // 소켓을 생성
  struct udphdr *udphdr;        // UDP 헤더 생성
  int sockd, on = 1;                // 소켓 기술자

  // len을 MTU와 반드시 비교할 것

/*
  int messlen;
  char message[BUFLEN];
  FILE *fp;
  
  fp = fopen(argv[5], "r");
  messlen = fread(message,1,2048, fp);

  if(argc < 5)  {
    fprintf(stderr,"usage: %s source_port source_address dest_port dest_address\n",
            argv[0]);
    exit(1);
  }
  
  sport = (unsigned short)atoi(argv[1]);
  saddr.s_addr = inet_addr(argv[2]);

  dport = (unsigned short)atoi(argv[3]);
  daddr.s_addr = inet_addr(argv[4]);
*/

  sport = (unsigned short)(MY_PORT);
  saddr.s_addr = INADDR_ANY; /* auto-fill with my IP */

  dport = (unsigned short)(dest_port);
  daddr.s_addr = inet_addr(dest_address);
  
  //소켓을 생성한다.  socket(도메일 페밀리, 소켓 타입,프로토콜);
  if((sockd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW)) < 0)  {
    perror("socket");
    exit(1);
  }
  
  //소켓 옵션을 변경 setsockopt(소켓기술자,프로토콜,옵션네임,옵션버퍼,사이즈);
  //소켓을 IP 프로토콜로 변경 ... 근뎅.... 왜 변경하징.. 몰것당..??
  if(setsockopt(sockd,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on)) < 0)  {
    perror("setsockopt");
    exit(1);
  }

  //IP를 생성  
  ip_gen(packet,IPPROTO_UDP,saddr,daddr,sizeof(packet));

  udphdr = (struct udphdr *)(packet + sizeof(struct iphdr));

  memset((packet+sizeof(struct udphdr)+sizeof(struct iphdr)),
         '0',len);  /* Just zero out the message content. */

  strcpy(packet+sizeof(struct iphdr) + sizeof(struct udphdr),message);
          
  udp_gen((char *)udphdr,sport,dport,(sizeof(struct udphdr)) + len);

  memset(&mysocket,'\0',sizeof(mysocket));
  
  mysocket.sin_family = AF_INET;
  mysocket.sin_port = htons(dport);
  mysocket.sin_addr = daddr;
  
/*
  printf("%s\n", packet+sizeof(struct iphdr) + sizeof(struct udphdr));
  printf("header size:%d\n", sizeof(struct iphdr) + sizeof(struct udphdr));
  printf("message:%d\n", strlen(message));
  printf("sizeof mysocket:%d\n", sizeof(mysocket));
  printf("messlen:%d\n", messlen);
*/

  if(sendto(sockd,&packet,sizeof(packet),0x0,(struct sockaddr *)&mysocket,
            sizeof(mysocket)) != sizeof(packet))  {
    perror("sendto");
    exit(1);
  }
  
 // exit(0);
}


// in_cksum -- Checksum routine for Internet Protocol family headers (C Version)    
unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;                                                  
        u_short answer = 0;                                                    
        register u_short *w = addr;                                            
        register int nleft = len;                                              
                                                                                
        /*                                                                      
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add    
         * sequential 16 bit words to it, and at the end, fold back all the    
         * carry bits from the top 16 bits into the lower 16 bits.              
         */                                                                    
        while (nleft > 1)  {                                                    
                sum += *w++;                                                    
                nleft -= 2;                                                    
        }                                                                      
                                                                                
        /* mop up an odd byte, if necessary */                                  
        if (nleft == 1) {                                                      
                *(u_char *)(&answer) = *(u_char *)w ;                          
                sum += answer;                                                  
        }                                                                      
                                                                                
        /* add back carry outs from top 16 bits to low 16 bits */              
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */      
        sum += (sum >> 16);                     /* add carry */                
        answer = ~sum;                          /* truncate to 16 bits */      
        return(answer);                                                        
}                        

// in_gen -- IP 데이터 그램을 해더를 생성한다.
void ip_gen(char *packet,
                 unsigned char protocol,
                 struct in_addr saddr,          
                 struct in_addr daddr,
                 unsigned short length)                        
{                                                                              

#define IPVERSION 4
#define DEFAULT_TTL 60  // Just hard code the ttl in the ip header.

  struct iphdr *iphdr;

  iphdr = (struct iphdr *)packet;
  //void  *memset(void *s,int c, size_t n);
  // 일정한 문자 c로 n길이 만큼 s를 채운다.
  memset((char *)iphdr,'\0',sizeof(struct iphdr));

  iphdr->ihl = 5;                                                              
  iphdr->version = IPVERSION;                                                  

  iphdr->tot_len = htons(length);                                              
  iphdr->id = htons(getpid());                                                  
  iphdr->ttl = DEFAULT_TTL;                                                    
  iphdr->protocol = protocol;                                                  
  iphdr->check = (unsigned short)in_cksum((unsigned short *)iphdr,              
                                          sizeof(struct iphdr));                
  iphdr->saddr = saddr.s_addr;  
  iphdr->daddr = daddr.s_addr;                                                  

  return;
}


void udp_gen(char *packet,
             unsigned short sport,
             unsigned short dport,
             unsigned short length)
{
  struct udphdr *udp;

  udp = (struct udphdr *)packet;
  udp->source = htons(sport);
  udp->dest = htons(dport);
  udp->len = htons(length);
  udp->check = 0;

  return;
}

