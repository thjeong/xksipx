#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h> 

#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <netinet/ip.h> /* used for ip structure */
#include <netinet/udp.h> /* used for udp structure */

#include <netdb.h> /* used for gethostbyname */
#include <inttypes.h>
#include <string.h>

#include <pthread.h>

#define MYPORT 5080/* the port users will be connecting to */
#define BUFSIZE 4096

unsigned short in_cksum(unsigned short *addr, int len);
void * send_message(void *arg);
void * recv_message(void *arg);

unsigned char message[BUFSIZE];

int main(int argc, char **argv){

    int sock = 0;
	pthread_t snd_thread, rcv_thread;
	void * thread_result;

	pthread_create(&snd_thread, NULL, send_message, (void*)sock);
	pthread_create(&rcv_thread, NULL, recv_message, (void*)sock);
	pthread_join(snd_thread, &thread_result);
	pthread_join(rcv_thread, &thread_result);
	close(sock);
	return 0;
}

void * recv_message(void *arg) /* 메시지 수신 쓰레드 실행 함수 */
{
    int sockfd;
    struct sockaddr_in my_addr;/* my address information */
    struct sockaddr_in their_addr; /* connector's address information */
    int addr_len, numbytes;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    my_addr.sin_family = AF_INET; /* host byte order */
    my_addr.sin_port = htons(MYPORT); /* short, network byte order */
    my_addr.sin_addr.s_addr = INADDR_ANY; /* auto-fill with my IP */
    bzero(&(my_addr.sin_zero), 8);/* zero the rest of the struct */

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) \
               == -1) {
        perror("bind");
        exit(1);
    }

    addr_len = sizeof(struct sockaddr);

    while(1) {
    if ((numbytes=recvfrom(sockfd, message, BUFSIZE, 0, \
                       (struct sockaddr *)&their_addr, &addr_len)) == -1) {
        perror("recvfrom");
        exit(1);
    }

    printf("========================================\n");
    printf("got packet from %s\n",inet_ntoa(their_addr.sin_addr));
    printf("packet is %d bytes long\n",numbytes);
    message[numbytes] = '\0';
    printf("packet contains ========================\n");
    printf("\n%s",message);
    printf("========================================\n");

    }

    close(sockfd);
}

void * send_message(void *arg) /* 메시지 전송 쓰레드 실행 함수 */
{ 
    /* for UAC */
    int port = MYPORT;
    int sock; 
    int bytes; 
    char dgram[BUFSIZE]; /* Datagram buf */
    FILE *fp;

    struct hostent *he; 
    struct sockaddr_in host; 
    struct ip *iph = (struct ip*)dgram; 
    struct udphdr *udp = (struct udphdr*)dgram + sizeof(struct ip); 
    char *buf = (char*)udp + sizeof(struct udphdr);

    char command[128];
    char filename[]="msg1.txt";
    char hostname[]="203.254.210.1";

    int i;
    int buf_size;
    char que[BUFSIZE];
    int que_size;
    
    /* end of init */
     
    while(1) {

    printf(">");
    fgets(command, BUFSIZE, stdin);
    if(command[0] == 'q') exit(0);
    { filename[3] = command[0]; /* start of if */

    if((he = gethostbyname(hostname)) == NULL) 
    { 
        perror("Gethostbyname error!n"); 
        exit(1); 
    } 
     
    if((sock = socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) == -1) 
    { 
        perror("Socket"); 
        exit(1); 
    } 
     
    memset(dgram, 0, BUFSIZE);

    fp = fopen(filename, "r");
    que_size = fread(que, 1, 2048, fp);
    que[que_size] = 0;

    buf_size = 0;
    for(i = 0; i < que_size; i++) {
        if(que[i] == '\n') {
            if(que[i - 1] != '\r') {
                buf[buf_size++] = '\r';
            } else {
                /* do nothing */
            }
        }
    buf[buf_size++] = que[i];
    }
    fclose(fp);


    { 
        /* UDP structure-------8 bytes in all */
        udp->uh_sport = htons(port); /* source port */
        udp->uh_dport = htons(port);
        udp->uh_ulen = htons(4 + sizeof(udp) + buf_size);
        udp->uh_sum = 0;
    } 
     
    /* Sockaddr_in structure */
    host.sin_family = AF_INET; 
    host.sin_port = htons(port); 
    host.sin_addr.s_addr = inet_addr(hostname);

    /* Send the datagram over to the intended host */
    if((sendto(sock, udp, 4 + sizeof(udp) + buf_size, 0, (struct sockaddr *)&host, sizeof(host))) == -1)
    { 
        perror("Sendto error"); 
        exit(1); 
    } else printf("Successfully send\n");
    
    } /* end of if */

    }   /* end of while */  
} 

unsigned short in_cksum(unsigned short *addr,int len)
{
    register int sum = 0; 
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;  

    /*
     *  * Our algorithm is simple, using a 32 bit accumulator (sum), we add 
     *   * sequential 16 bit words to it, and at the end, fold back all the
     *    * carry bits from the top 16 bits into the lower 16 bits. 
     *     */ 
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
    sum = (sum >> 16) + (sum & 0xffff);/* add hi 16 to low 16 */  
    sum += (sum >> 16); /* add carry */  
    answer = ~sum; /* truncate to 16 bits */  
    return(answer);  
}
