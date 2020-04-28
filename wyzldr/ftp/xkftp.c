/* 
Passive Mode를 이용한 간단한 FTP_Client
Command
1. PWD : 현재의 디렉토리 표시=> PWD
2. CWD : 디렉토리 변경 => CWD [directory]
3. LIST: 현재의 디렉토리 파일리스트 표시 => ls
4. RETR: 파일 다운로드 => get [filename]
5. STOR: 파일 업로드 => put [filename]
6. QUIT: 종료 => bye
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

/* 접속 FTP Sever 포트 설정 */
#define FTP_PORT 21

#define SLEEP_SEC 5
#define FILE_SEPERATED_COUNT (60 / SLEEP_SEC)

void * recv_data_thread(void* iport_number);
int get_remote_port(char * message);
void parse_filename(char * temp_buff, char * buff);
int read_wto(int sock, unsigned char *message, int buf_size, int seconds);
int connect_wto(char *serv_ip, int serv_port);

struct sockaddr_in ftp_ctrl_sock;
struct sockaddr_in ftp_recv_data_addr;

int ftp_ctrl_sockfd;
int msg_size;
int n_false = -1;
int n_true = 0;

/* 현재 전송상황에 대한 인덱스 : download_complete */
//unsigned long download_complete;

/* 다운로드나 업로드 할 파일 이름  */
char file_name[1024];

FILE *logfp;

char* host_ip;
pthread_t t;

int main(int argc, char* argv[])
{
 	pid_t cpid;
 	pthread_t recv_thread;
	int ptstatus;
 
 	char cmd_ctrl_buff[1024] = {0};
 	char temp_buff[1024] = {0};

 	int reconn_count = 0;
 	int sleep_count = 0;
 	int pasv_retry = 0;
	int ret;

	int thread_waiting = 1;
 	unsigned long n2;
 	unsigned long download_size;
 	char srcname[128];

 	int iport_number;

 if (argc < 2) {
  printf("Usage : ./xkftp [ip] {source_file} {1}\n");
  return -1;
 }

 /* 데몬으로 구동한다. */
if(argc < 3) {
 sigset(SIGCHLD, SIG_IGN);
 sigset(SIGHUP, SIG_IGN);
 if((cpid = fork()) < 0) {
         printf("Fail to create child process...\n");
         exit(0);
 } else if(cpid > 0) {
         exit(0); 
 }  

 if((logfp = fopen("xkftp.log", "a")) == NULL) {
         perror("file read error");
         exit(0);
 }
}

 if (argc > 2) {
  strcpy(srcname, argv[2]);
  n2 = strtoul(srcname, NULL, 16);
 } else {
  n2 = get_filename_to_download(0);
//  sprintf(srcname, "F51D3BC-60.bfr");
  if(n2 == 0) {
	printf("Fail to get a filename to download from db.\n");
	exit(0);
  }
  n2 = n2 + 60;
 }  

	host_ip = argv[1];
 	/* 다운로드 실패 시 재접속 */
 	while(1)
 	{
 		/* FTP Server에 대한 주소 및 포트 설정  */
 		ftp_ctrl_sock.sin_family = AF_INET;
 		ftp_ctrl_sock.sin_port = htons(FTP_PORT);
 		ftp_ctrl_sock.sin_addr.s_addr = inet_addr(argv[1]);
 		memset(&(ftp_ctrl_sock.sin_zero), 0, 8);

 		/* 서버 접속 소켓 생성  */
 		ftp_ctrl_sockfd = socket(AF_INET, SOCK_STREAM, 0);

 		/* 서버 접속 및 초기 서버 응답 데이타 수신  */
 		connect(ftp_ctrl_sockfd, (struct sockaddr*)&ftp_ctrl_sock, sizeof(struct sockaddr_in));

 		memset(temp_buff, '\0', sizeof(temp_buff));
 		read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
 		fprintf(logfp, "\n>%s", temp_buff);
 		fflush(logfp);

 		/* FTP서버 로그인 : 로그인 실패시 계속 로그인 시도 3번까지 가능함. 이후는 서버에서 파이프를 끊음  */
		// while(1)
		// { 
  		/* FTP Command : USER 유저명  */
  		sprintf(cmd_ctrl_buff,"USER ftpuser\n");
  		write(ftp_ctrl_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));
 
  		memset(temp_buff, '\0', sizeof(temp_buff));
  		read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
  		fprintf(logfp, ">%s", temp_buff);
  		fflush(logfp);

  		/* FTP Command : PASS 패스워드  */
  		sprintf(cmd_ctrl_buff, "PASS dpqxnl\n");
  		write(ftp_ctrl_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));

  		memset(temp_buff, '\0', sizeof(temp_buff));
  		read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
  		fprintf(logfp, ">%s", temp_buff);
  		fflush(logfp);
		// }

  		fprintf(logfp, "#You've logged on now.\n");
  		fflush(logfp);

		sleep_count = 0;
		reconn_count = 0;

   		/* passive 모드 설정 */
   		sprintf(cmd_ctrl_buff, "pasv\n");
   		write(ftp_ctrl_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));
		memset(temp_buff, '\0', sizeof(temp_buff));
   		read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
   		fprintf(logfp, ">%s", temp_buff);
   		fflush(logfp);

		if (strncmp(temp_buff, "230", 3) == 0)
  		{     
			memset(temp_buff, '\0', sizeof(temp_buff));
   			read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
   			fprintf(logfp, ">%s", temp_buff);
   			fflush(logfp);
		}
  		/* 
  		passive모드 설정을 위해서 227응답과 함께 서버로부터 해당 IP와 PORT가 전달된다.
  		클라이언트는 해당 IP와 PORT를 파싱하여 그쪽으로 접속을 한다. 이후 실제 데이타는 
  		현재 연결된 커넥션으로 수신 및 송신된다
   		*/
		if (strncmp(temp_buff, "227", 3) == 0)
  		{     
			iport_number = get_remote_port(temp_buff);
   			fprintf(logfp, "#227 Detect (port:%d)\n", iport_number);
   			fflush(logfp);
   			if(iport_number < 0) {
   				fprintf(logfp, "#Unknown Port\n");
	   			fflush(logfp);
				return -1;
			}
		} else return -1;

		while(1)
 		{
			sprintf(file_name, "%X-60.BFR", n2);
  			fprintf(logfp, "\n> %s ...", file_name);
   			fflush(logfp);

			/* 서버로의 명령 전달 retr 다운로드 파일명 */
   			sprintf(cmd_ctrl_buff, "retr %s\n", file_name);
   			write(ftp_ctrl_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));

			pthread_create(&t, NULL,recv_data_thread, (void*)iport_number);
			//download_size = recv_data_thread(argv[1], iport_number);

  			memset(temp_buff, '\0', sizeof(temp_buff));
   			read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
 			fprintf(logfp, "\n>%s", temp_buff);
 			fflush(logfp);

   			/* do not write log of 125 message. */
   			if (strncmp(temp_buff, "125", 3) == 0 || strncmp(temp_buff, "150", 3) == 0) {

   				memset(temp_buff, '\0', sizeof(temp_buff));
   				read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
 				fprintf(logfp, "\n>%s", temp_buff);
 				fflush(logfp);
			} 

  			/*
  			데이타 다운로드 실패응답 코드
  			실제 클라이언트에서는 다운로드시 먼저 로컬에 해당 파일을 생성하는데 다운로드 실패시는
  			해당 파일을 삭제하는 코드
   			*/

  			if (strncmp(temp_buff, "226", 3) == 0) {
   				if(rename("SWAP.BFR", file_name) == 0) {
					fprintf(logfp,"%lu bytes downloaded.\n", download_size);
 					fflush(logfp);
				} else {
					break;
				}

				// if(download_complete == 0) break;
				/* STAT_TOTAL을 PROC_FG D->N->Y 로 할 경우 활성화 */
				insert_stat_total(file_name, "D");
   				n2 = n2 + 60;
				sleep_count = 0;
				thread_waiting = 0;
  			} else if (strncmp(temp_buff, "550", 3) == 0) {
				/*
				pthread_join(&t, (void**)&ptstatus);
				if(ptstatus < 0) {
					fprintf(logfp,"#Listening socket failed.\n");
 					fflush(logfp);
				} else {
					fprintf(logfp,"#Listening socket succeed(%d).\n", ptstatus);
 					fflush(logfp);
				}	
				*/
				sleep(5);
				sleep_count++;
				if(sleep_count > FILE_SEPERATED_COUNT) {
					sleep_count = 0;
					fprintf(logfp,"nothing downloaded. reconnect...\n");
 					fflush(logfp);
				}
  			} else if (strncmp(temp_buff, "425", 3) == 0) {
				sleep(5);
				sleep_count++;
				if(sleep_count > FILE_SEPERATED_COUNT) {
					sleep_count = 0;
					fprintf(logfp,"nothing downloaded. reconnect...\n");
 					fflush(logfp);
					break;
				}
			} else {
				fprintf(logfp,"terminated by %.*s\n", 3, temp_buff);
 				fflush(logfp);
				break;
			}

  			/* passive 모드 설정 */
	 		sprintf(cmd_ctrl_buff, "pasv\n");
  			write(ftp_ctrl_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));
			memset(temp_buff, '\0', sizeof(temp_buff));
   			read(ftp_ctrl_sockfd, temp_buff, sizeof(temp_buff));
   			fprintf(logfp, ">%s", temp_buff);
   			fflush(logfp);

			if (strncmp(temp_buff, "227", 3) == 0)
	  		{     
				iport_number = get_remote_port(temp_buff);
   				fprintf(logfp, "#227 Detect (port:%d)\n", iport_number);
   				fflush(logfp);
   				if(iport_number < 0) {
   					fprintf(logfp, "#Unknown Port\n");
	   				fflush(logfp);
					break;
				}
			} else break;
			/* reconnection for IIS */
			//reconn_count++;
			//if(reconn_count > 20) break;
			// break;
			//  if(argc > 3) exit(1);
 		}

		/* reconnection */
  		shutdown(ftp_ctrl_sockfd, 2);
  		close(ftp_ctrl_sockfd);
		//pthread_join(t,NULL);
		ret = execlp("xkftp","xkftp",argv[1], NULL);
		if(ret == -1) {
			fprintf(logfp,"[EXECL] reconnect failed\n");
 			fflush(logfp);
			exit(1);
		}
 	}
 return 0;
}

/* 
서버에서 수신되는 컨트롤 메세지가 아닌 실제 데이타에 대한 수신 처리
한번의 연결후 소켓 종료
 */
void * recv_data_thread(void* iport_number)
{
	int fd;

 	char data_buff[4096] = {0};
 	unsigned long data_size;
 	unsigned long downloaded;
 	unsigned long download_complete;
 
	struct sockaddr_in connect_addr;
	int connect_fd; 
	int connect_result;

/* 데이타를 전달을 위한 서버 접속 */
/*
	connect_addr.sin_family = AF_INET;
	connect_addr.sin_port = htons((int)iport_number);
	connect_addr.sin_addr.s_addr = inet_addr(host_ip);
	memset(&(connect_addr.sin_zero), 0, 8);
	connect_fd = socket(AF_INET, SOCK_STREAM, 0);
*/

//	connect_result = connect(connect_fd, (struct sockaddr*)&connect_addr, sizeof(connect_addr));
  	fprintf(logfp, "CONN");
  	fflush(logfp);

	connect_fd = connect_wto(host_ip, (int)iport_number);

//	DO NOT MAKE THIS LINE COMMENTS
	if(connect_fd < 0) return (void*)n_true;

  	fprintf(logfp, "ECT");
  	fflush(logfp);

//	while(1) {
  		downloaded = 0;
	 	while(1) {   
//  			fprintf(logfp, "!");
//  			fflush(logfp);
			memset(data_buff, '\0', sizeof(data_buff));
			// data_size = read_wto((int)connect_fd, data_buff, sizeof(data_buff),1);
			data_size = read((int)connect_fd, data_buff, sizeof(data_buff));
			if (data_size == 0)
			{
				break;
			} else if(data_size > 0) {
				if(downloaded == 0) fd = open("SWAP.BFR", O_WRONLY|O_CREAT,0644);
				write(fd, data_buff, data_size);
				downloaded += data_size;
			} else break;
 		}
 		if(downloaded > 0) close(fd);
//	}
	close(connect_fd);
	return (void*)n_true;
}

/* 
pasv명령시 서버로부터 227응답과 함께 서버의 IP와 PORT를 보내주는 데 이함수는 이 IP와 PORT를 파싱하여
해당 서버로 접속하는 역할을 한다
 */
int get_remote_port(char * message)
{
 int index;
 int parse_start = 0;
 
 char ip_buff[512] = {0};
 char port_buff1[10] = {0};
 char port_buff2[10] = {0};
 
 char cport_number[2];
 int iport_number;

 char * ref_number;

 int comma_count = 0;
 int buff_count = 0;

 for (index = 0; index < strlen(message); index++)
 {
  if (message[index] == '(')
  {
   parse_start = 1;
   continue;
  }
  else if (message[index] == ')')
   break;
   
  if (parse_start == 1)/* addr process */
  {
   if (message[index] == ',')
   { 
    comma_count++;
    if (comma_count == 4)
    {
     buff_count = 0;
     parse_start = 2;
     continue;
    }
    else
    {
     ip_buff[buff_count] = '.';
     buff_count++;
    }
   }
   else
   {
    ip_buff[buff_count] = message[index]; 
    buff_count++;
   } 
  }
  if (parse_start == 2)/* port process */
  {
   if (message[index] == ',')
   {
    
    comma_count++;
    buff_count = 0;
   }
   else
   {
    if (comma_count == 5)
    {
     port_buff2[buff_count] = message[index];
     buff_count++;
    }
    else
    {
     port_buff1[buff_count] = message[index];
     buff_count++;
    }
   }
  }
 }

 
/* 전달된 포트는 상위바이트와 하위 바이트가 뒤바뀐채로 온다.
  여기에서 바로 잡아주는 역할을 한다 */
// ref_number = (char*)&iport_number;

// ref_number[0] = (char)atoi(port_buff2);
// ref_number[1] = (char)atoi(port_buff1);
	iport_number = atoi(port_buff1) * 256 + atoi(port_buff2);

	if(iport_number > 0 && iport_number < 65535) return iport_number;
	else return -1;
}

int read_wto(int sock, unsigned char *message, int buf_size, int seconds)
{
  struct timeval tv;
  fd_set selectfds, readfds, exceptfds;
  int nread;

  tv.tv_sec = seconds;          /* seconds to wait */
  tv.tv_usec = 0;

  FD_ZERO(&selectfds);
  FD_SET(sock, &selectfds);
  readfds = selectfds;
  exceptfds = selectfds;

  if (select(sock+1, &readfds, (fd_set *)NULL, &exceptfds, &tv) <= 0)
    return -1;
  else if (FD_ISSET(sock, &exceptfds))
    return -1;

  while (1) {
    nread = read(sock, message, buf_size);
    if (nread < 0) {
     if (errno == EINTR)
       continue;
     if (errno == EAGAIN) {
       readfds   = selectfds;
       exceptfds = selectfds;

       if (select(sock+1, &readfds, (fd_set *)0, &exceptfds, &tv) <= 0)
         return -1;
       else if (FD_ISSET(sock, &exceptfds))
         return -1;
       continue;
     }     
    } else if (nread >= 0)
      break;
  }
  
  return nread;
}

int connect_wto(char *serv_ip, int serv_port)
{
    int sock;
    extern int errno;
    struct sockaddr_in serv_addr;

    int res;
    long arg;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;

    sock=socket(PF_INET, SOCK_STREAM, 0);
    if(sock==-1) /* errno -1 : socket creation error */
        return -1;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(serv_ip);
    serv_addr.sin_port=htons(serv_port);

    
    /* Set non-blocking  */
    if((arg = fcntl(sock, F_GETFL, NULL)) < 0) {
        return -1;
    }
    
    arg |= O_NONBLOCK;
    if(fcntl(sock, F_SETFL, arg) < 0) {
        return -1;
    }
    
    /* trying to connect with timeout */
    res = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    
    if (res < 0) { 
         if (errno == EINPROGRESS) {
             do { 
                  tv.tv_sec = 4;/* seconds to wait */
                  tv.tv_usec = 0; 
                  FD_ZERO(&myset); 
                  FD_SET(sock, &myset); 
                  res = select(sock+1, &myset, &myset, NULL, &tv);
                  if (res < 0 && errno != EINTR) {
                     return -1;
                     } 
                  else if (res > 0) { 
                     /* Socket selected for write */
                     lon = sizeof(int); 
                     if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) {
                         return -1;
                     } 
                     /* Check the value returned... */
                     if (valopt) { 
                         return -1;
                     }
                     break;
                  }
                  else {
                     return -1;
                  }
             } while (1);
         }
         else {
             return -1;
         }
    }

    /* Set to blocking mode again... */
    if( (arg = fcntl(sock, F_GETFL, NULL)) < 0) {
        return -1;
    }
    arg &= (~O_NONBLOCK);
    if( fcntl(sock, F_SETFL, arg) < 0) {
        return -1;
    }

    return sock;
}
