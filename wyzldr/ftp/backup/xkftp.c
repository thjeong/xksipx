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

/* 접속 FTP Sever 포트 설정 */
#define FTP_PORT 21

#define SLEEP_SEC 5
#define FILE_SEPERATED_COUNT (60 / SLEEP_SEC)

void* send_data_thread(void* sockfd);
void* recv_ctrl_thread(void* sockfd);
void* recv_data_thread(void* sockfd);
void get_remote_port(char * message);
void parse_filename(char * temp_buff, char * buff);

struct sockaddr_in ftp_send_addr;
struct sockaddr_in ftp_recv_data_addr;

int ftp_send_sockfd;
int msg_size;

/* 현재 전송상황에 대한 인덱스 : download_complete */
long download_complete;

/* 다운로드나 업로드 할 파일 이름  */
char file_name[1024];

FILE *logfp;


int main(int argc, char* argv[])
{
 pid_t cpid;
 pthread_t recv_thread;
 
 char cmd_ctrl_buff[1024] = {0};
 char temp_buff[1024] = {0};

 int sleep_count = 0;
 int pasv_retry = 0;

 unsigned long n2;
 char srcname[128];

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

 if((logfp = fopen("xkftp.log", "w")) == NULL) {
         perror("file read error");
         exit(0);
 }
}

 /* FTP Server에 대한 주소 및 포트 설정  */
 ftp_send_addr.sin_family = AF_INET;
 ftp_send_addr.sin_port = htons(FTP_PORT);
 ftp_send_addr.sin_addr.s_addr = inet_addr(argv[1]);
 memset(&(ftp_send_addr.sin_zero), 0, 8);

 if (argc > 2) {
  strcpy(srcname, argv[2]);
  n2 = strtoul(srcname, NULL, 16);
 } else {
  n2 = get_filename_to_download(0);
//  sprintf(srcname, "F51D3BC-60.bfr");
  if(n2 < 0) {
	printf("Fail to get a filename to download from db.\n");
	exit(0);
  }
  n2 = n2 + 60;
 }  

 	/* 다운로드 실패 시 재접속 */
 	while(1)
 	{
 		/* 서버 접속 소켓 생성  */
 		ftp_send_sockfd = socket(AF_INET, SOCK_STREAM, 0);

 		/* 서버 접속 및 초기 서버 응답 데이타 수신  */
 		connect(ftp_send_sockfd, (struct sockaddr*)&ftp_send_addr, sizeof(struct sockaddr_in));

 		memset(temp_buff, '\0', sizeof(temp_buff));
 		read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));
 		fprintf(logfp, "\n>%s", temp_buff);
 		fflush(logfp);

 		/* FTP서버 로그인 : 로그인 실패시 계속 로그인 시도 3번까지 가능함. 이후는 서버에서 파이프를 끊음  */
		// while(1)
		// { 
  		/* FTP Command : USER 유저명  */
  		sprintf(cmd_ctrl_buff,"USER ftpuser\n");
  		write(ftp_send_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));
 
  		memset(temp_buff, '\0', sizeof(temp_buff));
  		read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));
  		fprintf(logfp, ">%s", temp_buff);
  		fflush(logfp);

  		/* FTP Command : PASS 패스워드  */
  		sprintf(cmd_ctrl_buff, "PASS dpqxnl\n");
  		write(ftp_send_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));

  		memset(temp_buff, '\0', sizeof(temp_buff));
  		read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));
  		fprintf(logfp, ">%s", temp_buff);
  		fflush(logfp);
		// }


		while(1)
 		{
   			download_complete = 0;

   			/* passive 모드 설정 */
   			sprintf(cmd_ctrl_buff, "pasv\n");
   			write(ftp_send_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));

   			memset(temp_buff, '\0', sizeof(temp_buff));
   			read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));

  			/* 
  			passive모드 설정을 위해서 227응답과 함께 서버로부터 해당 IP와 PORT가 전달된다.
  			클라이언트는 해당 IP와 PORT를 파싱하여 그쪽으로 접속을 한다. 이후 실제 데이타는 
  			현재 연결된 커넥션으로 수신 및 송신된다
   			*/
			if (strncmp(temp_buff, "227", 3) == 0)
  			{     
   				sprintf(file_name, "%X-60.BFR", n2);
   				fprintf(logfp, "\n> %s ...", file_name);
   				fflush(logfp);

		   		/* 서버로의 명령 전달 retr 다운로드 파일명 */
   				sprintf(cmd_ctrl_buff, "retr %s\n", file_name);
   				write(ftp_send_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));

   				get_remote_port(temp_buff);

   				memset(temp_buff, '\0', sizeof(temp_buff));
   				read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));

/*
   				if (strncmp(temp_buff, "125", 3) != 0) {
   					fprintf(logfp, ">%s", temp_buff);
   					fflush(logfp);
   				}
*/
			} else {
   				fprintf(logfp, ">%s", temp_buff);
   				fflush(logfp);
				sleep(5);
				pasv_retry++;
				if(pasv_retry > 1) {
					pasv_retry = 0;
					break;
				} else continue;
			} 

   			/* do not write log of 125 message. */
   			if (strncmp(temp_buff, "125", 3) == 0) {
  				memset(temp_buff, '\0', sizeof(temp_buff));
  				read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));
			}

  			/*    
  			데이타 다운로드 실패응답 코드
  			실제 클라이언트에서는 다운로드시 먼저 로컬에 해당 파일을 생성하는데 다운로드 실패시는
  			해당 파일을 삭제하는 코드
   			*/
  			if (strncmp(temp_buff, "226", 3) == 0) {
   				rename("SWAP.BFR", file_name);
				fprintf(logfp,"%ld bytes downloaded.\n", download_complete);
 				fflush(logfp);
				//	insert_stat_total(file_name, "D");
   				n2 = n2 + 60;
				sleep_count = 0;
  			} else if (strncmp(temp_buff, "550", 3) == 0) {
				sleep(5);
				sleep_count++;
				if(sleep_count > FILE_SEPERATED_COUNT) {
					sleep_count = 0;
   					// download_complete = -99999;
					break;
				} else continue;
  			}

			//  if(argc > 3) exit(1);
 		}

		/* reconnection */
		fprintf(logfp,"nothing downloaded. reconnect...\n");
 		fflush(logfp);
  		close(ftp_send_sockfd);
		sleep(5);
 	}
 return 0;
}

/* 
서버에서 수신되는 컨트롤 메세지가 아닌 실제 데이타에 대한 수신 처리
한번의 연결후 소켓 종료
 */
void * recv_data_thread(void* sockfd)
{
 int fd;

 char data_buff[4096] = {0};
 int data_size;
 long downloaded;
 
  fd = open("SWAP.BFR", O_WRONLY|O_CREAT,0644);
  downloaded = 0;

 while(1)
 {   
  memset(data_buff, '\0', sizeof(data_buff));
  data_size = read((int)sockfd, data_buff, sizeof(data_buff));
  if (data_size == 0)
  {
    break;
  }
  else
  {
    write(fd, data_buff, data_size);
    downloaded += data_size;
  }

 }
 
 close((int)sockfd);
 close(fd);

 download_complete = downloaded;
}

/* 서버로 부터 수신되는 컨트롤 메세지 */
void * recv_ctrl_thread(void* sockfd)
{
 char ctrl_buff[1024] = {0};
 int msg_size;
 int temp_port;
 while(1)
 {
  memset(ctrl_buff, '\0', sizeof(ctrl_buff));
  msg_size = read((int)sockfd, ctrl_buff, sizeof(ctrl_buff));
   
  if (msg_size <= 0)
   continue;
  /* 
  passive모드 설정을 위해서 227응답과 함께 서버로부터 해당 IP와 PORT가 전달된다.
  클라이언트는 해당 IP와 PORT를 파싱하여 그쪽으로 접속을 한다. 이후 실제 데이타는 
  현재 연결된 커넥션으로 수신 및 송신된다
   */
  if (strncmp(ctrl_buff, "227", 3) == 0)
  {
//   fprintf(logfp, ">%s", ctrl_buff);
//   fflush(logfp);
   get_remote_port(ctrl_buff); 
  }
  /* 
  데이타 다운로드 실패응답 코드
  실제 클라이언트에서는 다운로드시 먼저 로컬에 해당 파일을 생성하는데 다운로드 실패시는
  해당 파일을 삭제하는 코드
   */
  else if (strncmp(ctrl_buff, "550", 3) == 0) {
   fprintf(logfp, " <550> ");
   fflush(logfp);
//   fprintf(logfp, ">%s", ctrl_buff);
//   fflush(logfp);
   memset(ctrl_buff, '\0', sizeof(ctrl_buff));
   sprintf(ctrl_buff, "rm -f SWAP.BFR", file_name);
   system(ctrl_buff);
   download_complete = -1;
  } else if (strncmp(ctrl_buff, "226", 3) == 0) {
   rename("SWAP.BFR", file_name);
  } else {
   fprintf(logfp, "S>%s\n", ctrl_buff);
   fflush(logfp);
  }
 }
 close((int)sockfd);
 fprintf(logfp, "Exit Thread");
 fflush(logfp);
 exit(0);
}

/* 
pasv명령시 서버로부터 227응답과 함께 서버의 IP와 PORT를 보내주는 데 이함수는 이 IP와 PORT를 파싱하여
해당 서버로 접속하는 역할을 한다
 */
void get_remote_port(char * message)
{

 pthread_t t;
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


 struct sockaddr_in connect_addr;
 int connect_fd; 
 int connect_result;

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
 ref_number = (char*)&iport_number;

 ref_number[0] = (char)atoi(port_buff2);
 ref_number[1] = (char)atoi(port_buff1);


/* 데이타를 전달을 위한 서버 접속 */
 connect_addr.sin_family = AF_INET;
 connect_addr.sin_port = htons(iport_number);
 connect_addr.sin_addr.s_addr = inet_addr(ip_buff);
 memset(&(connect_addr.sin_zero), 0, 8);
 
 connect_fd = socket(AF_INET, SOCK_STREAM, 0);

 connect_result = connect(connect_fd, (struct sockaddr*)&connect_addr, sizeof(connect_addr));
 
/* 데이타 커넥션후 각 명령에 따라 서버로부터 수신을 전용으로 하는 쓰레드
  서버로부터 송신을 전용으로하는 쓰레드가 따로 호출된다
 ls 명령의 경우 수신 쓰레드, get명령의 경우 수신 쓰레더
 put명령의 경우 송신 쓰레드 생성
 */
 pthread_create(&t, NULL,recv_data_thread, (void*)connect_fd); 
}

