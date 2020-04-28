/* 
Passive Mode�� �̿��� ������ FTP_Client
Command
1. PWD : ������ ���丮 ǥ��=> PWD
2. CWD : ���丮 ���� => CWD [directory]
3. LIST: ������ ���丮 ���ϸ���Ʈ ǥ�� => ls
4. RETR: ���� �ٿ�ε� => get [filename]
5. STOR: ���� ���ε� => put [filename]
6. QUIT: ���� => bye
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

/* ���� FTP Sever ��Ʈ ���� */
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

/* ���� ���ۻ�Ȳ�� ���� �ε��� : download_complete */
long download_complete;

/* �ٿ�ε峪 ���ε� �� ���� �̸�  */
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

 /* �������� �����Ѵ�. */
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

 /* FTP Server�� ���� �ּ� �� ��Ʈ ����  */
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

 	/* �ٿ�ε� ���� �� ������ */
 	while(1)
 	{
 		/* ���� ���� ���� ����  */
 		ftp_send_sockfd = socket(AF_INET, SOCK_STREAM, 0);

 		/* ���� ���� �� �ʱ� ���� ���� ����Ÿ ����  */
 		connect(ftp_send_sockfd, (struct sockaddr*)&ftp_send_addr, sizeof(struct sockaddr_in));

 		memset(temp_buff, '\0', sizeof(temp_buff));
 		read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));
 		fprintf(logfp, "\n>%s", temp_buff);
 		fflush(logfp);

 		/* FTP���� �α��� : �α��� ���н� ��� �α��� �õ� 3������ ������. ���Ĵ� �������� �������� ����  */
		// while(1)
		// { 
  		/* FTP Command : USER ������  */
  		sprintf(cmd_ctrl_buff,"USER ftpuser\n");
  		write(ftp_send_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));
 
  		memset(temp_buff, '\0', sizeof(temp_buff));
  		read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));
  		fprintf(logfp, ">%s", temp_buff);
  		fflush(logfp);

  		/* FTP Command : PASS �н�����  */
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

   			/* passive ��� ���� */
   			sprintf(cmd_ctrl_buff, "pasv\n");
   			write(ftp_send_sockfd, cmd_ctrl_buff, strlen(cmd_ctrl_buff));

   			memset(temp_buff, '\0', sizeof(temp_buff));
   			read(ftp_send_sockfd, temp_buff, sizeof(temp_buff));

  			/* 
  			passive��� ������ ���ؼ� 227����� �Բ� �����κ��� �ش� IP�� PORT�� ���޵ȴ�.
  			Ŭ���̾�Ʈ�� �ش� IP�� PORT�� �Ľ��Ͽ� �������� ������ �Ѵ�. ���� ���� ����Ÿ�� 
  			���� ����� Ŀ�ؼ����� ���� �� �۽ŵȴ�
   			*/
			if (strncmp(temp_buff, "227", 3) == 0)
  			{     
   				sprintf(file_name, "%X-60.BFR", n2);
   				fprintf(logfp, "\n> %s ...", file_name);
   				fflush(logfp);

		   		/* �������� ���� ���� retr �ٿ�ε� ���ϸ� */
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
  			����Ÿ �ٿ�ε� �������� �ڵ�
  			���� Ŭ���̾�Ʈ������ �ٿ�ε�� ���� ���ÿ� �ش� ������ �����ϴµ� �ٿ�ε� ���нô�
  			�ش� ������ �����ϴ� �ڵ�
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
�������� ���ŵǴ� ��Ʈ�� �޼����� �ƴ� ���� ����Ÿ�� ���� ���� ó��
�ѹ��� ������ ���� ����
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

/* ������ ���� ���ŵǴ� ��Ʈ�� �޼��� */
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
  passive��� ������ ���ؼ� 227����� �Բ� �����κ��� �ش� IP�� PORT�� ���޵ȴ�.
  Ŭ���̾�Ʈ�� �ش� IP�� PORT�� �Ľ��Ͽ� �������� ������ �Ѵ�. ���� ���� ����Ÿ�� 
  ���� ����� Ŀ�ؼ����� ���� �� �۽ŵȴ�
   */
  if (strncmp(ctrl_buff, "227", 3) == 0)
  {
//   fprintf(logfp, ">%s", ctrl_buff);
//   fflush(logfp);
   get_remote_port(ctrl_buff); 
  }
  /* 
  ����Ÿ �ٿ�ε� �������� �ڵ�
  ���� Ŭ���̾�Ʈ������ �ٿ�ε�� ���� ���ÿ� �ش� ������ �����ϴµ� �ٿ�ε� ���нô�
  �ش� ������ �����ϴ� �ڵ�
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
pasv���ɽ� �����κ��� 227����� �Բ� ������ IP�� PORT�� �����ִ� �� ���Լ��� �� IP�� PORT�� �Ľ��Ͽ�
�ش� ������ �����ϴ� ������ �Ѵ�
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

 
/* ���޵� ��Ʈ�� ��������Ʈ�� ���� ����Ʈ�� �ڹٲ�ä�� �´�.
  ���⿡�� �ٷ� ����ִ� ������ �Ѵ� */
 ref_number = (char*)&iport_number;

 ref_number[0] = (char)atoi(port_buff2);
 ref_number[1] = (char)atoi(port_buff1);


/* ����Ÿ�� ������ ���� ���� ���� */
 connect_addr.sin_family = AF_INET;
 connect_addr.sin_port = htons(iport_number);
 connect_addr.sin_addr.s_addr = inet_addr(ip_buff);
 memset(&(connect_addr.sin_zero), 0, 8);
 
 connect_fd = socket(AF_INET, SOCK_STREAM, 0);

 connect_result = connect(connect_fd, (struct sockaddr*)&connect_addr, sizeof(connect_addr));
 
/* ����Ÿ Ŀ�ؼ��� �� ���ɿ� ���� �����κ��� ������ �������� �ϴ� ������
  �����κ��� �۽��� ���������ϴ� �����尡 ���� ȣ��ȴ�
 ls ������ ��� ���� ������, get������ ��� ���� ������
 put������ ��� �۽� ������ ����
 */
 pthread_create(&t, NULL,recv_data_thread, (void*)connect_fd); 
}
