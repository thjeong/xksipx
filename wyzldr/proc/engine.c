/*******************************************************************************
 *  Copyrights(c) 2007~ Modern Limes Technology(MLT) Co., Ltd. Seoul Korea
 *  
 * All rights are reserved. This is unpublished proprietary source code of MLT.
 * The copyright notice does not evidence any actual publication of such source
 * code.
 * 
 *      Subject : SIP Packet's Parser Main Module
 *      Authors : Steven, Oh. MLT
 *      Date : FEB 10, 2007 
 * 
 *      Overview
 * 
 * $Log$
 * 
 ******************************************************************************/

/*******************************************************************************
 * IMPORTED SYSTEM HEADER FILES
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>

#include "sip_attrs.h"
#include "types.h"


/*******************************************************************************
 * PRIVATE DEFINITIONS
 ******************************************************************************/
static const char network_instruments_magic[] = {"ObserverPktBufferVersion=09.00"};
static const int true_magic_length = 17;
static const guint32 observer_packet_magic = 0x88888888;
static const char reg_str[] = {"REGISTER"};
static const char opt_str[] = {"OPTIONS"};
static const char ping_str[] = {"PING"};

/*******************************************************************************
 * PRIVATE TYPE DEFINITIONS
 ******************************************************************************/
#define WRITE_BLOCK_SIZE 4096
#define SBUFF_SIZE  16384 
#define RETRY_LIMIT_VALUE 300

/*******************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 ******************************************************************************/
int fileload(sip_attrs_t *rcvdsip);


/*******************************************************************************
 * INTERFACE VARIABLES
 ******************************************************************************/

/*******************************************************************************
 * PUBLIC VARIABLES
 ******************************************************************************/
unsigned long packetno;             /* packet number */
char datestr[32];         /* packet create date */
char ipsrc[20];           /* SIP source IP-Address */
char ipdst[20];           /* SIP destination IP-Address */
unsigned short srcport, dstport;  /* SIP source, destination port */

char srcname[256];        /* SIP source file name */
char expire_str[12];      /* SIP expire-part string */
char reginame[64];        /* after work, saved REGISTER DATA */
char callname[64];        /* after work, saved CALL DATA */
char statname[64];        /* after work, saved CALL DATA */
char last_reginame[64];        /* after work, saved REGISTER DATA */
char last_callname[64];        /* after work, saved CALL DATA */
char last_statname[64];        /* after work, saved CALL DATA */
//int hour, min, sec;       /* SIP packet file's create date */

static time_t seconds1970to2000;  /* each SIP packet create time */
struct tm *file_time;

capture_file_header file_header;
packet_entry_header packet_header;

FILE *callfp, *regifp, *statfp, *srcfp, *logfp;  /* each file pointer */
char cal_wbuf[WRITE_BLOCK_SIZE], reg_wbuf[WRITE_BLOCK_SIZE];
int cal_ofs, reg_ofs;

phone_number_pool *phone_stat[6][8000000];
int phone_stat_totalcnt[6];
statistics *host_stat[6][512];	/* per 1/6 minute, 512 entries for each SRC,DST,FONNO */
int host_stat_totalcnt;

/*******************************************************************************
 * PRIVATE VARIABLES
 ******************************************************************************/


/*******************************************************************************
 * IMPLEMENTATION OF INTERFACE FUNCTIONS
 ******************************************************************************/

/*******************************************************************************
 * NAME : parser's main function
 * ARGUMENT : int argc, char** argv
 * RETURNS/SIDE-EFFECTS : int
 ******************************************************************************/
int main(int argc, char** argv)
{
	int result;
	int t, i, j, k;
	sip_attrs_t *rcvdsip;
        unsigned long n2;
	pid_t cpid;
	char srcfullname[256];        /* SIP source file name */
	float reg_succ_rate, inv_succ_rate;
	time_t show_time;

	/* Observer's date setting from 1970's */
	struct tm midnight_2000_01_01;

	/* retry count for trying to read file */
	int retry = 0;

	/* retry accelation count */
	int retry_limit = RETRY_LIMIT_VALUE;	/* default is 120 secs */

	cal_ofs = 0;
	reg_ofs = 0;
	
	midnight_2000_01_01.tm_year = 2000 - 1900;
	midnight_2000_01_01.tm_mon = 0;
	midnight_2000_01_01.tm_mday = 1;
	midnight_2000_01_01.tm_hour = 0;
	midnight_2000_01_01.tm_min = 0;
	midnight_2000_01_01.tm_sec = 0;
	midnight_2000_01_01.tm_isdst = -1;
	seconds1970to2000 = mktime(&midnight_2000_01_01);

	for(i = 0; i < 6; i++) {
		for(j = 0; j < 512; j++) {
			host_stat[i][j] = malloc(sizeof(statistics));
		}
	}

	if (argc > 3) {
		printf("Usage : ./wyzldr {source_file}\n");
		return -1;
	}

	if (argc > 1) {
		strcpy(srcname, argv[1]);
		if(strlen(srcname) > 10) {
			printf("[ERROR] Invalid file name for processing.\n");
			return -1;
		}
        	n2 = strtoul(srcname, NULL, 16);
	} else {
		n2 = get_filename_to_parse(0);
		if(n2 < 0) {
			printf("[ERROR] There is not a file to process in the Database.\n");
			return -1;
		} else n2 += 60;	// last + 60
	}

        /* 데몬으로 구동한다. */
// FOR DEBUG
if(argc < 3) {
        sigset(SIGCHLD, SIG_IGN);
        sigset(SIGHUP, SIG_IGN);
        if((cpid = fork()) < 0) {
                printf("Fail to create child process...\n");
                exit(0);
        } else if(cpid > 0) {
                exit(0);
        }

}
	if((logfp = fopen("wyzldr.log", "w")) == NULL) {
		perror("file read error");
		exit(0);
	}

        /* memory allocation */
       	rcvdsip = (sip_attrs_t*)malloc(sizeof(sip_attrs_t));
       	rcvdsip->uri = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
       	rcvdsip->from = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
       	rcvdsip->to = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
       	rcvdsip->contact = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
       	rcvdsip->route = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
       	rcvdsip->via = (via_attrs_t*)malloc(sizeof(via_attrs_t));
       	rcvdsip->credential = (digest_attrs_t*)malloc(sizeof(digest_attrs_t));
	// 20090302
       	rcvdsip->sdp = (sdp_attrs_t*)malloc(sizeof(sdp_attrs_t));

	while(1) {

//		fprintf(logfp, "[n2:%ld]", n2);
//		fflush(logfp);
		
		if(n2 > 0) {
		// if(retry == 0) {
			sprintf(srcname, "%X-60.BFR", n2);
			sprintf(reginame, "%X.REGI.SWAP", n2);
			sprintf(callname, "%X.CALL.SWAP", n2);
			sprintf(statname, "%X.STAT.SWAP", n2);
			sprintf(last_reginame, "%X.REGI", n2);
			sprintf(last_callname, "%X.CALL", n2);
			sprintf(last_statname, "%X.STAT", n2);

//			fprintf(logfp, "> Read File : %s ", srcname);
//			fflush(logfp);
		// }
		} else {
			sleep(5);
			n2 = get_filename_to_parse(0) + 60;	// last + 60sec
			continue;
		}

		sprintf(srcfullname, "/data2/GigaStor/%s", srcname);
		if((srcfp = fopen(srcfullname, "r")) == NULL) {
			// perror("file read error");
			fprintf(logfp, ".");
			fflush(logfp);
			sleep(5);
			continue;
		} else if((regifp = fopen(reginame, "w")) == NULL) {
			perror("regi file read error");
			break;
		} else if((callfp = fopen(callname, "w")) == NULL) {
			perror("call file read error");
			break;
		} else if((statfp = fopen(statname, "w")) == NULL) {
			perror("stat file read error");
			break;
		} else {
			time(&show_time);
			fprintf(logfp, "\nStart : %s> Parsing File : %s\n", ctime(&show_time), srcname);
			fflush(logfp);
			retry = 0;

			/* get host list for statistic of hosts */
			host_stat_totalcnt = get_host_list();

			/* file loading and processing */
			if(result = fileload(rcvdsip) > 0) {
				/* fflush last writing buffer */
				if(reg_ofs > 0) {
					fprintf(regifp, "%s", reg_wbuf);
					fflush(regifp);
				}
				if(cal_ofs > 0) {
					fprintf(callfp, "%s", cal_wbuf);
					fflush(callfp);
				}

				for(i = 0; i < 6; i++) {
					for(j = 0; j < host_stat_totalcnt; j++) {
						fprintf(statfp, "%04d%02d%02d%02d%02d%d`%s`%s`%u`%u`%u`%u`%u`%u`%u`%u`%u\n", file_time->tm_year+1900, file_time->tm_mon+1, file_time->tm_mday, file_time->tm_hour, file_time->tm_min, i, host_stat[i][j]->src_ip, host_stat[i][j]->dst_ip, host_stat[i][j]->reg[0][0][0], host_stat[i][j]->reg[2][0][0], host_stat[i][j]->reg[4][0][1], host_stat[i][j]->reg[4][0][4], host_stat[i][j]->inv[0][0][0], host_stat[i][j]->inv[2][0][0], host_stat[i][j]->inv[4][8][7], host_stat[i][j]->inv[5][0][0], host_stat[i][j]->inv[5][0][3]);
					}
				}

				fflush(statfp);
				
				/* close fp */
        			fclose(callfp);
        			fclose(regifp);
        			fclose(statfp);
        			fclose(srcfp);
				/* rename file for sqlldr */
				rename(reginame, last_reginame);
				rename(callname, last_callname);
				rename(statname, last_statname);

				/* insert result to stat_total */
// FOR DEBUG
				if(insert_stat_total(srcname, "P") > 0) {
					n2 += 60;
				} else {
					fprintf(logfp, "SQL> Stat_total Insert error\n");
					fflush(logfp);
					break;
				}
				time(&show_time);
				fprintf(logfp, "Completed : %s", ctime(&show_time));
				fflush(logfp);
			} else {
				fprintf(logfp, "PARSER> Parsing error\n");
				fflush(logfp);
				break;
			}
		}
		if(argc > 1) break;
	}


	free(rcvdsip->uri);
	free(rcvdsip->from);
	free(rcvdsip->to);
	free(rcvdsip->contact);
	free(rcvdsip->route);
	free(rcvdsip->via);
	free(rcvdsip->credential);
	free(rcvdsip->sdp);
	free(rcvdsip);

	fclose(logfp);

	return result;
}

/*******************************************************************************
 * NAME : management arrival time
 * ARGUMENT : void
 * RETURNS/SIDE-EFFECTS : guint64, observer_time*
 ******************************************************************************/
gboolean fill_time_struct(guint64 ns_since2000, observer_time* time_conversion)
{
    time_conversion->seconds_from_1970 = (time_t) (seconds1970to2000 + ns_since2000/1000000000);
    time_conversion->nseconds = (guint64)(ns_since2000%1000000000);
    return 0;
}

/*******************************************************************************
 * NAME : display the last data from structure
 * ARGUMENT : static void
 * RETURNS/SIDE-EFFECTS : FILE *, int, unsigned char, int, int
 ******************************************************************************/
static void
write_parsed_context(unsigned long long f_offset, int payload_len, sip_attrs_t *rcvdsip)
{
	int rcvdsip_expires;
	const char *rcvdsip_mthdstat;
	int rcvdsip_mthdstatlen;

	// if(rcvdsip->expires > rcvdsip->contact_expires) rcvdsip_expires = rcvdsip->expires;
	// else rcvdsip_expires = rcvdsip->contact_expires;
	rcvdsip_expires = rcvdsip->expires > rcvdsip->contact_expires ? rcvdsip->expires : rcvdsip->contact_expires;
	// printf("<<%d - %d = %d>>\n", rcvdsip->expires,rcvdsip->contact_expires,rcvdsip_expires); 
	if(rcvdsip->methodlen > 0) {
		rcvdsip_mthdstat = rcvdsip->method;
		rcvdsip_mthdstatlen = rcvdsip->methodlen;
	} else if(rcvdsip->statuslen > 0) {
		rcvdsip_mthdstat = rcvdsip->status;
		rcvdsip_mthdstatlen = rcvdsip->statuslen + rcvdsip->status_phraselen + 1;
	} else {
//		printf("[ELSE]");
//		fflush(stdout);
		return;
	}

// FOR DEBUG
/*
	if(rcvdsip->cause > 0 && rcvdsip->cause < 255) {
                printf("<%d>==================================\n", packetno);
                printf("Status-Code : %.*s\n",rcvdsip->statuslen, rcvdsip->status);
                printf("Status-Phrase : %.*s\n",rcvdsip->status_phraselen, rcvdsip->status_phrase);
                printf("Method : %.*s\n",rcvdsip->methodlen, rcvdsip->method);
                printf("From user: %.*s\n",rcvdsip->from->userlen, rcvdsip->from->user);
                printf("From host: %.*s\n",rcvdsip->from->hostlen, rcvdsip->from->host);
                printf("To user: %.*s\n",rcvdsip->to->userlen, rcvdsip->to->user);
                printf("To host: %.*s\n",rcvdsip->to->hostlen, rcvdsip->to->host);
                printf("CallID : %.*s\n",rcvdsip->callidlen, rcvdsip->callid);
		printf("Cseq : %lu\n",rcvdsip->cseq);
                printf("Cseq Method : %.*s\n",rcvdsip->cseq_methodlen, rcvdsip->cseq_method);
                printf("UserAgt : %.*s\n",rcvdsip->useragtlen, rcvdsip->useragt);
		printf("Real Expires : %d\n", rcvdsip_expires);
		printf("Reason : %.*s\n", rcvdsip->reasonlen, rcvdsip->reason);
		printf("Q.850 Cause : %d\n", rcvdsip->cause);
		printf("Media Addr : %.*s\n", rcvdsip->sdp->o_addrlen, rcvdsip->sdp->o_addr);
		printf("Media Port : %d\n", rcvdsip->sdp->m_port[0]);
		fflush(stdout);
	}
*/
// END DEBUG

        if (memcmp(rcvdsip->cseq_method, reg_str, rcvdsip->cseq_methodlen ) == 0 || 
		memcmp(rcvdsip->cseq_method, opt_str, rcvdsip->cseq_methodlen ) == 0 || 
		memcmp(rcvdsip->cseq_method, ping_str, rcvdsip->cseq_methodlen ) == 0) {
		sprintf(reg_wbuf + reg_ofs, "%02d%02d`%s`%lu`%s`%s`%s`%.*s`%.*s`%.*s`%.*s`%.*s`%.*s`%d`%d`%u`%.*s`%.*s`%d`%llu`%d\n",
			file_time->tm_hour, file_time->tm_min, srcname, packetno, datestr, ipsrc, ipdst, rcvdsip_mthdstatlen,
			rcvdsip_mthdstat, rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host,
			rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host,
			rcvdsip->callidlen, rcvdsip->callid, srcport, dstport, rcvdsip->cseq,
			rcvdsip->cseq_methodlen, rcvdsip->cseq_method, rcvdsip->useragtlen, rcvdsip->useragt,
			rcvdsip_expires, f_offset, payload_len);
		reg_ofs = strlen(reg_wbuf);
//		printf("[REGI: %d bytes loaded.]\n", reg_ofs);
//		fflush(stdout);
	} else {
		sprintf(cal_wbuf + cal_ofs, "%02d%02d`%s`%lu`%s`%s`%s`%.*s`%.*s`%.*s`%.*s`%.*s`%.*s`%d`%d`%u`%.*s`%.*s`%llu`%d`%d`%.*s`%d\n",
			file_time->tm_hour, file_time->tm_min, srcname, packetno, datestr, ipsrc, ipdst, rcvdsip_mthdstatlen,
			rcvdsip_mthdstat, rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host,
			rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host,
			rcvdsip->callidlen, rcvdsip->callid, srcport, dstport, rcvdsip->cseq,
			rcvdsip->cseq_methodlen, rcvdsip->cseq_method, rcvdsip->useragtlen, rcvdsip->useragt,
			f_offset, payload_len, rcvdsip->cause, rcvdsip->sdp->o_addrlen, rcvdsip->sdp->o_addr,
			rcvdsip->sdp->m_port[0]);
		cal_ofs = strlen(cal_wbuf);
//		printf("[CALL: %d bytes loaded.]\n", cal_ofs);
//		fflush(stdout);
	} 

	if(reg_ofs > (WRITE_BLOCK_SIZE - 1024)) {
		fprintf(regifp, "%s", reg_wbuf);
		fflush(regifp);
		reg_ofs = 0;
	}
	if(cal_ofs > (WRITE_BLOCK_SIZE - 1024)) {
		fprintf(callfp, "%s", cal_wbuf);
		fflush(callfp);
		cal_ofs = 0;
	}


}

void filestat(int file_time_part, sip_attrs_t *rcvdsip)
{
	int i = file_time_part;
	int j = 0;

	for(j = 0; j < host_stat_totalcnt; j = j + 2) {
		if(memcmp(host_stat[i][j]->src_ip, ipsrc, strlen(ipsrc)) == 0) {
			if(rcvdsip->cseq_methodlen == strlen("REGISTER") && strncmp(rcvdsip->cseq_method, "REGISTER", strlen("REGISTER")) == 0) {
				if(rcvdsip->methodlen == strlen("REGISTER") && strncmp(rcvdsip->method, "REGISTER", strlen("REGISTER")) == 0) {
					host_stat[i][j]->reg[0][0][0]++;
				} else if(rcvdsip->statuslen > 0)
					if(48 <= *(rcvdsip->status) && 57 >= *(rcvdsip->status) && 48 <= *(rcvdsip->status+1) && 57 >= *(rcvdsip->status+1) && 48 <= *(rcvdsip->status+2) && 57 >= *(rcvdsip->status+2)) {
						host_stat[i][j]->reg[*(rcvdsip->status) - 48][*(rcvdsip->status+1) - 48][*(rcvdsip->status+2) - 48]++;
					}
			} else if(rcvdsip->cseq_methodlen == strlen("INVITE") && strncmp(rcvdsip->cseq_method, "INVITE", strlen("INVITE")) == 0) {
				if(rcvdsip->methodlen == strlen("INVITE") && strncmp(rcvdsip->method, "INVITE", strlen("INVITE")) == 0) {
					host_stat[i][j]->inv[0][0][0]++;
				} else if(rcvdsip->statuslen > 0) {
					if(48 <= *(rcvdsip->status) && 57 >= *(rcvdsip->status) && 48 <= *(rcvdsip->status+1) && 57 >= *(rcvdsip->status+1) && 48 <= *(rcvdsip->status+2) && 57 >= *(rcvdsip->status+2)) {
						host_stat[i][j]->inv[*(rcvdsip->status) - 48][*(rcvdsip->status+1) - 48][*(rcvdsip->status+2) - 48]++;
					}
					if(rcvdsip->reasonlen == strlen("Q.850") && strncmp(rcvdsip->reason, "Q.850", strlen("Q.850")) == 0) {
						if(rcvdsip->cause < 255 && rcvdsip->cause > 0) {
							host_stat[i][j]->q850_cause[rcvdsip->cause]++;
						}
					}
				}
			}
		}
	}

	for(j = 1; j < host_stat_totalcnt; j = j + 2) {
		if(memcmp(host_stat[i][j]->dst_ip, ipdst, strlen(ipdst)) == 0) {
			if(rcvdsip->cseq_methodlen == strlen("REGISTER") && strncmp(rcvdsip->cseq_method, "REGISTER", strlen("REGISTER")) == 0) {
				if(rcvdsip->methodlen == strlen("REGISTER") && strncmp(rcvdsip->method, "REGISTER", strlen("REGISTER")) == 0) {
					host_stat[i][j]->reg[0][0][0]++;
				} else if(rcvdsip->statuslen > 0)
					if(48 <= *(rcvdsip->status) && 57 >= *(rcvdsip->status) && 48 <= *(rcvdsip->status+1) && 57 >= *(rcvdsip->status+1) && 48 <= *(rcvdsip->status+2) && 57 >= *(rcvdsip->status+2)) {
						host_stat[i][j]->reg[*(rcvdsip->status) - 48][*(rcvdsip->status+1) - 48][*(rcvdsip->status+2) - 48]++;
					}
			} else if(rcvdsip->cseq_methodlen == strlen("INVITE") && strncmp(rcvdsip->cseq_method, "INVITE", strlen("INVITE")) == 0) {
				if(rcvdsip->methodlen == strlen("INVITE") && strncmp(rcvdsip->method, "INVITE", strlen("INVITE")) == 0) {
					host_stat[i][j]->inv[0][0][0]++;
				} else if(rcvdsip->statuslen > 0) {
					if(48 <= *(rcvdsip->status) && 57 >= *(rcvdsip->status) && 48 <= *(rcvdsip->status+1) && 57 >= *(rcvdsip->status+1) && 48 <= *(rcvdsip->status+2) && 57 >= *(rcvdsip->status+2)) {
						host_stat[i][j]->inv[*(rcvdsip->status) - 48][*(rcvdsip->status+1) - 48][*(rcvdsip->status+2) - 48]++;
					}
					if(rcvdsip->reasonlen == strlen("Q.850") && strncmp(rcvdsip->reason, "Q.850", strlen("Q.850")) == 0) {
						if(rcvdsip->cause < 255 && rcvdsip->cause > 0) {
							host_stat[i][j]->q850_cause[rcvdsip->cause]++;
						}
					}
				}
			}
		}
	}
}

/*******************************************************************************
 * NAME : analyze the input file
 * ARGUMENT : void
 * RETURNS/SIDE-EFFECTS : 
 ******************************************************************************/
//static unsigned char buff[SBUFF_SIZE];
int fileload(sip_attrs_t *rcvdsip)
{
	int bytes_read, *err;
	long seek_increment;
	time_t seconds;
	observer_time packet_time;
	guint64 f_offset = 0;     /* file offset */
    
	/* Ether and IP and L3 header */
	struct ether_header *ep;
	struct ip *ip;
	struct udphdr *udph;
	u_int iphlen, iplen, off;
	u_char *cp;
	int cp_len;
	unsigned char buff[SBUFF_SIZE];

	int file_time_part;
	int sip_type;

	errno = 0;

	/* XK: START READ */
	if(fread(&file_header, sizeof(capture_file_header), 1, srcfp) != 1) {
		perror("file read error");
		return -1;
	}

	if (fseek(srcfp, file_header.offset_to_first_packet, SEEK_SET) == -1) {
		perror("fseek to offset_to_first_packet doesn't exist");
		return -1;
	}
	/* FILE OFFSET RESET */
	f_offset = file_header.offset_to_first_packet;
	   
	/* PACKET READ LOOPING */
	for(;;)
	{
		if(fread(&packet_header, sizeof(packet_header), 1, srcfp) != 1) {
			fprintf(logfp, "> Loop end : %s\n", strerror(errno));
			fflush(logfp);
			return 1;
		} else packetno++;

		if (packet_header.packet_type != TYPE_DATA_PACKET) {
			if (packet_header.offset_to_next_packet < sizeof(packet_header)) {
				perror("Observer: bad record (offset to next packet)");
				return -1;
			}
			seek_increment = packet_header.offset_to_next_packet - sizeof(packet_header);
			if (seek_increment > 0) {
	    			if (fseek(srcfp, seek_increment, SEEK_CUR) == -1) {
					perror("fseek to offset_to_first_packet doesn't exist");
					return -1;
				}
			}
			/* FILE OFFSET RESET */
			f_offset += packet_header.offset_to_next_packet;
			continue;
		}

		seek_increment = packet_header.offset_to_frame - sizeof(packet_header);

		if(seek_increment > 0) {
			if (fseek(srcfp, seek_increment, SEEK_CUR) == -1) {
				perror("Observer: bad record (offset to next packet)");
				return -1;
			}
		}

		bzero(buff, sizeof(buff));
		bytes_read = fread(buff, packet_header.captured_size, 1, srcfp);

		/* IP header, TCP header analyse */
		ep = (struct ether_header *)buff;
       		if ((u_short)ntohs(ep->ether_type) == ETHERTYPE_IP) {
               		ip = (struct ip *)(buff + sizeof(struct ether_header));
               		iphlen = ip->ip_hl * 4;
               		iplen = ntohs(ip->ip_len);

/*
               		if ((packet_header.captured_size-14) < iplen)
                       		printf("truncated-ip - %d bytes missing!", iplen - (packet_header.captured_size-14));
*/

               		off = ntohs(ip->ip_off);

               		if ((off & 0x1fff) == 0 && ip->ip_p == IPPROTO_UDP) {
				udph = (struct udphdr *)((u_char *)ip + iphlen);
                       		sprintf(ipsrc, "%s", inet_ntoa_b(ip->ip_src));
                       		sprintf(ipdst, "%s", inet_ntoa_b(ip->ip_dst));

                       		srcport = htons(udph->source);
                       		dstport = htons(udph->dest);
                       		/* UDP data */
                       		cp = (u_char *)ip + iphlen + sizeof(struct udphdr);

				/* datestr build */
				fill_time_struct(packet_header.nano_seconds_since_2000, &packet_time);
				// useconds = (guint64)(packet_time.useconds_from_1970-((guint64)packet_time.seconds_from_1970)*1000000);
				// nseconds = (guint64)(packet_time.nseconds_from_1970);
				// seconds = (time_t)packet_time.seconds_from_1970;

				file_time = localtime(&packet_time.seconds_from_1970);

				sprintf(datestr, "%04d-%02d-%02d-%02d:%02d:%02d.%09llu", file_time->tm_year+1900, file_time->tm_mon+1, file_time->tm_mday, file_time->tm_hour, file_time->tm_min, file_time->tm_sec, (unsigned long long)packet_time.nseconds);

				cp_len = iplen-iphlen-sizeof(struct udphdr);
				/* parse sip message */
				sip_type = sip_parse(cp, cp_len , rcvdsip);
				if(sip_type > -1) {

// FOR DEBUG
					 file_time_part = (int)(file_time->tm_sec / 10);
					// ##################################
					 filestat(file_time_part, rcvdsip);

                   			/* Print UDP data */
//					printf("%.*s\t%.*s\t%.*s\n", rcvdsip->cseq_methodlen, rcvdsip->cseq_method, rcvdsip->methodlen, rcvdsip->method, rcvdsip->statuslen, rcvdsip->status);
//					fflush(stdout);
					write_parsed_context(f_offset + 98, cp_len, rcvdsip);
				} else {
//					printf("0 parsed.\n");
//					fflush(stdout);
				}	
	  		}
		}
		/* FILE OFFSET RESET */
		f_offset += packet_header.offset_to_next_packet;
	}
//			proc_head(buff, (int)packet_header.captured_size, rcvdsip);
	return 1;
}
