
#ifndef __CFILE_H__
#define __CFILE_H__
#endif

#ifndef __NSTIME_H__
#define __NSTIME_H__
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP		0x0800
#endif

#define G_HAVE_GINT64 1          /* deprecated, always true : supported 64bit integer */
#define G_GINT64_CONSTANT(val)	(G_GNUC_EXTENSION (val##LL))
#define G_GUINT64_CONSTANT(val)	(G_GNUC_EXTENSION (val##ULL))
#define FILE_T  FILE *
#define GUINT16_TO_LE(val)	((guint16) (val))
#define GUINT16_FROM_LE(val)	(GUINT16_TO_LE (val))
#define file_read fread
#define TYPE_DATA_PACKET		0
#define TYPE_EXPERT_INFORMATION_PACKET	1

extern char stat_host[256][64];

typedef void* gpointer;
typedef const void *gconstpointer;
typedef char gchar;
typedef unsigned char guchar;
typedef int gint;
typedef unsigned int guint;
typedef short gshort;
typedef unsigned gushort;
typedef long glong;
typedef unsigned long gulong;
typedef signed char gint8;
typedef unsigned char guint8;
typedef signed short gint16;
typedef unsigned short guint16;
typedef signed int gint32;
typedef unsigned int guint32;
typedef signed long long gint64;
typedef unsigned long long guint64;
typedef gint   gboolean;
typedef float   gfloat;
typedef double  gdouble;
typedef unsigned int gsize;
typedef signed int gssize;

typedef struct _GList GList;

#define INET_NTOA_MAX_LEN   16  /* max 12 digits + 3 '.'s + 1 nul */

#ifdef  linux 
#include <sys/socket.h>    
#include <netinet/if_ether.h>
#include <netinet/in.h>    
#include <netinet/in_systm.h>
#include <netinet/ip.h>    
#include <netinet/udp.h>
#else
/* linux/if_ether.h */
#define ETH_ALEN       6               /* Octets in one ethernet addr   */

typedef unsigned char u_int8_t;
typedef unsigned int u_int;
typedef unsigned short u_int16_t;
typedef unsigned short u_short;
typedef unsigned char u_char;

/* net/ethernet.h */       
struct ether_header
{   
  u_int8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
  u_int16_t ether_type;             /* packet type ID field */
};  

#define      ETHERTYPE_IP            0x0800          /* IP */

/* netinet/in.h */
/* Standard well-defined IP protocols.  */
enum
  {
    IPPROTO_IP = 0,        /* Dummy protocol for TCP.  */
    #define IPPROTO_IP      IPPROTO_IP
    IPPROTO_HOPOPTS = 0,   /* IPv6 Hop-by-Hop options.  */
    #define IPPROTO_HOPOPTS     IPPROTO_HOPOPTS
    IPPROTO_ICMP = 1,      /* Internet Control Message Protocol.  */
    #define IPPROTO_ICMP        IPPROTO_ICMP
    IPPROTO_IGMP = 2,      /* Internet Group Management Protocol. */
    #define IPPROTO_IGMP        IPPROTO_IGMP
    IPPROTO_IPIP = 4,      /* IPIP tunnels (older KA9Q tunnels use 94).  */
    #define IPPROTO_IPIP        IPPROTO_IPIP
    IPPROTO_TCP = 6,       /* Transmission Control Protocol.  */
    #define IPPROTO_TCP     IPPROTO_TCP
    IPPROTO_EGP = 8,       /* Exterior Gateway Protocol.  */
    #define IPPROTO_EGP     IPPROTO_EGP
    IPPROTO_PUP = 12,      /* PUP protocol.  */
    #define IPPROTO_PUP     IPPROTO_PUP
    IPPROTO_UDP = 17,      /* User Datagram Protocol.  */
    #define IPPROTO_UDP     IPPROTO_UDP
    IPPROTO_IDP = 22,      /* XNS IDP protocol.  */
    #define IPPROTO_IDP     IPPROTO_IDP
    IPPROTO_TP = 29,       /* SO Transport Protocol Class 4.  */
    #define IPPROTO_TP      IPPROTO_TP
    IPPROTO_IPV6 = 41,     /* IPv6 header.  */
    #define IPPROTO_IPV6        IPPROTO_IPV6
    IPPROTO_ROUTING = 43,  /* IPv6 routing header.  */
    #define IPPROTO_ROUTING     IPPROTO_ROUTING
    IPPROTO_FRAGMENT = 44, /* IPv6 fragmentation header.  */
    #define IPPROTO_FRAGMENT    IPPROTO_FRAGMENT
    IPPROTO_RSVP = 46,     /* Reservation Protocol.  */
    #define IPPROTO_RSVP        IPPROTO_RSVP
    IPPROTO_GRE = 47,      /* General Routing Encapsulation.  */
    #define IPPROTO_GRE     IPPROTO_GRE
    IPPROTO_ESP = 50,      /* encapsulating security payload.  */
    #define IPPROTO_ESP     IPPROTO_ESP
    IPPROTO_AH = 51,       /* authentication header.  */
    #define IPPROTO_AH      IPPROTO_AH
    IPPROTO_ICMPV6 = 58,   /* ICMPv6.  */
    #define IPPROTO_ICMPV6      IPPROTO_ICMPV6
    IPPROTO_NONE = 59,     /* IPv6 no next header.  */
    #define IPPROTO_NONE        IPPROTO_NONE
    IPPROTO_DSTOPTS = 60,  /* IPv6 destination options.  */
    #define IPPROTO_DSTOPTS     IPPROTO_DSTOPTS
    IPPROTO_MTP = 92,      /* Multicast Transport Protocol.  */
    #define IPPROTO_MTP     IPPROTO_MTP
    IPPROTO_ENCAP = 98,    /* Encapsulation Header.  */
    #define IPPROTO_ENCAP       IPPROTO_ENCAP
    IPPROTO_PIM = 103,     /* Protocol Independent Multicast.  */
    #define IPPROTO_PIM     IPPROTO_PIM
    IPPROTO_COMP = 108,    /* Compression Header Protocol.  */
    #define IPPROTO_COMP        IPPROTO_COMP
    IPPROTO_SCTP = 132,    /* Stream Control Transmission Protocol.  */
    #define IPPROTO_SCTP        IPPROTO_SCTP
    IPPROTO_RAW = 255,     /* Raw IP packets.  */
    #define IPPROTO_RAW     IPPROTO_RAW
    IPPROTO_MAX
  };


/* Internet address.  */
typedef unsigned int in_addr_t;
struct in_addr
  {
    in_addr_t s_addr;
  };


/* netinet/ip.h */
struct ip
  {
    unsigned int ip_hl:4;       /* header length */
    unsigned int ip_v:4;        /* version */
    u_int8_t ip_tos;            /* type of service */
    u_short ip_len;             /* total length */
    u_short ip_id;              /* identification */
    u_short ip_off;             /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_int8_t ip_ttl;            /* time to live */
    u_int8_t ip_p;              /* protocol */
    u_short ip_sum;             /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
  };

/* netinet/udp.h */
struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};

#endif


struct _GList
{
  gpointer data;
  GList *next;
  GList *prev;
};

typedef enum {
	FILE_CLOSED,		         /* No file open */
	FILE_READ_IN_PROGRESS,	 /* Reading a file we've opened */
	FILE_READ_ABORTED,	     /* Read aborted by user */
	FILE_READ_DONE		       /* Read completed */
} file_state;

typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;

typedef struct Buffer {
	guchar		*data;
	unsigned int	allocated;
	unsigned int	start;
	unsigned int	first_free;
} Buffer;

typedef struct capture_file_header
{
	char	observer_version[32];
	guint16	offset_to_first_packet;
	char	probe_instance;
	char	extra_information_present;
} capture_file_header;

typedef struct packet_entry_header
{
	guint32 packet_magic;
	guint32 network_speed;
	guint16 captured_size;
	guint16 network_size;
	guint16 offset_to_frame;
	guint16 offset_to_next_packet;
	guint8 network_type;
	guint8 flags;
	guint8 extra_information;
	guint8 packet_type;
	guint16 errors;
	guint16 reserved;
	guint64 packet_number;
	guint64 original_packet_number;
	guint64 nano_seconds_since_2000;
} packet_entry_header;

typedef struct observer_time
{
	guint64 ns_since2000;		    /* given in packet_entry_header */

	guint64 us_since2000;		    /* Micro-Seconds since 1-1-2000 */
	guint64 sec_since2000;	  	/* Seconds since 1-1-2000 */

	time_t seconds_from_1970;
	guint64 useconds_from_1970;

} observer_time;


typedef struct stat_protocol {
  int tcp_cnt;
  int udp_cnt;
  int tot_cnt;
  int sip_cnt;
} STATPROTOCOL;
	
typedef struct stat_tcp {
	int tcp1;
	int tcp2;
	int tcp3;
	int tcp4;
	int tcp5;
	int tcp6;
	int tcp7;
	int tcp8;
	int tcp9;
	int tcp10;
	int tcp11;
	int tcp12;
	int tcp13;
	int tcp14;
	int tcp15;
	int tcp16;
	int tcp17;
	int tcp18;
	int tcp19;
	int tcp20;
	int tcp21;
	int tcp22;
	int tcp23;
	int tcp24;
	int tcp25;
	int tcp26;
	int tcp27;
	int tcp28;
	int tcp29;
	int tcp30;
	int tcp31;
	int tcp32;
	int tcp33;
	int tcp34;
	int tcp35;
	int tcp36;
	int tcp37;
	int tcp38;
	int tcp39;
	int tcp40;
	int tcp41;
	int tcp42;
	int tcp43;
	int tcp44;
	int tcp45;
	int tcp46;
	int tcp47;
	int tcp48;
	int tcp49;
	int tcp50;
	int tcp51;
	int tcp52;
	int tcp53;
	int tcp54;
	int tcp55;
	int tcp56;
	int tcp57;
	int tcp58;
	int tcp59;
	int tcp60;
	int tcp61;
	int tcp62;
	int tcp63;
	int tcp64;
	int tcp65;
	int tcp66;
	int tcp67;
	int tcp68;
	int tcp69;
	int tcp70;
	int tcp71;
	int tcp72;
	int tcp73;
	int tcp74;
	int tcp75;
	int tcp76;
	int tcp77;
	int tcp78;
	int tcp79;
	int tcp80;
	int tcp81;
	int tcp82;
	int tcp83;
	int tcp84;
	int tcp85;
	int tcp86;
	int tcp87;
	int tcp88;
	int tcp89;
	int tcp90;
	int tcp91;
	int tcp92;
	int tcp93;
	int tcp94;
	int tcp95;
	int tcp96;
	int tcp97;
	int tcp98;
	int tcp99;
	int tcp100;
	int tcp101;
	int tcp102;
	int tcp103;
	int tcp104;
	int tcp105;
	int tcp106;
	int tcp107;
	int tcp108;
	int tcp109;
	int tcp110;
	int tcp111;
	int tcp112;
	int tcp113;
	int tcp114;
	int tcp115;
	int tcp116;
	int tcp117;
	int tcp118;
	int tcp119;
	int tcp120;
	int tcp121;
	int tcp122;
	int tcp123;
	int tcp124;
	int tcp125;
	int tcp126;
	int tcp127;
	int tcpoth;
} TCPPROTOCOL;

typedef struct stat_method {
   int invite_cnt;
   int ack_cnt;
   int bye_cnt;
   int cancel_cnt;
   int register_cnt;
   int option_cnt;
   int info_cnt;
   int message_cnt;
   int update_cnt;
   int refer_cnt;
   int prack_cnt;
   int subscribe_cnt;
   int unsubscribe_cnt;
   int notify_cnt;
} METHODCNT;

typedef struct stat_message {
    int cnt_100;
    int cnt_180;
    int cnt_181;
    int cnt_182;
    int cnt_183;
    int cnt_200;
    int cnt_202;
    int cnt_300;
    int cnt_301;
    int cnt_302;
    int cnt_305;
    int cnt_380;
    int cnt_400;
    int cnt_401;
    int cnt_402;
    int cnt_403;
    int cnt_404;
    int cnt_405;
    int cnt_406;
    int cnt_407;
    int cnt_408;
    int cnt_410;
    int cnt_413;
    int cnt_414;
    int cnt_415;
    int cnt_416;
    int cnt_420;
    int cnt_421;
    int cnt_422;
    int cnt_423;
    int cnt_429;
    int cnt_480;
    int cnt_481;
    int cnt_483;
    int cnt_484;
    int cnt_485;
    int cnt_486;
    int cnt_487;
    int cnt_488;
    int cnt_489;
    int cnt_491;
    int cnt_493;
    int cnt_494;
    int cnt_500;
    int cnt_501;
    int cnt_502;
    int cnt_503;
    int cnt_504;
    int cnt_505;
    int cnt_513;
    int cnt_580;
    int cnt_600;
    int cnt_603;
    int cnt_604;
    int cnt_607;
    int cnt_687;
} MESSAGECNT;

typedef struct db_column {
	char *packetno_col;
	char *datestr_col;
	char *ipsrc_col;
	char *ipdst_col;
	char *srcport_col;
	char *dstport_col;
	char *method_col;
	char *to_num_col;
	char *to_domain_col;
	char *from_num_col;
	char *from_domain_col;
	char *callid_str_col;
	char *cseq_num_col;
	char *cseq_mtd_col;
        char *user_agent_col;
	char *srcname_col;
        char *expire_col;
        int offsetnum_col;
        int length_col;
} DBCOLINFO;

enum SIP_METHOD {
   INVITE,
   ACK,
   BYE,
   CANCEL,
   REGISTER,
   OPTIONS,
   INFO,
   MESSAGE,
   UPDATE,
   REFER,
   PRACK,
   SUBSCRIBE,
   UNSUBSCRIBE,
   NOTITY
} METHOD;

enum SIP_MESSAGE {
   MSG_100,
   MSG_180,
   MSG_181,
   MSG_182,
   MSG_183,
   MSG_200,
   MSG_202,
   MSG_300,
   MSG_301,
   MSG_302,
   MSG_305,
   MSG_380,
   MSG_400,
   MSG_401,
   MSG_402,
   MSG_403,
   MSG_404,
   MSG_405,
   MSG_406,
   MSG_407,
   MSG_408,
   MSG_410,
   MSG_413,
   MSG_414,
   MSG_415,
   MSG_416,
   MSG_420,
   MSG_421,
   MSG_422,
   MSG_423,
   MSG_429,
   MSG_480,
   MSG_481,
   MSG_483,
   MSG_484,
   MSG_485,
   MSG_486,
   MSG_487,
   MSG_488,
   MSG_489,
   MSG_491,
   MSG_493,
   MSG_494,
   MSG_500,
   MSG_501,
   MSG_502,
   MSG_503,
   MSG_504,
   MSG_505,
   MSG_513,
   MSG_580,
   MSG_600,
   MSG_603,
   MSG_604,
   MSG_607,
   MSG_687
} MESSAGES;

typedef struct env_list {
  int debug_status;
  int log_file;
  int dblog_file;
  char temp_file;
  char log_folder[512];
  char dblog_folder[512];
  char temp_folder[512];
  char hostname[100];
  char dbname[100];
  char username[50];
  char password[50];
  char dbsid[50];
} ENVLST;
