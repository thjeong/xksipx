
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

//	guint64 us_since2000;		    /* Micro-Seconds since 1-1-2000 */
//	guint64 sec_since2000;	  	/* Seconds since 1-1-2000 */

	time_t seconds_from_1970;
//	guint64 useconds_from_1970;
	guint64 nseconds;

} observer_time;

typedef struct summary
{
	char src_ip[32];
	char dst_ip[32];
	long reg_req;
	long reg_200;
	long reg_300;
	long reg_400;
	long reg_500;
	long reg_600;
	long reg_other;
	long inv_req;
	long inv_200;
	long inv_300;
	long inv_400;
	long inv_500;
	long inv_501;
	long inv_502;
	long inv_503;
	long inv_504;
	long inv_600;
	long inv_other;
	long other;
} statistics;

extern statistics *host_stat[6][512];

