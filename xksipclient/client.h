#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

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
