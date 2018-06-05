/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *
 *  Copyright (c) 2018 Maksym Sobolyev <sobomax@sippysoft.com>
 *  Copyright (c) Homer Project 2012 (http://www.sipcapture.org)
 *  Copyright (c) 2010-2016 <Alexandr Dubovikov> 
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the <SIPCAPTURE>. The name of the SIPCAPTURE may not be used to 
 * endorse or promote products derived from this software without specific 
 * prior written permission.

 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
*/

#define USE_IPV6

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#ifdef USE_ZLIB
#include <zlib.h>
#endif /* USE_ZLIB */

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#endif /* USE_SSL */  

struct rc_info;
typedef struct rc_info rc_info_t;

#define HEP_VID_GEN	0x0000

#define HEP_TID_PF	0x0001	/* IP protocol family */
#define HEP_TID_PID	0x0002	/* IP protocol ID */
#define HEP_TID_SA4	0x0003	/* IPv4 source address */
#define HEP_TID_DA4	0x0004	/* IPv4 destination address */
#define HEP_TID_SA6	0x0005	/* IPv6 source address */
#define HEP_TID_DA6	0x0006	/* IPv6 destination address */
#define HEP_TID_SP	0x0007	/* protocol source port (UDP, TCP, SCTP) */
#define HEP_TID_DP	0x0008	/* protocol destination port (UDP, TCP, SCTP) */
#define HEP_TID_TS_S	0x0009	/* timestamp, seconds since 01/01/1970 (epoch) */
#define HEP_TID_TS_MS	0x000a	/* timestamp microseconds offset (added to timestamp) */
#define HEP_TID_PT	0x000b	/* protocol type (SIP/H323/RTP/MGCP/M2UA) */
#define HEP_TID_CAID	0x000c	/* capture agent ID (202, 1201, 2033...) */
		     /* 0x000d     keep alive timer (sec) */
#define HEP_TID_AKEY	0x000e	/* authenticate key (plain text / TLS connection) */
#define HEP_TID_PL_RAW	0x000f	/* captured uncompressed packet payload */
#define HEP_TID_PL_GZ	0x0010	/* captured compressed payload (gzip/inflate) */
#define HEP_TID_CID	0x0011	/* Internal correlation id */

struct hep_ctx {
    int sock;
    long initfails;
    struct addrinfo *ai;
    struct addrinfo hints[1];
    char *capt_host;
    char *capt_port;
    char *capt_password;
    int   capt_id;
    int hep_version;
    int usessl;
    int pl_compress;

    struct hep_generic *hep_hdr;
    u_int16_t hdr_len;

    int sendPacketsCount;

#ifdef USE_SSL
    SSL *ssl;
    SSL_CTX *ctx;
#endif /* USE_SSL */
};

#ifdef USE_SSL
SSL_CTX* initCTX(void);
#endif /* USE_SSL */

void handler(int value);

void hep_gen_dtor(struct hep_ctx *);
int hep_gen_fill(struct hep_ctx *, rc_info_t *);
int hep_gen_append(struct hep_ctx *, u_int16_t, u_int16_t, void *, u_int16_t);
int send_hepv3 (struct hep_ctx *, rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int sendzip);
int send_hepv2 (struct hep_ctx *, rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int send_data (struct hep_ctx *, void *buf, unsigned int len);
int init_hepsocket_blocking (struct hep_ctx *);
int init_hepsocket (struct hep_ctx *);
void sigPipe(int);

/* HEPv3 types */

struct hep_chunk {
       u_int16_t vendor_id;
       u_int16_t type_id;
       u_int16_t length;
       u_int8_t data[0];
} __attribute__((packed));

typedef struct hep_chunk hep_chunk_t;

struct hep_chunk_uint8 {
       hep_chunk_t chunk;
       u_int8_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint8 hep_chunk_uint8_t;

struct hep_chunk_uint16 {
       hep_chunk_t chunk;
       u_int16_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint16 hep_chunk_uint16_t;

struct hep_chunk_uint32 {
       hep_chunk_t chunk;
       u_int32_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint32 hep_chunk_uint32_t;

struct hep_chunk_str {
       hep_chunk_t chunk;
       char *data;
} __attribute__((packed));

typedef struct hep_chunk_str hep_chunk_str_t;

struct hep_chunk_ip4 {
       hep_chunk_t chunk;
       struct in_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip4 hep_chunk_ip4_t;

struct hep_chunk_ip6 {
       hep_chunk_t chunk;
       struct in6_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip6 hep_chunk_ip6_t;

struct hep_ctrl {
    char id[4];
    u_int16_t length;
} __attribute__((packed));

typedef struct hep_ctrl hep_ctrl_t;

struct hep_chunk_payload {
    hep_chunk_t chunk;
    char *data;
} __attribute__((packed));

typedef struct hep_chunk_payload hep_chunk_payload_t;

/* Structure of HEP */

struct hep_generic {
        hep_ctrl_t         header;
        hep_chunk_uint8_t  ip_family;
        hep_chunk_uint8_t  ip_proto;
        hep_chunk_uint16_t src_port;
        hep_chunk_uint16_t dst_port;
        hep_chunk_uint32_t time_sec;
        hep_chunk_uint32_t time_usec;
        hep_chunk_uint8_t  proto_t;
        hep_chunk_uint32_t capt_id;
} __attribute__((packed));

typedef struct hep_generic hep_generic_t;

/*
static hep_generic_t HDR_HEP = {
    {0x48455033, 0x0},
    {0, 0x0001, 0x00, 0x00},
    {0, 0x0002, 0x00, 0x00},
    {0, 0x0003, 0x00, 0x00},
    {0, 0x0004, 0x00, 0x00},
    {0, 0x0005, 0x00, 0x00},
    {0, 0x0006, 0x00, 0x00},
    {0, 0x0007, 0x00, 0x00},
    {0, 0x0008, 0x00, 0x00},
    {0, 0x0009, 0x00, 0x00},
    {0, 0x000a, 0x00, 0x00},
    {0, 0x000b, 0x00, 0x00},
    {0, 0x000c, 0x00, 0x00},
    {0, 0x000d, 0x00, 0x00},
    {0, 0x000e, 0x00, 0x00},
    {0, 0x000f, 0x00, 0x00}
};
*/


struct hep_hdr{
    u_int8_t hp_v;            /* version */
    u_int8_t hp_l;            /* length */
    u_int8_t hp_f;            /* family */
    u_int8_t hp_p;            /* protocol */
    u_int16_t hp_sport;       /* source port */
    u_int16_t hp_dport;       /* destination port */
};

struct hep_timehdr{
    u_int32_t tv_sec;         /* seconds */
    u_int32_t tv_usec;        /* useconds */
    u_int16_t captid;         /* Capture ID node */
};

struct hep_iphdr{
        struct in_addr hp_src;
        struct in_addr hp_dst;      /* source and dest address */
};

#ifdef USE_IPV6
struct hep_ip6hdr {
        struct in6_addr hp6_src;        /* source address */
        struct in6_addr hp6_dst;        /* destination address */
};
#endif
