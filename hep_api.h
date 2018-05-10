/*
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

typedef struct rc_info {
    uint8_t     ip_family;  /* IP family IPv6 IPv4 */
    uint8_t     ip_proto;   /* IP protocol ID : tcp/udp */
    uint8_t     proto_type; /* SIP: 0x001, SDP: 0x03*/    
    char        *src_ip;
    char        *dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint32_t    time_sec;
    uint32_t    time_usec;
} rc_info_t;
