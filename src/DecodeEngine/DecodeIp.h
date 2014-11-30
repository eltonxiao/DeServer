
/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

// DecodeIp.h: interface for the CDecodeIp class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(DECODE_IP_H)
#define DECODE_IP_H

#ifndef __CS_LINUX
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#endif
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include "wtap.h"
#include "packet.h"
#include "file.h"
#include "AppTypeIdDefine.h"


/* IP structs and definitions */

typedef struct _e_iphdr {
   guint8  ip_v_hl; /* combines ip_v and ip_hl */
   guint8  ip_tos;
   guint16 ip_len;
   guint16 ip_id;
   guint16 ip_off;
   guint8  ip_ttl;
   guint8  ip_p;
   guint16 ip_sum;
   guint32 ip_src;
   guint32 ip_dst;
} e_iphdr;

typedef struct _e_udphdr {
  guint16 uh_sport;
  guint16 uh_dport;
  guint16 uh_ulen;
  guint16 uh_sum;
} e_udphdr;

typedef struct _e_tcphdr {
  guint16 th_sport;
  guint16 th_dport;
  guint32 th_seq;
  guint32 th_ack;
  guint8  th_reserved1: 4;
  guint8  th_offset: 4; /* combines th_off and th_x2 */
  guint8  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECN  0x40
#define TH_CWR  0x80
  guint16 th_win;
  guint16 th_sum;
  guint16 th_urp;
} e_tcphdr;

#define DNS_PORT		53
#define TCP_PROTOCOL	6
#define UDP_PROTOCOL	17

#define IP_PACKET_MIX_LENGTH	48
#define IP_PACKET				0x0008
#define IP_HDR_OFFSET			14
#define LLC_PROTOCOL_OFFSET     12

typedef struct _portPair
{
	unsigned srcPort;
	unsigned dstPort;
} PORT_PAIR_T, *PORT_PAIR_P;

#if 0 /* remove to AppTypeIdDefine.h for bug#6124 */
/*+-----------------------------------------------
 *  Application Types
 *-------------------------------------------------
-*/
#define APP_UNKNOWN     0
#define APP_GENERIC		0
#define APP_HTTP        1
#define APP_SMTP        2
#define APP_TELNET      3
#define APP_SNMP        4
#define APP_DNS         5
//#define APP_MAIL        6
#define APP_FTP        6
#define APP_SQL         7
#define APP_VOICE       8
#define APP_SIP         9
#define APP_H323        10
#define APP_MGCP        11
#define APP_SKINNY      13
#define APP_RTP         15
#define APP_RAS         16
#define APP_H245        17
#define APP_H225        18
#define APP_LDAP        19
#define APP_POP         20
#define APP_MAPI	    21
#define APP_ADS         22		// active directory service
#define APP_MSSQL       23
#define APP_ORACLE      24
#define APP_SYBASE      25
#define APP_CITRIX      26
#define APP_AIM         27
#define APP_YAHOO_MESENGER   30
#define APP_MSN_MESENGER     31

#define APP_RTCP        47
#define APP_MSN				 56

#define APP_3G324M			 63 /* Added by Huang Yang for Ntt project*/
#define APP_MAX         APP_3G324M  
#endif



inline e_iphdr *GetIpHdr(unsigned char *pFrameStart)
{
	return (e_iphdr *) (pFrameStart + IP_HDR_OFFSET);
}

inline bool IsTcp(unsigned char *pFrameStart)
{
	e_iphdr *pIpHdr = GetIpHdr(pFrameStart);

	return pIpHdr->ip_id == TCP_PROTOCOL;

}

inline bool IsUdp(unsigned char *pFrameStart)
{
	e_iphdr *pIpHdr = GetIpHdr(pFrameStart);

	return pIpHdr->ip_id == UDP_PROTOCOL;

}

inline e_udphdr *GetUdpHdr(unsigned char *pFrameStart)
{
	return (e_udphdr *) (pFrameStart + IP_HDR_OFFSET + sizeof(e_iphdr));
}

inline e_tcphdr *GetTcpHdr(unsigned char *pFrameStart)
{
	return (e_tcphdr *) (pFrameStart + IP_HDR_OFFSET + sizeof(e_iphdr));
}

inline int GetTcpAppDataLen(e_tcphdr *pTcpHdr, int frameLen)
{
	register int tcpOffset = pTcpHdr->th_offset*4;

	return frameLen - (IP_HDR_OFFSET + sizeof(e_iphdr) + tcpOffset);
}

inline int GetUdpAppDataLen(e_udphdr *pUdpHdr, int frameLen)
{
	return frameLen - (IP_HDR_OFFSET + sizeof(e_iphdr) + sizeof(e_udphdr));
}

inline unsigned char *GetTcpAppStart(e_tcphdr *pTcpHdr)
{
	return ((unsigned char *) pTcpHdr) + pTcpHdr->th_offset*4;
}

inline unsigned char *GetUdpAppStart(e_udphdr *pUdpHdr)
{
	return ((unsigned char *) pUdpHdr) + sizeof(e_udphdr);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */



#endif // !defined(DECODE_IP_H)

