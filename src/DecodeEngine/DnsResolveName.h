
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
#ifndef __DNSRESOLVENAME_H__
#define __DNSRESOLVENAME_H__
#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

extern void DnsResolveName(guchar *, guint);
BYTE * skipRName(BYTE * offset);
BYTE * getRString(BYTE * startPkt, BYTE * offset, guchar *strName, guint frameLen);
bool checkIPAdr(guchar *strName);

/*+--------------------------------------------------
 * Dns Response types
 *---------------------------------------------------
-*/
typedef enum _DNS_RESPONSE_TYPE
{
	dnsUnknown,
	dnsHostAddr,
	dnsNameServer,
	dnsMailDest,
	dnsMailForward,
	dnsCName,
	dnsStartOfAuth,
	dnsMailBox,
	dnsMailGroup,
	dnsMailRename,
	dnsNull,
	dnsWellKnown,
	dnsDomainNamePtr,
	dnsHostInfo,
	dnsMailInfo,
	dnsMailRouting,
	dnsText,
	dnsRespPerson,
	dnsAFSDB,
	dnsX25,
	dnsISDN,
	dnsRouteThru,
	dnsNSAP,
	dnsNSAPPtr,
	dnsSignature,
	dnsKey,
	dnsX400,
	dnsGeoPos,
	dnsIPV6Addr,
	dnsLocation,
	dnsNext,
	dnsEID,
	dnsNIMLoc,
	dnsSrvLoc,
	dnsATMA,
	dnsNameAuthPtr,
	dnsKeyExch,
	dnsCert,
	dnsIndIPV6,
	dnsNTInd,
	dnsUKN1,
	dnsOpt
			// ignore the rest for now
}	DNS_RESPONSE_TYPE;

/*+--------------------------------------------------
 * Dns packet struture
 *---------------------------------------------------
-*/
typedef struct _CDnsPacket
{
	WORD				uQueryID;
	WORD				flagRecursionDesired:1;
	WORD				flagTruncation:1;
	WORD				flagAuthAnswer:1;
	WORD				opCode:4;
	WORD				bQueryResponse:1;
	WORD				responseCode:4;
	WORD				flagReserv3:1;
	WORD				flagCheckdisabled:1;
	WORD				flagAuthenticateData:1;
	WORD				flagRecursionAvail:1;

	WORD				questionCount;
	WORD				answerCount;
	WORD				authorityCount;
	WORD				additionalCount;
} CDnsPacket;

/*+--------------------------------------------------
 * Dns general Name format
 *---------------------------------------------------
-*/
typedef struct _CDnsName
{
	BYTE				uNameLen;		// should be < 63 for labels, and 
	BYTE				cName;			// we need to subtract this byte
}CDnsName;
/*+--------------------------------------------------
 * Dns Question section format
 *---------------------------------------------------
-*/
typedef struct _CDnsQuestionRecord
{
//	CDnsName			qName[];
	WORD				qType;
	WORD				qClass;
}CDnsQuestionRecord;

/*+--------------------------------------------------
 * Dns Response section format
 *---------------------------------------------------
-*/
typedef struct _CDnsResponseRecord
{
//	CDnsName			rrName[];
	WORD				rrType;
	WORD				rrClass;
	int					rrTTL;		// in seconds
	WORD				rdLength;
	BYTE				rdData;			// we need to subtract this byte
} CDnsResponseRecord;

/*+--------------------------------------------------
 * Dns Service Location Response Record section format
 *---------------------------------------------------
-*/
typedef struct _CDnsServiceLocationRR
{
	WORD				rrPriority;
	WORD				rrWeight;
	WORD				rrPort;
	BYTE				rrTarget;	// variable length			// we need to subtract this byte
} CDnsServiceLocationRR;


/*+--------------------------------------------------
 * Regular expression used to find the IP address for 3 or 4 IPs
 *---------------------------------------------------
-*/
static const char anyIP[] =  {
    "\\b"								// bracket with beginning non-word
    "("									// capture D octet
        "2[0-4]\\d"						// 2[0-4] can have any digit after it
        "|"								// or
        "25[0-5]"						// 25 can only have [0-5]
        "|"								// or
        "[01]?\\d{1,2}"					// optional [01] then 1 or 2 digits
    ")"
    "\\."
    "(2[0-4]\\d|25[0-5]|[01]?\\d{1,2})"	// repeat for C octet
    "\\."
    "(2[0-4]\\d|25[0-5]|[01]?\\d{1,2})"	// repeat for B octet
    "\\.*"
    "(2[0-4]\\d|25[0-5]|[01]?\\d{1,2})*"	// repeat for A octet
    "\\b"								// bracket with ending non-word
	"\\.in-addr\\.arpa"
};

/* Macros to byte-swap 32-bit and 16-bit quantities. */
#define	BSWAP32(x) \
	((((x)&0xFF000000)>>24) | \
	 (((x)&0x00FF0000)>>8) | \
	 (((x)&0x0000FF00)<<8) | \
	 (((x)&0x000000FF)<<24))
#define	BSWAP16(x) \
	 ((((x)&0xFF00)>>8) | \
	  (((x)&0x00FF)<<8))

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif  /* __DNSRESOLVENAME_H_ */