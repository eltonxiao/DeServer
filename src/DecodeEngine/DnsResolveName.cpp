
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
#include "StdAfx.h"
#ifndef __CS_LINUX
	#include <Winsock2.h>

        // undefine the TRY, CATCH, etc macros defined for MFC - they conflict
        // with ethereal definitions
        #include "UndefineTryCatch.h"
#else
	#include <pthread.h>
        #include <arpa/inet.h>

        #include <boost/thread/thread.hpp>
        #include <boost/thread/mutex.hpp>
        #include <boost/thread/tss.hpp>
        #include <cstdio>
#include <stdlib.h>
#include <string.h>
#include "decode_predef.h"
#endif

#include <string.h> 
#include <ctype.h>

#include "glib.h"

#include "DnsResolveName.h"

//#include "regexx.h"
//using namespace regexx;
//#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
/* adds a hostname/IP in the hash table */
extern void add_ipv4_name(guint addr, const guchar *name);

void DnsResolveName(guchar *pFrame, guint frameLen)
{
	if (frameLen < 12)	// minumum size req of a DNS packet
	{
		return;
	}

/*	if (pFrame->IsTcpFrame())
	{
		pFrame->GetAppDataStart()  += 2;
		pFrame->appDataLen -= 2;

	}
*/
	BYTE * pCurrentOffset = pFrame;
	BYTE * pLastOffset = frameLen + pCurrentOffset + 1;

	CDnsPacket *dnsPkt = (CDnsPacket*)pCurrentOffset;
	// set the local flag about if this is a query or a response
	bool bResponse = dnsPkt->bQueryResponse;

	// we only care about the response packet
//	if (!bResponse)
//		return;
	// make sure the response is OK
	if (dnsPkt->responseCode != 0)
		return;
	/*+-----------------------------------------
	 * There are four sections to process: Question, Answer, Authority, and Additional
	 *------------------------------------------
	-*/

	guchar dnsName[4096];
	dnsName[0] = 0;
	guint dnsIPAdr = 0;

	// place offset at start of RR
	// Question section name starts right after the dns header pkt
	pCurrentOffset += sizeof(CDnsPacket);
	if (pCurrentOffset > pLastOffset)
		return;
	DNS_RESPONSE_TYPE queryType = dnsUnknown;		// temp location to store the query type for process Additional RR

	// process the Question RR
	guint qCount = BSWAP16(dnsPkt->questionCount);
	while (qCount != 0)
	{
		qCount --;	// we are going to process this pkt

		pCurrentOffset = getRString((BYTE *)dnsPkt, pCurrentOffset, dnsName, frameLen);
		// do not insert reverse lookup entries into addressbook
		if (checkIPAdr(dnsName))
			return;

		if (pCurrentOffset > pLastOffset)
			return;
		// Question data structure occurs after the name
		// save off the query type for later processing of the Response or an Update
		CDnsQuestionRecord *qr = (CDnsQuestionRecord*)pCurrentOffset;
		queryType = (DNS_RESPONSE_TYPE)BSWAP16(qr->qType);

		// skip past the Question data structure to the next RR
		pCurrentOffset += sizeof(CDnsQuestionRecord);
		if (pCurrentOffset > pLastOffset)
			return;
	}
	// process the Answer RR
	qCount = BSWAP16(dnsPkt->answerCount);
	bool bGotIP = false;
	bool bGotDNS = false;
	// skip the rest of the answer records so we can get to the Authority section
	while (qCount != 0)
	{
		qCount --;
		// always skip the first name in every RR, data is in the RData
		pCurrentOffset = skipRName(pCurrentOffset);
		guchar strName[256];
		strName[0] = 0;
//		pCurrentOffset = getRString((BYTE *)dnsPkt, pCurrentOffset, strName);
		
		// we should be at the RR's structure section
		CDnsResponseRecord *rr = (CDnsResponseRecord*)pCurrentOffset;
		pCurrentOffset += sizeof(CDnsResponseRecord) - 1;
		if (pCurrentOffset > pLastOffset)
			return;
		guint rrType = BSWAP16(rr->rrType);
		
		// try to locate the DNS name
		if ((bGotDNS == false) || (bGotIP == false))
		{
			// check if the first RR is a Canonical Name type, if not just check if an IP address
			if ((rrType == dnsCName) ||
				(rrType == dnsDomainNamePtr) ||
				(rrType == dnsStartOfAuth) ||
				(rrType == dnsNameServer))
			{
				// RData only contains hostname
				getRString((BYTE *)dnsPkt, pCurrentOffset, strName, frameLen);
				// if domain name is an IP, look for Real DNS name in the next packet
				if (checkIPAdr(strName))
				{
					if (bGotIP == false)
					{
						// convert the IP str to int
						dnsIPAdr = *(guint *)&rr->rdData;
//						dnsIPAdr = Str2IpAddr(strName);
						if (dnsName[0] != 0)
							add_ipv4_name(dnsIPAdr, dnsName);
						bGotIP = true;
					}
				}
				else
				{
					if (bGotDNS == false)
					{
						strcpy((gchar*)dnsName, (gchar*)strName);
						bGotDNS = true;
					}
				}
			}
			else 
			if ((rrType == dnsHostAddr) ||
				(rrType == dnsSrvLoc))
			{
				if (bGotIP == false)
				{
					// make sure the RDatalength is long enough to hold an IPAddr
					if (BSWAP16(rr->rdLength) == 4)
					{
						// convert the IP to string
						dnsIPAdr = *(guint *)&rr->rdData;
						if (dnsName[0] != 0)
							add_ipv4_name(dnsIPAdr, dnsName);
						bGotDNS = true;
						bGotIP = true;
					}
				}
			}
		}
		pCurrentOffset += BSWAP16(rr->rdLength);
		if (pCurrentOffset > pLastOffset)
			return;
	}
	// process the Authority RR
	qCount = BSWAP16(dnsPkt->authorityCount);
	// skip the rest of the answer records so we can get to the Authority section
	while (qCount != 0)
	{
		qCount --;
		// always skip the first name in every RR, data is in the RData
		pCurrentOffset = skipRName(pCurrentOffset);
		
		// we should be at the first RR's structure section
		CDnsResponseRecord *rr = (CDnsResponseRecord*)pCurrentOffset;
		pCurrentOffset += sizeof(CDnsResponseRecord) - 1;
		if (pCurrentOffset > pLastOffset)
			return;
		guint rrType = BSWAP16(rr->rrType);
/*		if ((bGotDNS == false) || (bGotIP == false))//((bResponse && (BSWAP16(dnsPkt->answerCount) == 0)) ||
//			(dnsPkt->opCode == 5))
		{
			if ((rrType == dnsStartOfAuth) ||
				(rrType == dnsCName) ||
				(rrType == dnsDomainNamePtr))
			{
				char strName[256];
				strName[0] = 0;
				getRString((BYTE *)dnsPkt, pCurrentOffset, strName);
				// if domain name is an IP, look for Real DNS name in the next packet
				if (checkIPAdr(strName))
				{
					if (bGotIP == false)
					{
						dnsIPAdr = Str2Ipaddr(strName);
						if (dnsName[0] != 0)
							add_host_name(dnsIPAdr, dnsName);
						bGotIP = true;
					}
				}
				else
				{
					if (bGotDNS == false)
					{
						strcpy(dnsName, strName);
						bGotDNS = true;
					}
				}
			}
		}
		*/
/*		else
//		{
//			pFlow->respDnsName = strName;
//			bGotDNS = true;
//		}
		// get the domain name of the update in the next record
		if ((bGotDNS == false) && (dnsPkt->opCode == 5))
		{
			strName.Empty();
			if (rrType == dnsDomainNamePtr)
			{
				getRString((BYTE *)dnsPkt, pCurrentOffset, strName);
			}
			pFlow->respDnsName = strName;
			bGotDNS = false;
		}
*/
		pCurrentOffset += BSWAP16(rr->rdLength);
		if (pCurrentOffset > pLastOffset)
			return;
	}
	// process the Additional RR
	qCount = BSWAP16(dnsPkt->additionalCount);
	while ((qCount != 0) && ((bGotIP == false) || (bGotDNS == false)))
	{
		qCount --;
		// always skip the first name in every RR, data is in the RData
		guchar strName[256];
		strName[0] = 0;
		pCurrentOffset = getRString((BYTE *)dnsPkt, pCurrentOffset, strName, frameLen);
		// we should be at the first RR's structure section
		CDnsResponseRecord *rr = (CDnsResponseRecord*)pCurrentOffset;
		pCurrentOffset += sizeof(CDnsResponseRecord) - 1;
		if (pCurrentOffset > pLastOffset)
			return;
		if ((strlen((gchar *)dnsName) == 0) || (strcmp((gchar *)dnsName, (gchar *)strName) == 0))
		{
			guint rrType = BSWAP16(rr->rrType);
			if (bGotIP == false)// && ((queryType == dnsSrvLoc)||(queryType == dnsStartOfAuth)))
			{
				// get the primary server
				if (rrType == dnsHostAddr)
				{
					// make sure the RDatalength is long enough to hold an IPAddr
					if (BSWAP16(rr->rdLength) == 4)
					{
						// convert the IP to string
						dnsIPAdr =  *(guint*)&rr->rdData;
						if (dnsName[0] != 0)
							add_ipv4_name(dnsIPAdr, dnsName);
						bGotIP = true;
					}
				}
			}
		}
		pCurrentOffset += BSWAP16(rr->rdLength);
		if (pCurrentOffset > pLastOffset)
			return;
	}
}
// used to skip through the name string
BYTE * skipRName(BYTE * offset)
{
	CDnsName *pName = (CDnsName *)offset;
	// if the name is a ptr, just skip the pointers to get to the struct
	guint nameLen = pName->uNameLen;
	if ((nameLen & 0xF0) == 0xC0)	// PTR?
	{
		offset += sizeof(WORD);	// size and ptr
	}
	else
	{
		// not a PTR, need to traverse the string name
		while (nameLen != 0)
		{
			if (nameLen > 63)
				return offset + 4000;	// error
			pName = (CDnsName *)((BYTE*)pName + nameLen + sizeof(BYTE));	// size
			nameLen = pName->uNameLen;
			// if last item is a Ptr, just finish
			if ((nameLen & 0xF0) == 0xC0)	// PTR?
			{
				pName = (CDnsName *)((BYTE*)pName + sizeof(BYTE));	// size and ptr	is added outside of loop
				nameLen = 0;
			}
		}
		// set to current end of string
		offset = (BYTE *)pName + sizeof(BYTE);	// add in the terminating null byte
	}
	return offset;
}
// used to get the name string into a '.' format
BYTE * getRString(BYTE * startPkt, BYTE * offset, guchar *strName, guint frameLen)
{
	bool	bPtrDetected = false;
    int count = 0;
	
	CDnsName *pName = (CDnsName *)offset;
	guint nameLen = pName->uNameLen;
    BYTE * packetEnd = startPkt + frameLen;
	while (nameLen != 0)
	{
        // don't let this be an infinite loop
        if (count++ >= 20)
        {
            return offset + 4000;
        }

		if (frameLen < nameLen)
		{
			return offset + 4000;	// error
		}

		if ((nameLen & 0xF0) == 0xC0)	// PTR?  only the first 4 bits count
		{
			if (bPtrDetected == false)
			{
				bPtrDetected = true;	// make sure we preserve the new offset
				// Ptr is always the last item
				// final offset is always 2 bytes after this ptr
				offset = (BYTE *)pName + sizeof(WORD);
			}
			// set the char pointer to where the string is actually at
			pName = (CDnsName *)(startPkt + *((BYTE*)&pName->cName));
			nameLen = pName->uNameLen;

			BYTE * pNextString = startPkt + (((pName->uNameLen & 0x0F)<<8)+*((BYTE*)&pName->cName));
            if (pNextString == (BYTE *)pName)
            {
                // pointing to the same location, recursive
                return offset + 4000;
            }
			pName = (CDnsName *)pNextString;
            // make sure we don't go past the packet
            if ((BYTE *)pName > packetEnd)
                return offset + 4000;
			nameLen = pName->uNameLen;
		}
		else
		{
			if (nameLen > 63)
				return offset + 4000;	// error
			guint curlen = guint(strlen((gchar *)strName));
			if (curlen > 256)
				return offset + 4000;	// error
			if (curlen != 0)
				strcat((gchar *)strName, ".");
			strncat((gchar *)strName, (gchar *)&pName->cName, nameLen);
			pName = (CDnsName *)((BYTE*)pName + sizeof(BYTE) + nameLen);
            // make sure we don't go past the packet
            if ((BYTE *)pName > packetEnd)
                return offset + 4000;
			nameLen = pName->uNameLen;
		}
	}
	// determine ptr to next string. we'll need to skip the zero-byte 
    // length which terminated the string - unless the string was terminated by
    // a 'c0' field (in which case pName is pointing to the next byte already).
    BYTE * pNextByte = (BYTE *) pName;
	if (bPtrDetected == false)
	{
		// set to current end of string
		pNextByte = (BYTE *)pNextByte + sizeof(BYTE);
	}
	return pNextByte;
}

// checks the passed in string for an IPaddr beginning
// only support the IPv4 currently, the input IP address's format should like 11.22.33.in-addr.arpa or 11.22.33.44.in-addr.arpa
bool checkIPAdr(guchar *strName)
{
	bool bRet = false;
	if ((strName == NULL) || (strName[0] == 0))
		return false;
	if (!isdigit(strName[0]))
		return false;
/// Shawn modify[3/7/2006]: delete the dependent on GPL regexx
	/* was
	try
	{
		guint matches;
		Regexx rxx;
		rxx.exec((gchar *)strName, anyIP);
		if (rxx.match.size() > 0)
		{
			matches = rxx.match[0].atom.size();
			if (matches >= 3)
			{
/*				char netAddr[50];
				BYTE addr8[4];
				addr8[3] = 0;
				for (int i = 0; i < matches; i++)
				{
					char *str = rxx.match[0].atom[i];
					addr8[matches-1 - i] = atoi(str);
				}
				int ipAddr = (int)(*(int *)addr8);
				IpAddr2Str(netAddr, &ipAddr);
				strcpy(strName, netAddr);
				if (matches == 3)
				{
					// strip out last number
					int len = strlen(strName) - 1;
					if ((strName[len] == '0') || (strName[len] == '.'))
						strName[len] = 0;
				}
* /
				bRet = true;
			}
		}
	}
	catch (Regexx::CompileException &e)
	{
		e;
	}
	*/

	static const char INPUT_IP_STR_END[] =  ".in-addr.arpa";
	char *pSearch = strstr((char *)strName, INPUT_IP_STR_END);
	if (pSearch != NULL)
	{
		const gint MAX_IP_STR_LEN = 15;
		gint ipLen = gint(pSearch - (char *)strName);
		if (ipLen <= MAX_IP_STR_LEN)
		{
			char ipAddrBuf[MAX_IP_STR_LEN+1];
			strncpy(ipAddrBuf, (char *)strName, ipLen);
			ipAddrBuf[ipLen] = '\0';
			int ipAddr = inet_addr(ipAddrBuf);
			if (ipAddr != INADDR_NONE)
			{
				bRet = true;
			}
		}
	}
/// Shawn modify[3/7/2006] end
	return bRet;
}
#ifdef __cplusplus
}
#endif

