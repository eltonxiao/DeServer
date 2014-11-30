
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
// PreScanProtocolH323.cpp: implementation of the CPreScanProtocolH323 class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#ifndef __CS_LINUX

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
#include <string.h>
#include <stdlib.h>
        #include "decode_predef.h"
#endif

#include "PreScanProtocolH323.h"


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPreScanProtocolH323::CPreScanProtocolH323(char *protocolName) : CPreScanProtocol(protocolName)
{
	SetProtocolId(PRO_H323_ID);
	pH323 = new CONSTRUCT_DATA;
}

CPreScanProtocolH323::~CPreScanProtocolH323()
{
	delete pH323;
}

gint CPreScanProtocolH323::FindMediaPortByString(gchar *str)
{
#define MEDIA_STR	"m=audio"
	gchar *ptr;
	gint portNumberLength = 0;
	ptr = strstr(str, MEDIA_STR);
	if (ptr)
	{
		gchar portNumber[32];
		gchar *pPortNumber = &portNumber[0];

		ptr += strlen(MEDIA_STR);
		while (*ptr == ' ')
		{
			ptr++;
		}

		while ((*ptr != ' ') && (portNumberLength++ < 32))

		{
			*pPortNumber++ = *ptr++;
		}

		*pPortNumber = '\0';
		return atoi(portNumber);
	}

	return 0;
}

gchar *CPreScanProtocolH323::FindCallIdByString(gchar *str, gchar *callId)
{
#define CALLID_STR	"Call-ID:"

	gchar *ptr;
	gchar *endCallId;
	gint  callIdLen;

	ptr = strstr(str, CALLID_STR);
	if (ptr)
	{
		ptr += strlen(CALLID_STR);
		while (*ptr == ' ')
		{
			ptr++;
		}
		
		endCallId = strstr(ptr, "@");
		if (endCallId)
		{
			callIdLen = (gint) (endCallId - ptr);
			if (callIdLen >= 128)
				callIdLen = 127;
			strncpy(callId, ptr, callIdLen);
			callId[callIdLen] = '\0';

			return callId;
		}
	}

	return (gchar *) 0;
}

BOOL IsRtpFrame(unsigned char *pUdpStart, int appDataLen)
{
	unsigned char *pAppStart = pUdpStart + 8;

	unsigned short  srcPort, dstPort;
    unsigned char   payload, rtpVersion;
	
	srcPort    = *((WORD*) pUdpStart);
	srcPort    = (((srcPort)>>8 & 0xff) | ((srcPort)<<8 & 0xff00));
	dstPort    = *((WORD*) (pUdpStart+2));
	dstPort    = (((dstPort)>>8 & 0xff) | ((dstPort)<<8 & 0xff00));
	             
	rtpVersion = (*pAppStart) >>6;

	payload = (*(pAppStart+1)) & 0x7F;

	//normally RTP ports are even numbers
	//RTP version is 2
	//payload max 34 at this time
	//min length for RTP is 16
	if(rtpVersion == 2 && 
	   (srcPort%2==0 || dstPort%2 ==0) && 
	   payload>=0 && 
	   payload<=34 && 
	   appDataLen >=16)
	{
		return TRUE;
	}
	return FALSE;
}

/*+-----------------------------------------------------------------------
 *	Parse
 *    How to smell the H.245 port:
 *       Look at SETUP-UUIE and Alerting-UUIE
 *    How to get RTP/RTCP port from H.245
 *       Response packets from: Open Logical Channel (ACK)
 *------------------------------------------------------------------------
-*/
bool CPreScanProtocolH323::Parse(unsigned char *pFrameStart, int frameLen)
{
	register guchar *pAppStart;
	register gint   appDataLen;
	gint            rtpPort = 0;
	e_tcphdr *pTcpHdr;

	pTcpHdr    = GetTcpHdr(pFrameStart);
	pAppStart  = GetTcpAppStart(pTcpHdr);
	appDataLen = GetTcpAppDataLen(pTcpHdr, frameLen);

	if(appDataLen == 0)
		return false;
	// if you find H245 port please add it here
	//Start from Q.931
	BYTE *pxData = (BYTE*)pAppStart;
	UINT DataLen = appDataLen;
	TRANSPORTaddress  h245Addr;

	for(; pxData<=(pAppStart+DataLen); pxData++)
	{		
		if(*pxData ==0x7E && *(pxData+3)==0x05)
			break;
	}
	if(pxData>=(pAppStart+DataLen))
		return false;
	/////////////////////H323-UserInformation: the root///////////////////////////////
	{
		UINT  msgType;
		BOOL  bExt;		

		pxData+=4; //protocol discriminator
		initH323ConstructData(pH323, pxData, (pFrameStart + frameLen), 8);
		//h323-user ext, user-data option, h323-uu-pdu ext, nonStadand option = 4 bits
		pH323->cur_bit_offset = 4;

		//h323-message-body ext, 3 bits for msg type = 4 bits
		bExt = IncludeOptionalField(pH323, 1);

		if(!bExt)
		msgType = getBitsFieldValue(pH323, 3, 0);
		else
			msgType = getExtensionFieldNumber(pH323, 7);

		initTRANSPORTaddressData(h245Addr);

		switch(msgType)
		{
		case 0:	//setup
		{
			BOOL  bExt, bH245Addr, bSrcAddr, bDstAddr, bDstCallSigAddr,
				  bDstExtraCallInfo, bDstExtraCRV, bCallService;
			unsigned short length;

			bExt				= IncludeOptionalField(pH323, 1);
			bH245Addr			= IncludeOptionalField(pH323, 1);
			bSrcAddr			= IncludeOptionalField(pH323, 1);
			bDstAddr			= IncludeOptionalField(pH323, 1);
			bDstCallSigAddr		= IncludeOptionalField(pH323, 1);
			bDstExtraCallInfo	= IncludeOptionalField(pH323, 1);
			bDstExtraCRV		= IncludeOptionalField(pH323, 1);
			bCallService		= IncludeOptionalField(pH323, 1);

			//protocolIdentifier:length filed and contents field
			length = *pH323->pData;
			setH323CurrentData(pH323, 1+length);

			//h245Address
			if(bH245Addr)
			{
				h225_TransportAddress(pH323, h245Addr);
			}
			break;
		}
		case 2:  //connect
			{
				BOOL  bExt, bH245Addr;
				unsigned short length;

				bExt				= IncludeOptionalField(pH323, 1);
				bH245Addr			= IncludeOptionalField(pH323, 1);	

				//protocolIdentifier:length filed and contents field
				needAdvancePointer(pH323);
				length = *pH323->pData;
				setH323CurrentData(pH323, 1+length, 8);

				//h245Address
				if(bH245Addr)
				{
					h225_TransportAddress(pH323, h245Addr);
				}
				break;
			}
		case 3: //alerting
			/*{
				BOOL  bExt, bH245Addr;
				unsigned short length;

				bExt				= IncludeOptionalField(pH323, 1);
				bH245Addr			= IncludeOptionalField(pH323, 1);	

				//protocolIdentifier:length filed and contents field
				needAdvancePointer(pH323);
				length = *pH323->pData;
				setH323CurrentData(pH323, 1+length, 8);

				//destinationInfo  EndpointType
				h323_EndpointType(pH323);

				//h245Address
				if(bH245Addr)
				{
					h225_TransportAddress(pH323, h245Addr);
				}			
			}*/
			break;
		case 1: //callProceeding
			break;
		default: break;
		}
	}

	if (h245Addr.port !=0) //h245 port, if protocol discriminator is 8, and it is user to user element
	{
		gint h245Port = h245Addr.port;

		AddAppPort(APP_H323, h245Port, true);
		tie_port(PT_TCP, h245Port, "h245");
		return true;
	}

#ifdef FIXME
	if (tear down)
	{
		gint h245Port = 11016;
		DelAppPort(APP_H323, h245Port);

	}
#endif
	
	return false;
}

