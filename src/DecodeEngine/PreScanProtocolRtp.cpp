
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
// PreScanProtocolRtp.cpp: implementation of the CPreScanProtocolRtp class.
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

#include "PreScanProtocolRtp.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPreScanProtocolRtp::CPreScanProtocolRtp(char *protocolName) : CPreScanProtocol(protocolName)
{
	SetProtocolId(PRO_RTP_ID);
}

CPreScanProtocolRtp::~CPreScanProtocolRtp()
{

}

gint CPreScanProtocolRtp::FindMediaPortByString(gchar *str)
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

gchar *CPreScanProtocolRtp::FindCallIdByString(gchar *str, gchar *callId)
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

#define RTP_MAX_PAYLOAD_TYPE		127
static bool IsRtpFrame(unsigned char *pUdpStart, int appDataLen)
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
	   payload<=RTP_MAX_PAYLOAD_TYPE && 
	   appDataLen >=16)
	{
		return TRUE;
	}
	return FALSE;
}

/*+-----------------------------------------------------------------------
 *	Parse
 *------------------------------------------------------------------------
-*/
bool CPreScanProtocolRtp::Parse(unsigned char *pFrameStart, int frameLen)
{
	register gint   appDataLen;
	gint            rtpPort = 0;

	if (frameLen < 58)		// not enough length for RTP packet
		return false;

	if (pFrameStart[23] != 0x11)		// not a UDP packet
		return false;

	appDataLen = GetUdpAppDataLen(frameLen);

	/*+------------------------------------------
	 * Ports never released.  But, this is one
	 * decode instance only 
	 *-------------------------------------------
	-*/
	if (IsRtpFrame(pFrameStart+34, appDataLen))		// pass UDP start address and app length
	{
		tie_port(PT_UDP, rtpPort, "rtp");
		tie_port(PT_UDP, rtpPort+1, "rtcp");
		return true;
	}

	return false;
}

/*+-----------------------------------------------------------------------
 *	always return true since there is no checking here.  RTP can only be
 *  the last one.
 *------------------------------------------------------------------------
-*/
bool CPreScanProtocolRtp::IsMe(unsigned int protocolId)
{
	return true;
}

