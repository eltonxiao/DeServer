
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
// PreScanProtocolMgcp.cpp: implementation of the CPreScanProtocolMgcp class.
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

#include "PreScanProtocolMgcp.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPreScanProtocolMgcp::CPreScanProtocolMgcp(char *protocolName) : CPreScanProtocol(protocolName)
{
	SetProtocolId(PRO_MGCP_ID);

}

CPreScanProtocolMgcp::~CPreScanProtocolMgcp()
{

}

gint CPreScanProtocolMgcp::FindMediaPortByString(gchar *str)
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

gchar *CPreScanProtocolMgcp::FindCallIdByString(gchar *str, gchar *callId)
{
#define CALLID_STR	"C:"

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
		
		endCallId = strstr(ptr, "\n");
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

bool CPreScanProtocolMgcp::Parse(unsigned char *pFrameStart, int frameLen)
{
	register guchar *pAppStart;
	register gint   appDataLen;
	gint            rtpPort = 0;
	char            callId[128];

	pAppStart  = GetUdpAppStartAddress(pFrameStart);
	appDataLen = GetUdpAppDataLen(frameLen);

	if (pAppStart)
	{
		if (strncmp((gchar *) pAppStart, "MDCX", strlen("MDCX")) == 0 ||
			strncmp((gchar *) pAppStart, "CRCX", strlen("CRCX")) == 0)
		{
			rtpPort = FindMediaPortByString((gchar *) pAppStart);
			FindCallIdByString((gchar *) pAppStart, callId);
			AddPort(&callId[0], rtpPort);
			tie_port(PT_UDP, rtpPort, "rtp");
			tie_port(PT_UDP, rtpPort+1, "rtcp");
			return true;
		}
		else if (strncmp((gchar *) pAppStart, "DLCX", strlen("DLCX")) == 0)
		{
			FindCallIdByString((gchar *) pAppStart, callId);
			DelPort(&callId[0]);
			return true;
		}

	}
	
	return false;
}

