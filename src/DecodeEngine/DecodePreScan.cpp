
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
// DecodePreScan.cpp: implementation of the CDecodePreScan class.
//
//////////////////////////////////////////////////////////////////////

#include "StdAfx.h"
#ifndef __CS_LINUX

// undefine the TRY, CATCH, etc macros defined for MFC - they conflict
// with ethereal definitions
    #include "UndefineTryCatch.h"
#else
    #include <arpa/inet.h>
    #include <pthread.h>
    #include <boost/thread/thread.hpp>
    #include <boost/thread/mutex.hpp>
    #include <boost/thread/tss.hpp>
    #include <cstdio>
#include <stdlib.h>
#include <string.h>
    #include "decode_predef.h"
#endif


#include "DecodePreScan.h"
#include "DecodeIp.h"
#include "PreScanProtocolSip.h"
#include "PreScanProtocolMgcp.h"
#include "PreScanProtocolRtp.h"
#include "PreScanProtocolH323.h"
#include "PreScanProtocolH245.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CDecodePreScan::CDecodePreScan()
{
    
    AddPreScanProtocol(new CPreScanProtocolSip("SIP"));
    AddPreScanProtocol(new CPreScanProtocolMgcp("MGCP"));
    AddPreScanProtocol(new CPreScanProtocolH323("H323"));
    AddPreScanProtocol(new CPreScanProtocolH245("H245"));

    // RTP has to be the last one
    // it might be reomved later.
    // AddPreScanProtocol(new CPreScanProtocolRtp("RTP"));
}

CDecodePreScan::~CDecodePreScan()
{
    register size_t count = m_preScanProtocolVector.size();
    for (size_t i=0; i < count; i++)
    {
	    CPreScanProtocol* pPreScanProtocol = m_preScanProtocolVector[i];
	    delete pPreScanProtocol;
    }
}

bool CDecodePreScan::GetProtocolId(unsigned char *pFrameStart, int frameLen, PORT_PAIR_P pPortPair)
{
    register unsigned short  packetType;
    register e_iphdr  *pIpHdr;
    register e_tcphdr *pTcpHdr;
    register e_udphdr *pUdpHdr;
    

    if (frameLen < IP_PACKET_MIX_LENGTH)
    {
	return false;
    }

    packetType = *((unsigned short *)(pFrameStart+LLC_PROTOCOL_OFFSET));
    if (packetType == IP_PACKET)
    {
	pIpHdr = (e_iphdr *) (pFrameStart + IP_HDR_OFFSET);

	if (pIpHdr->ip_p == UDP_PROTOCOL)
	{
	    pUdpHdr = GetUdpHdr(pFrameStart);
	    pPortPair->srcPort = ntohs(pUdpHdr->uh_sport);
	    pPortPair->dstPort = ntohs(pUdpHdr->uh_dport);

	    return true;
	}
	else if (pIpHdr->ip_p == TCP_PROTOCOL)
	{
	    pTcpHdr = GetTcpHdr(pFrameStart);
	    
	    pPortPair->srcPort = ntohs(pTcpHdr->th_sport);
	    pPortPair->dstPort = ntohs(pTcpHdr->th_dport);

	    return true;
	}

    }
    return false;
}

bool CDecodePreScan::ProcessGlobalSettingPorts(unsigned short srcPort, unsigned short dstPort)
{
    unsigned short appType, appPort = srcPort;

    appType = CPreScanProtocol::FindAppPort(appPort);

    if (appType == 0)
    {
	appPort = dstPort;
	appType = CPreScanProtocol::FindAppPort(appPort);
    }

    if (appType == 0)
    {
	return false;
    }
    // modified by xulei for bug#5896
    gboolean ret = false;
	switch (appType)
	{
		case APP_HTTP:
			ret = tie_port_ex(appPort, "HTTP");
			break;

		case APP_SMTP:
			ret = tie_port_ex(appPort, "SMTP");
			break;

		case APP_DNS:
			ret = tie_port_ex(appPort, "DNS");
			break;

		case APP_FTP:
			ret = tie_port_ex(appPort, "FTP");
			break;

		case APP_LDAP:
			ret = tie_port_ex(appPort, "LDAP");
			break;

		case APP_POP:
			ret = tie_port_ex(appPort, "POP");
			break;

		case APP_SNMP:
			ret = tie_port_ex(appPort, "SNMP");
			break;

		case APP_TELNET:
			ret = tie_port_ex(appPort, "TELNET");
			break;

			//....................................

		case APP_MSSQL:
			ret = tie_port_ex(appPort, "TDS");
			break;

		case APP_ORACLE:
			ret = tie_port_ex(appPort, "TNS");
			break;

		case APP_SKINNY:
			ret = tie_port_ex(appPort, "SKINNY");
			break;

		case APP_MAPI:
			ret = tie_port_ex(appPort, "MAPI");
			break;

		case APP_RTP:
			ret = tie_port_ex(appPort, "RTP");
            ret = tie_port_ex(appPort+1, "RTCP");
			break;

		case APP_CITRIX:
			ret = tie_port_ex(appPort, "CITRIX");
			break;

        // added by xulei for bug#3137
        case APP_AIM:
            ret = tie_port_ex(appPort, "AIM");
            break;

        case APP_SIP:
            ret = tie_port_ex(appPort, "SIP");
            break;

        case APP_H323:
            ret = tie_port_ex(appPort, "H.323");
            break;

        case APP_MGCP:
            ret = tie_port_ex(appPort, "MGCP");
            break;

        case APP_RAS:
            ret = tie_port_ex(appPort, "RAS");
            break;

        case APP_H225:
            ret = tie_port_ex(appPort, "H.225");
            break;

        case APP_H245:
            ret = tie_port_ex(appPort, "H.245");
            break;

        case APP_ADS:
            ret = tie_port_ex(appPort, "ADS");
            break;

        case APP_SYBASE:
            ret = tie_port_ex(appPort, "SYBASE");
            break;

        case APP_YAHOO_MESENGER:
            ret = tie_port_ex(appPort, "YHOO");
            break;

#if 0
        case APP_SMB:
            ret = tie_port_ex(appPort, "SMB", 0);
            break;

        case APP_IKE:
            ret = tie_port_ex(appPort, "ISAKMP", 0);
            break;

        case APP_WINS:
            ret = tie_port_ex(appPort, "WINS", 0);
            break;

        case APP_MEDIA_PLAYER:
            ret = tie_port_ex(appPort, "MediaPlayer", 0);
            break;

        case APP_NAPSTER:
            ret = tie_port_ex(appPort, "NAPSTER", 0);
            break;

        case APP_NNTP:
            ret = tie_port_ex(appPort, "NNTP", 0);
            break;

        case APP_GOPHER:
            ret = tie_port_ex(appPort, "GOPHER", 0);
            break;

        case APP_NFS:
            ret = tie_port_ex(appPort, "NFS", 0);
            break;

        case APP_NGS:
            ret = tie_port_ex(appPort, "NGS", 0);
            break;

        case APP_X_WINDOWS:
            ret = tie_port_ex(appPort, "X11", 0);
            break;

        case APP_RIP:
            ret = tie_port_ex(appPort, "RIP", 0);
            break;

        case APP_BOOTP:
            ret = tie_port_ex(appPort, "BOOTP", 0);
            break;

        case APP_TFTP:
            ret = tie_port_ex(appPort, "TFTP", 0);
            break;

        case APP_NETBIOS:
            ret = tie_port_ex(appPort, "NETBIOS", 0);
            break;

        case APP_KERBEROS:
            ret = tie_port_ex(appPort, "KERBEROS", 0);
            break;

        case APP_MEGACO:
            ret = tie_port_ex(appPort, "MEGACO", 0);
            break;
#endif
        default:
	    return false;

    }
    
    CPreScanProtocol::DelAppPort(appPort);
    if(ret)
        CPreScanProtocol::AddTiedAppPort(appPort);// added by xulei for bug#5986
    return true;
}

void CDecodePreScan::Process(unsigned char *pFrameStart, int frameLen)
{
    register size_t count = m_preScanProtocolVector.size();
    register CPreScanProtocol *pPreScanProtocol;
    register PORT_PAIR_T portPair;

    if (GetProtocolId(pFrameStart, frameLen, &portPair))
    {
        for (size_t i = 0; i < count; i++)
        {
            pPreScanProtocol = m_preScanProtocolVector[i];

            if (pPreScanProtocol->IsMe(portPair.srcPort) ||
                pPreScanProtocol->IsMe(portPair.dstPort))
            {
                if (pPreScanProtocol->Parse(pFrameStart, frameLen))
                {
                    //break;
                }
                return;
            }
            else
            {
            }
        }

#if 0 // for bug#6124
	// process user defined application ports
	if (ProcessGlobalSettingPorts(portPair.srcPort, portPair.dstPort))
	{
	    return;
	}
#endif

	/*+---------------------------------------
	 *  Smell the protocol or applications
	 *----------------------------------------
	-*/
	if (SmellFrame(pFrameStart, frameLen, portPair.srcPort))
	{
	    return;
	}
    }



}

void CDecodePreScan::AddPreScanProtocol(CPreScanProtocol *pPreScanProtocol)
{
    m_preScanProtocolVector.push_back(pPreScanProtocol);
}

/*+-------------------------------
 *  TNS  Header 
 *--------------------------------
-*/
#define TNS_TYPE_MAX		20
typedef struct _TNS_HEADER_T
{
    gushort packetLength;	// packet size is from 8 to 4096
    gushort dataChecksum;
    guchar  tnsType;
    guchar  packetFlag;		    // not used prior to TNS version 3
    gushort tnsHeaderChecksum;
    guchar  dataFlag1;
    guchar  dataFlag2;
}   TNS_HEADER_T, *TNS_HEADER_P;

#define TNS_HEADER_SIZE	    (sizeof(TNS_HEADER_T))

// oracle frame
bool CDecodePreScan::SmellTnsFrame(guchar *pTnsData, int dataLen)
{
    TNS_HEADER_P pTnsHeader = (TNS_HEADER_P) pTnsData;
    register guchar packetLen = BSWAP16(pTnsHeader->packetLength);

    dataLen -= 4;

    if (dataLen < sizeof(TNS_HEADER_T) ||
	dataLen != packetLen)
	return false;

    //-----------------------------
    //	CheckSum checking
    //-----------------------------
    if (pTnsHeader->dataChecksum != 0 ||
	pTnsHeader->tnsHeaderChecksum != 0)
    {
	return false;
    }

    //-----------------------------
    //	length checking
    //-----------------------------

    if (pTnsHeader->tnsType > TNS_TYPE_MAX)
    {
	return false;
    }

    return true;
}

bool CDecodePreScan::SmellFrame(guchar *pFrameStart, int frameLen, gushort port)
{
    register guchar *pAppStart;
    register gint   appDataLen;
    e_tcphdr	    *pTcpHdr;

    pTcpHdr    = GetTcpHdr(pFrameStart);
    pAppStart  = GetTcpAppStart(pTcpHdr);
    appDataLen = GetTcpAppDataLen(pTcpHdr, frameLen);

    if (SmellTnsFrame(pAppStart, appDataLen))
    {
	tie_port(PT_TCP, port, "TNS");
	return true;
    }

    return false;
}

