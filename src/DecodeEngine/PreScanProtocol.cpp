
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
// PreScanProtocol.cpp: implementation of the CPreScanProtocol class.
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

#include "PreScanProtocol.h"

#define HAVE_CONFIG_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include "packet.h"
#include <vector>// added by xulei for bug#5986

#include "PreScanDynamicPorts.h"

static CPreScanDynamicPorts gpAppPorts;

// added by xulei for bug#5986
static std::vector<unsigned short> gTiedAppPorts; // records ports tied to dissect handle

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPreScanProtocol::CPreScanProtocol(char *protocolName)
{
    if (protocolName)
    {
	strcpy(m_protocolName, protocolName);
    }
    else
    {
	m_protocolName[0] = '\0';
    }

    // string hash table
    m_pStrHashTable = g_hash_table_new(g_str_hash, g_str_equal);

    // unsignged 32 bit id hashtable

    m_applicationId = 0;

}

CPreScanProtocol::~CPreScanProtocol()
{
    if (m_pStrHashTable)
	g_hash_table_destroy(m_pStrHashTable);

}

void CPreScanProtocol::SetProtocolName(char *protocolName)
{
    if (protocolName)
    {
	strcpy(m_protocolName, protocolName);
    }

}

char *CPreScanProtocol::GetProtocolName()
{
    return m_protocolName;
}


bool CPreScanProtocol::IsMe(unsigned int protocolId)
{
    return protocolId == m_protocolId;
}

void CPreScanProtocol::SetProtocolId(unsigned int protocolId)
{
    m_protocolId = protocolId;
}

unsigned int CPreScanProtocol::GetProtocolId()
{
    return m_protocolId;
}

unsigned char *CPreScanProtocol::GetUdpAppStartAddress(unsigned char *pFrameStart)
{
    // LLC + IP + UDP 
    return pFrameStart + 42;
}

int CPreScanProtocol::GetUdpAppDataLen(int frameLen)
{
    return frameLen - 42;
}

void CPreScanProtocol::AddPort(char *key, unsigned int port)
{
    g_hash_table_insert(m_pStrHashTable, key, GUINT_TO_POINTER(port));
}

void CPreScanProtocol::DelPort(char *key)
{
    g_hash_table_remove(m_pStrHashTable, key);
}

unsigned int CPreScanProtocol::GetPort(char *key)
{
    gpointer port;

    port = g_hash_table_lookup(m_pStrHashTable, key);
    
    return GPOINTER_TO_UINT(port);
}

void CPreScanProtocol::AddAppPort(unsigned short applicationId, unsigned short portNumber, bool bDefault)
{
    gpAppPorts.AddPort(applicationId, portNumber, bDefault);
}

void CPreScanProtocol::DelAppPort(unsigned short portNumber)
{
    gpAppPorts.DelPort(portNumber);
}

unsigned short CPreScanProtocol::FindAppPort(unsigned short portNumber)
{

    return gpAppPorts.FindPort(portNumber);
}

//for bug#6124
unsigned short CPreScanProtocol::FindAppPort(unsigned short portNumber, bool bDefault)
{
    return gpAppPorts.FindPort(portNumber, bDefault);
}

void CPreScanProtocol::DelAllAppPort()
{
    gpAppPorts.DelAllPort();
}

// begin added by xulei for bug#5986
void CPreScanProtocol::AddTiedAppPort(unsigned short usPort)
{
    gTiedAppPorts.push_back(usPort);
}

unsigned int CPreScanProtocol::GetTiedAppPortNum()
{
    return gTiedAppPorts.size();
}

unsigned short CPreScanProtocol::GetTiedAppPort(unsigned int uiIndex)
{
    if( uiIndex >= gTiedAppPorts.size() ) return 0;
    return gTiedAppPorts[uiIndex];
}
// end added by xulei for bug#5986

