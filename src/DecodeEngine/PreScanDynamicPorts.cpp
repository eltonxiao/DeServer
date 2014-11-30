
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
// PreScanDynamicPorts.cpp: implementation of the CPreScanDynamicPorts class.
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

#include "PreScanDynamicPorts.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPreScanDynamicPorts::CPreScanDynamicPorts()
{
	m_numDynamicApplicaton = 0;
}

CPreScanDynamicPorts::~CPreScanDynamicPorts()
{

}

bool CPreScanDynamicPorts::NewDynamicApplication(int applicationId)
{
	return true;
}

bool CPreScanDynamicPorts::DelDynamicApplication(int applicationId)
{
	return true;
}

bool CPreScanDynamicPorts::FindProtocolId(int applicaitonId, unsigned short protcolId)
{
	return false;
}

void CPreScanDynamicPorts::AddPort(int applicaitonId, unsigned short portNumber, bool bDefault)
{
	CDynamicPort appPort;

	appPort.applicationId = applicaitonId;
	appPort.portNumber    = portNumber;
    appPort.bDefaultPort  = bDefault;//for bug#6124

	pair<CPortMap::iterator, bool> ret;

    ret = m_portMap.insert(CPortMap::value_type(portNumber, appPort));
	
	if (ret.second)
	{
		// true;
	}
	else
	{
		// false;
	}
}

void CPreScanDynamicPorts::DelPort(unsigned short portNumber)
{
	m_portMap.erase(portNumber);
}

void CPreScanDynamicPorts::DelAllPort()
{
	m_portMap.erase(m_portMap.begin(), m_portMap.end());
}


unsigned short CPreScanDynamicPorts::FindPort(unsigned short portNumber)
{
	CDynamicPort       appPort;
    CPortMap::iterator theIterator;

    theIterator = m_portMap.find(portNumber);

    if(theIterator != m_portMap.end()) 
	{
		appPort = (*theIterator).second;
		return appPort.applicationId;
	}

	return 0;

}

//for bug#6124
unsigned short CPreScanDynamicPorts::FindPort(unsigned short portNumber, bool bDefault)
{
	CDynamicPort       appPort;
    CPortMap::iterator theIterator;

    theIterator = m_portMap.find(portNumber);

    if(theIterator != m_portMap.end()) 
	{
		appPort = (*theIterator).second;

        if(appPort.bDefaultPort == bDefault)
		    return appPort.applicationId;
	}
	return 0;
}

