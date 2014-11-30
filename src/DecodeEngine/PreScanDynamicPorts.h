
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
// PreScanDynamicPorts.h: interface for the CPreScanDynamicPorts class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PRESCANDYNAMICPORTS_H__5E10A81F_6D33_410F_98E3_47822E97DAD8__INCLUDED_)
#define AFX_PRESCANDYNAMICPORTS_H__5E10A81F_6D33_410F_98E3_47822E97DAD8__INCLUDED_

#ifndef __CS_LINUX
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#endif

#pragma warning(4:4786)

#include "DecodeIp.h"

class CDynamicPort
{
public:
	unsigned short portNumber;
	unsigned short applicationId;
    bool           bDefaultPort;//for bug#6124
};

#include <map>
using namespace std;

typedef std::map<unsigned short, CDynamicPort, less<unsigned short> > CPortMap;

class CPreScanDynamicPorts  
{
public:
	CPreScanDynamicPorts();
	virtual ~CPreScanDynamicPorts();

	bool NewDynamicApplication(int applicationId);
	bool DelDynamicApplication(int applicationId);

	bool FindProtocolId(int applicaitonId, unsigned short portNumber);

        void AddPort(int applicaitonId, unsigned short portNumber, bool bDefault);
	void DelPort(unsigned short protcolId);
	void DelAllPort();
	unsigned short FindPort(unsigned short portNumber);
    unsigned short FindPort(unsigned short portNumber, bool bDefault);
private:
	int		m_numDynamicApplicaton;

	CPortMap m_portMap;



};

#endif // !defined(AFX_PRESCANDYNAMICPORTS_H__5E10A81F_6D33_410F_98E3_47822E97DAD8__INCLUDED_)

