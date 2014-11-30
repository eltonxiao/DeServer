
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
// DecodePreScan.h: interface for the CDecodePreScan class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DECODEPRESCAN_H__B8FC93A0_656E_441A_B013_470EB51A04F0__INCLUDED_)
#define AFX_DECODEPRESCAN_H__B8FC93A0_656E_441A_B013_470EB51A04F0__INCLUDED_

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
#include "DecodePreScan.h"
#include "PreScanProtocol.h"

#ifdef __cplusplus
}
#endif /* __cplusplus */

#include <vector>
using namespace std;

typedef std::vector<CPreScanProtocol *>  CPreScanProtocolVector;

class CDecodePreScan  
{
public:
	CDecodePreScan();
	virtual ~CDecodePreScan();

	void AddPreScanProtocol(CPreScanProtocol *pPreScanProtocol);

	bool ProcessGlobalSettingPorts(unsigned short srcPort, unsigned short dstPort);
	void Process(unsigned char *pFrameStart, int frameLen);

	bool  GetProtocolId(unsigned char *pFrameStart, int frameLen, PORT_PAIR_P pPortPair);

	bool  SmellFrame(guchar *pFrameStart, int frameLen, gushort port);
	bool  SmellTnsFrame(guchar *pFrameStart, int frameLen);

private:

	CPreScanProtocolVector m_preScanProtocolVector;

};

#endif // !defined(AFX_DECODEPRESCAN_H__B8FC93A0_656E_441A_B013_470EB51A04F0__INCLUDED_)

