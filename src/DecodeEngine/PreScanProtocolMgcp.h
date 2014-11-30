
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
// PreScanProtocolMgcp.h: interface for the CPreScanProtocolMgcp class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PRESCANPROTOCOLMGCP_H__6F2C5FCD_A511_4A7D_9EAD_AEABBD81E1A7__INCLUDED_)
#define AFX_PRESCANPROTOCOLMGCP_H__6F2C5FCD_A511_4A7D_9EAD_AEABBD81E1A7__INCLUDED_

#ifndef __CS_LINUX
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#endif

#include "PreScanProtocol.h"

#define PRO_MGCP_ID		2427


class CPreScanProtocolMgcp : public CPreScanProtocol  
{
public:
	CPreScanProtocolMgcp(char *protocolName);
	virtual ~CPreScanProtocolMgcp();

	inline virtual  bool Parse(unsigned char *pFrameStart, int frameLen);

private:
	gint   FindMediaPortByString(gchar *str);
	gchar *FindCallIdByString(gchar *str, gchar *callId);

};

#endif // !defined(AFX_PRESCANPROTOCOLMGCP_H__6F2C5FCD_A511_4A7D_9EAD_AEABBD81E1A7__INCLUDED_)

