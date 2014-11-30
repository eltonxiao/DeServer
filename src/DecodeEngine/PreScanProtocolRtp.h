
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
// PreScanProtocolRtp.h: interface for the CPreScanProtocolRtp class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PRESCANPROTOCOLRTP_H__0FF80769_DCA0_4CD5_9279_F628A711BA49__INCLUDED_)
#define AFX_PRESCANPROTOCOLRTP_H__0FF80769_DCA0_4CD5_9279_F628A711BA49__INCLUDED_

#ifndef __CS_LINUX
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#endif

#include "PreScanProtocol.h"

#define PRO_RTP_ID		0             

class CPreScanProtocolRtp : public CPreScanProtocol  
{
public:
	CPreScanProtocolRtp(char *protocolName);
	virtual ~CPreScanProtocolRtp();

	inline virtual  bool Parse(unsigned char *pFrameStart, int frameLen);
	inline virtual  bool IsMe(unsigned int protocolId);

private:
	gint   FindMediaPortByString(gchar *str);
	gchar *FindCallIdByString(gchar *str, gchar *callId);

};

#endif // !defined(AFX_PRESCANPROTOCOLRTP_H__0FF80769_DCA0_4CD5_9279_F628A711BA49__INCLUDED_)

