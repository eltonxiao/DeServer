
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
// PreScanProtocolH245.h: interface for the CPreScanProtocolH245 class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PRESCANPROTOCOLH245_H__FCFE184A_7BF8_45E4_ABDA_052319EDB887__INCLUDED_)
#define AFX_PRESCANPROTOCOLH245_H__FCFE184A_7BF8_45E4_ABDA_052319EDB887__INCLUDED_

#ifndef __CS_LINUX
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#endif

#include "PreScanProtocol.h"

#define PRO_H225_ID		1720    // H.323 Call Signaling
#define PRO_H323_ID		PRO_H225_ID

class CPreScanProtocolH245 : public CPreScanProtocol  
{
public:
	CPreScanProtocolH245(char *protocolName);
	virtual ~CPreScanProtocolH245();

	inline virtual  bool IsMe(unsigned int protocolId);
	inline virtual  bool Parse(unsigned char *pFrameStart, int frameLen);

private:
	gint   FindMediaPortByString(gchar *str);
	gchar *FindCallIdByString(gchar *str, gchar *callId);

};

#endif // !defined(AFX_PRESCANPROTOCOLH245_H__FCFE184A_7BF8_45E4_ABDA_052319EDB887__INCLUDED_)

