
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
// PreScanProtocolH323.h: interface for the CPreScanProtocolH323 class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PRESCANPROTOCOLH323_H__2BCD33CD_4DD5_4C96_B32C_5A0C4DBDC984__INCLUDED_)
#define AFX_PRESCANPROTOCOLH323_H__2BCD33CD_4DD5_4C96_B32C_5A0C4DBDC984__INCLUDED_

#ifndef __CS_LINUX
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#endif

#include "PreScanProtocol.h"
#include "H323Common.h"

#define PRO_H225_ID		1720    // H.323 Call Signaling
#define PRO_H323_ID		PRO_H225_ID

class CPreScanProtocolH323 : public CPreScanProtocol  
{
public:
	CPreScanProtocolH323(char *protocolName);
	virtual ~CPreScanProtocolH323();

	inline virtual  bool Parse(unsigned char *pFrameStart, int frameLen);

private:
	gint   FindMediaPortByString(gchar *str);
	gchar *FindCallIdByString(gchar *str, gchar *callId);

public:
	CONSTRUCT_DATA  *pH323;

};

#endif // !defined(AFX_PRESCANPROTOCOLH323_H__2BCD33CD_4DD5_4C96_B32C_5A0C4DBDC984__INCLUDED_)

