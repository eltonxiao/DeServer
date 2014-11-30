
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
// PreScanProtocol.h: interface for the CPreScanProtocol class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PRESCANPROTOCOL_H__3DE8D6BA_38EE_48D3_9CC6_FFF9EA7C2400__INCLUDED_)
#define AFX_PRESCANPROTOCOL_H__3DE8D6BA_38EE_48D3_9CC6_FFF9EA7C2400__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define HAVE_CONFIG_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include "packet.h"

#ifdef __cplusplus
}
#endif /* __cplusplus */

#include "DecodeIp.h"

class CPreScanProtocol  
{
public:
	CPreScanProtocol(char *protocolName);
	virtual ~CPreScanProtocol();

	inline void SetProtocolName(char *protocolName);
	inline char *GetProtocolName();

	void         AddPort(char *key, unsigned int value);
	void         DelPort(char *key);
	unsigned int GetPort(char *key);

	static void           AddAppPort(unsigned short applicationId, unsigned short portNumber, bool bDefault);
	static void           DelAppPort(unsigned short portNumber);
	static unsigned short FindAppPort(unsigned short portNumber);
    static unsigned short FindAppPort(unsigned short portNumber, bool bDefault);//for bug#6124
	static void           DelAllAppPort();
    
    // added by xulei for bug#5986
    static void           AddTiedAppPort(unsigned short usPort);
    static unsigned int   GetTiedAppPortNum();
    static unsigned short GetTiedAppPort(unsigned int uiIndex);

	inline virtual  bool IsMe(unsigned int protocolId);
	inline virtual  bool Parse(unsigned char *pFrameStart, int frameLen) = 0;

	void         SetProtocolId(unsigned int protocolId);
	unsigned int GetProtocolId();

	unsigned char *GetUdpAppStartAddress(unsigned char *pFrameStart);
	int            GetUdpAppDataLen(int frameLen);

	void           SetApplicationId(unsigned short id) {m_applicationId = id;};
	unsigned short GetApplicationId() {return m_applicationId;};
#ifdef samuell
	static void			 AddGlobalSettingPort(unsigned int appType, unsigned int ipPortNumber);
	static void			 DelGlobalSettingPort(unsigned int ipPortNumber);
	static unsigned int  FindGlobalSettingAppPort(unsigned int ipPortNumber);
#endif
protected:
	unsigned short m_applicationId;

private:
	// protocaol NAME;
	char		 m_protocolName[128];
	unsigned int m_protocolId;
	GHashTable*  m_pStrHashTable;

};

#endif // !defined(AFX_PRESCANPROTOCOL_H__3DE8D6BA_38EE_48D3_9CC6_FFF9EA7C2400__INCLUDED_)
