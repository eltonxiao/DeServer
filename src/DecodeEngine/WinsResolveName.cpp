
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
#include <ctype.h>
        #include "decode_predef.h"
#endif

///#include <string.h>
///#include <ctype.h>

#include "glib.h"

#include "WinsResolveName.h"

#ifdef __cplusplus
extern "C" {
#endif
/* adds a hostname/IP in the hash table */
extern void add_ipv4_name(guint addr, const guchar *name);

#define	BSWAP16(x) \
	 ((((x)&0xFF00)>>8) | \
	  (((x)&0x00FF)<<8))


void WinsResolveName(guchar *pFrame, guint frameLen)
{
	if (frameLen < 62) return; // bad

	// Is the answer count greater than 0?
	guint replyCount = BSWAP16(*(WORD*)&pFrame[6]);
	if (0 == replyCount) return;
	
	BYTE * nameFieldPtr = pFrame+12;
	BYTE offset = 0;
	for (guint i=0; i < replyCount; i++)
	{
		gchar nameBuf[128];
		guint bufIdx = 0;
		memset(nameBuf, 0, sizeof(nameBuf));

		guint len = *(nameFieldPtr + offset);

		if (len/2 > sizeof(nameBuf)) return; //array may be overrun, bad data, return

		offset++;
		for (guint j=0; j < len/2; j++)
		{
			char firstChar = *(nameFieldPtr + offset++);
			char secondChar = *(nameFieldPtr + offset++);
			if (isalpha(firstChar) == 0 || isalpha(secondChar) == 0) return; //bad
			nameBuf[bufIdx++] = ((firstChar - 'A') << 4)|(secondChar-'A');
		}

		guint l = guint(strlen(nameBuf));
		while (--l) {
			if (nameBuf[l] <= ' ' || nameBuf[l] > 127)
				nameBuf[l] = '\0';
			else break;
		}
		// jump 13 bytes to ip field
		offset += 13;

		BYTE* ipFieldPtr = nameFieldPtr + offset;

		guint IPAdr = *(guint *)ipFieldPtr;

		add_ipv4_name(IPAdr, (guchar*)nameBuf);

//		IpAddr2Str(ipBuf, (IP_ADDR_P)ipFieldPtr);

//		CDynAddressBook *pDynAddrBook = (CDynAddressBook *) GetDynAddressBook();
//		pDynAddrBook->AddAddressBookItem(nameBuf, ipBuf);

		offset += 4;
	}

	return;

}
// used to get the name string into a '.' format

#ifdef __cplusplus
}
#endif
