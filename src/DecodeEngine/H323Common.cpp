
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
/*///////////////////////
 *
 * H323common.cxx
 * handles all H.323 common utilities
 * including asn per(packet encoding rule) related tag and fields
 *
 *//////////////////////
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

#include <stdio.h>
#include <stdlib.h>

#include "H323Common.h"

inline unsigned short SwapU16(unsigned short u16)
{
	return (((u16)<<8 & 0xff00) | ((u16)>>8 & 0xff));
};

/*---------------------------------------------------
 *
 * get bits-number field value
 * num: number of bits in the field but >=1 && <=8
 * base: base value for adding together
 *
 *----------------------------------------------------*/
unsigned short getBitsFieldValue(CONSTRUCT_DATA *pH323, unsigned char num, unsigned char base)
{
	unsigned short 		value = *pH323->pData;
//	unsigned short      length;

//	if(pH323->cur_bit_offset <8)
//		setH323CurrentData(pH323, -1);  //move pointer to the curent byte

	switch (pH323->cur_bit_offset)
	{
	case 8:
	{	//bits are in one byte
		switch(num)
		{
		case 8: 
			value = ((value & 0xff)>>0) + base; 
			break;
		case 7:
			value = ((value & 0xfe)>>1) + base;
			break;
		case 6:
			value = ((value & 0xfc)>>2) + base;
			break;
		case 5:
			value = ((value & 0xf8)>>3) + base;
			break;
		case 4:
			value = ((value & 0xf0)>>4) + base;
			break;
		case 3:
			value = ((value & 0xe0)>>5) + base;
			break;
		case 2:
			value = ((value & 0xc0)>>6) + base;
			break;
		case 1:
			value = ((value & 0x80)>>7) + base;
		}
		break;
	}
	case 7:
	{
		//possible 2 bytes involved
		if(num>7) value = SwapU16(*((WORD*)pH323->pData));
		switch(num)
		{
		case 8:
			value = ((value & 0x7f80)>>7) + base;
			break;
		case 7:
			value = ((value & 0x7f)>>0) + base;
			break;
		case 6:
			value = ((value & 0x7e)>>1) + base;
			break;
		case 5:
			value = ((value & 0x7c)>>2) + base;
			break;
		case 4:
			value = ((value & 0x78)>>3) + base;
			break;
		case 3:
			value = ((value & 0x70)>>4) + base;
			break;
		case 2:
			value = ((value & 0x60)>>5) + base;
			break;
		case 1:
			value = ((value & 0x40)>>6) + base;
		}
		break;
	}
	case 6:
	{
		if(num>6) value = SwapU16(*((WORD*)pH323->pData));
		switch(num)
		{
		case 8:
			value = ((value & 0x3fc0)>>6) + base;
			break;
		case 7:
			value = ((value & 0x3f80)>>7) + base;
			break;
		case 6:
			value = ((value & 0x3f)>>0) + base;
			break;
		case 5:
			value = ((value & 0x3e)>>1) + base;
			break;
		case 4:
			value = ((value & 0x3c)>>2) + base;
			break;
		case 3:
			value = ((value & 0x38)>>3) + base;
			break;
		case 2:
			value = ((value & 0x30)>>4) + base;
			break;
		case 1:
			value = ((value & 0x20)>>5) + base;
		}
		break;
	}
	case 5:
	{
		if(num>5)  value = SwapU16(*((WORD*)pH323->pData));
		switch(num)
		{
		case 8:
			value = ((value & 0x1fe0)>>5) + base;
			break;
		case 7:
			value = ((value & 0x1fc0)>>6) + base;
			break;
		case 6:
			value = ((value & 0x1f80)>>7) + base;
			break;
		case 5:
			value = ((value & 0x1f)>>0) + base;
			break;
		case 4:
			value = ((value & 0x1e)>>1) + base;
			break;
		case 3:
			value = ((value & 0x1c)>>2) + base;
			break;
		case 2:
			value = ((value & 0x18)>>3) + base;
			break;
		case 1:
			value = ((value & 0x10)>>4) + base;
			break;
		}
		break;
	}
	case 4:
	{
		if(num>4)  value = SwapU16(*((WORD*)pH323->pData));
		switch(num)
		{
		case 8:
			value = ((value & 0x0ff0)>>4) + base;
			break;
		case 7:
			value = ((value & 0x0fe0)>>5) + base;
			break;
		case 6:
			value = ((value & 0x0fc0)>>6) + base;
			break;
		case 5:
			value = ((value & 0x0f80)>>7) + base;
			break;
		case 4:
			value = ((value & 0x0f)>>0) + base;
			break;
		case 3:
			value = ((value & 0x0e)>>1) + base;
			break;
		case 2:
			value = ((value & 0x0c)>>2) + base;
			break;
		case 1:
			value = ((value & 0x08)>>3) + base;
		}
		break;
	}
	case 3:
	{
		if(num>3)  value = SwapU16(*((WORD*)pH323->pData));
		switch(num)
		{
		case 8:
			value = ((value & 0x07f8)>>3) + base;
			break;
		case 7:
			value = ((value & 0x07f0)>>4) + base;
			break;
		case 6:
			value = ((value & 0x07e0)>>5) + base;
			break;
		case 5:
			value = ((value & 0x07c0)>>6) + base;
			break;
		case 4:
			value = ((value & 0x0780)>>7) + base;
			break;
		case 3:
			value = ((value & 0x07)>>0) + base;
			break;
		case 2:
			value = ((value & 0x06)>>1) + base;
			break;
		case 1:
			value = ((value & 0x04)>>2) + base;
		}
		break;
	}
	case 2:
	{
		if(num>2)  value = SwapU16(*((WORD*)pH323->pData));
		switch(num)
		{
		case 8:
			value = ((value & 0x03fc)>>2) + base;
			break;
		case 7:
			value = ((value & 0x03f8)>>3) + base;
			break;
		case 6:
			value = ((value & 0x03f0)>>4) + base;
			break;
		case 5:
			value = ((value & 0x03e0)>>5) + base;
			break;
		case 4:
			value = ((value & 0x03c0)>>6) + base;
			break;
		case 3:
			value = ((value & 0x0380)>>7) + base;
			break;
		case 2:
			value = ((value & 0x03)>>0) + base;
			break;
		case 1:
			value = ((value & 0x02)>>1) + base;
		}
		break;
	}
	case 1:
	{
		if(num>1)  value = SwapU16(*((WORD*)pH323->pData));
		switch(num)
		{
		case 8:
			value = ((value & 0x01fe)>>1) + base;
			break;
		case 7:
			value = ((value & 0x01fc)>>2) + base;
			break;
		case 6:
			value = ((value & 0x01f8)>>3) + base;
			break;
		case 5:
			value = ((value & 0x01f0)>>4) + base;
			break;
		case 4:
			value = ((value & 0x01e0)>>5) + base;
			break;
		case 3:
			value = ((value & 0x01c0)>>6) + base;
			break;
		case 2:
			value = ((value & 0x0180)>>7) + base;
			break;
		case 1:
			value = ((value & 0x01)>>0) + base;
		}
		break;
	}

	default: break;

	}
	
	//if((pH323->cur_bit_offset >=num )	//same byte
	//	length = 1;
	//else	length = 2;
		
	//setH323CurrentData(pH323, length);

	setH323CurrentBitPos(pH323, num);

	return value;

} //END getBitsFieldValue()


/*+------------------------------------------------------
 * 
 * check the number of extension fields
 * beyond extension root in CHOICE AND SEQUENCE
 *
 * it returns number fields in SEQUENCE
 * returns type value in CHOICE (base is the msg in extension)
 *
 *--------------------------------------------------------
-*/
unsigned short getExtensionFieldNumber(CONSTRUCT_DATA *pH323, unsigned short base)
{
	unsigned short  number;
	BOOL    bIndex;

	bIndex = IncludeOptionalField(pH323, 1);
	
	if(!bIndex) // 6 bits for small non negative integer
		number = getBitsFieldValue(pH323, 6, base);
	else 
	{ // semi constrained integer 
		needAdvancePointer(pH323);
		number = *pH323->pData + base;
		setH323CurrentData(pH323, 1, 8); 
	}

	return number;
}

/*+------------------------------------------------------
 * 
 * Skip over open type field which is beyond extension root
 * 
 * normally 1 byte field for length
 * and contents with the legnth of bytes
 *
 *--------------------------------------------------------
-*/
void SkipOverOpenTypeField(CONSTRUCT_DATA *pH323Data)
{
	unsigned short   length;

	//openType
	needAdvancePointer(pH323Data);
	length = *pH323Data->pData;
	setH323CurrentData(pH323Data, 1+length, 8); //bit_offset 8
}


//transport address decode
void h225_TransportAddress(CONSTRUCT_DATA  *pH323, TRANSPORTaddress &h245Addr)
{
	unsigned short	Type;
	unsigned short	num, length;
	BOOL    bExt;	

	bExt = IncludeOptionalField(pH323, 1);	
	//3 bits for index
	Type = getBitsFieldValue(pH323, 3, 0);

	switch(Type)
	{
		case 0:	//IP 
			needAdvancePointer(pH323);
			memcpy(h245Addr.addr, pH323->pData, 4);
			h245Addr.len = 4;
			setH323CurrentData(pH323, 4, 8); //4 bytes, curbit is 8
			//2 bytes for port 
			h245Addr.port = SwapU16(*(WORD*)pH323->pData);			
			setH323CurrentData(pH323, 2, 8); //2 bytes, curbit is 8
			break;		
		
		case 3:	// IP6
			//extension bit
			IncludeOptionalField(pH323, 1);
			needAdvancePointer(pH323);
			memcpy(h245Addr.addr, pH323->pData, 16);
			h245Addr.len = 16;
			setH323CurrentData(pH323, 16, 8); //16 bytes, curbit is 8
			//2 bytes for port 
			h245Addr.port = SwapU16(*(WORD*)pH323->pData);			
			setH323CurrentData(pH323, 2, 8); //2 bytes, curbit is 8
			break;		
		
		case 2:	 // IPXaddress
			needAdvancePointer(pH323);
			memcpy(h245Addr.addr, pH323->pData, 6);
			h245Addr.len = 6;
			setH323CurrentData(pH323, 6, 8); //6 bytes, curbit is 8
			//netnum 4 bytes
			setH323CurrentData(pH323, 4, 8); //6 bytes, curbit is 8
			//2 bytes for port 
			h245Addr.port = SwapU16(*(WORD*)pH323->pData);			
			setH323CurrentData(pH323, 2, 8); //2 bytes, curbit is 8
			break;		
		
		case 4:	// Netbios:16 octet 
			needAdvancePointer(pH323);
			memcpy(h245Addr.addr, pH323->pData, 16);
			h245Addr.len = 16;
			setH323CurrentData(pH323, 16, 8); //16 bytes, curbit is 8
			h245Addr.port = 0;  //no port number
			break;
		
		case 5:	// nsap::=OCTET STRING (SIZE(1..20)) 5-bits-encoding length 
			length = getBitsFieldValue(pH323, 5, 1);
			needAdvancePointer(pH323);
			memcpy(h245Addr.addr, pH323->pData, length>MAX_addrLen?MAX_addrLen:length);
			h245Addr.len = length;
			setH323CurrentData(pH323, length, 8); //length bytes, curbit is 8
			h245Addr.port = 0;  //no port number
			break;
		
		case 6:	// nonStandardParameter 
			break;
		
		case 1:	// ipSourceRoute  
			//extension bit
			IncludeOptionalField(pH323, 1);			
			needAdvancePointer(pH323);

			memcpy(h245Addr.addr, pH323->pData, 4);
			h245Addr.len = 4;
			setH323CurrentData(pH323, 4, 8); //16 bytes, curbit is 8
			//2 bytes for port 
			h245Addr.port = SwapU16(*(WORD*)pH323->pData);			
			setH323CurrentData(pH323, 2, 8); //2 bytes port, curbit is 8

			num = (UINT)(*pH323->pData);
			//route		SEQUENCE OF OCTET STRING(SIZE(4)),
			setH323CurrentData(pH323, 1 + num*4, 8); //1 byte num field 

			//routing extension bit
			IncludeOptionalField(pH323, 1);	
			//routing type
			getBitsFieldValue(pH323, 1, 0);
			
		default:	break;
	} 

} //END h225_TransportAddress

