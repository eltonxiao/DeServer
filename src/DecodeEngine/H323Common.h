
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
/*
 * H323Common.h
 *
 * 
 *
 ******************************************************************/

#ifndef  __H323COMMON_H
#define  __H323COMMON_H


//#include "StdString.h"
//#include "CoDaiType.h"

#define   MAX_addrLen 20
#define   MAX_string  150;
#define   MAX_RT_PORT    10
#define   MAX_H245_PORT  4

typedef struct {
	BYTE	*pData;
	BYTE	*pEndData;
	unsigned char	cur_bit_offset;   //from high to low
	unsigned short  cur_byte_offset;	
} CONSTRUCT_DATA;

typedef struct {
	BYTE	addr[MAX_addrLen];
	unsigned short	port;
	unsigned char   len;
	BOOL    bPort;
}TRANSPORTaddress;

typedef struct {
	union {
		BYTE ver:4;
		BYTE len:4;
	}HdrLen;
	BYTE  TypeSvc;
	unsigned short   totalLength;
	unsigned short   Ident;
}IPHeader;

		
typedef struct {
	unsigned short   srcPort;
	unsigned short   dstPort;
	unsigned int   seqNum;
	unsigned int   ackNum;
	BYTE     dataOffset;
	BYTE     flag;
	unsigned short   windSize;
	unsigned short   checksum;
}TCPHeader;

inline void initTRANSPORTaddressData(TRANSPORTaddress &StructAddr)
{
	memset(StructAddr.addr, 0, MAX_addrLen);
	StructAddr.port = 0;
	StructAddr.len  = 0;
	StructAddr.bPort=FALSE;
}

inline void initH323ConstructData(CONSTRUCT_DATA  *pH323Data, BYTE *pStart, BYTE *pEnd, unsigned char bit_offset)
{
	pH323Data->cur_bit_offset = bit_offset;  //set to 8
	pH323Data->pData = pStart;
	pH323Data->pEndData = pEnd;
}

inline void setH323CurrentData(CONSTRUCT_DATA  *pH323Data, unsigned short length)
{
	pH323Data->pData +=length;
}

inline void setH323CurrentData(CONSTRUCT_DATA  *pH323Data, unsigned short length, unsigned char curBit)
{
	pH323Data->pData +=length;
	pH323Data->cur_bit_offset = curBit;
}


inline void setH323CurrentBitPos(CONSTRUCT_DATA *pH323Data, unsigned short num)
{
	if(pH323Data->cur_bit_offset > num)
		pH323Data->cur_bit_offset = pH323Data->cur_bit_offset - num;
	else  //2 bytes involved
	{
		pH323Data->cur_bit_offset = pH323Data->cur_bit_offset - num + 8;
		setH323CurrentData(pH323Data, 1);
	}
}

unsigned short getBitsFieldValue(CONSTRUCT_DATA *pH323, unsigned char num, unsigned char base);

//handle extenion or optional field
inline BOOL IncludeOptionalField(CONSTRUCT_DATA *pH323Data, unsigned char num)
{
	return getBitsFieldValue(pH323Data, num, 0);
}

//data pointer need to advance if the next field is byte boundary value
//and the cur_bit_offset is not point to the next field yet
inline BOOL needAdvancePointer(CONSTRUCT_DATA *pH323Data)
{
	if(pH323Data->cur_bit_offset<8)
		setH323CurrentData(pH323Data, 1, 8);

	return TRUE;
}


unsigned short getExtensionFieldNumber(CONSTRUCT_DATA *pH323Data, unsigned short base);
void SkipOverOpenTypeField(CONSTRUCT_DATA *pH323Data);


void h225_TransportAddress(CONSTRUCT_DATA  *pH323, TRANSPORTaddress &h245Addr);


#endif  //END  __H323COMMON_H