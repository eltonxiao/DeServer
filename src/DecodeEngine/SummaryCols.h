
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
#ifndef __SUMMARY_COLS_H__
#define __SUMMARY_COLS_H__

typedef enum
{
	SUMMARY_COL_NUMBER = 0,
	SUMMARY_COL_REL_TIME,
	SUMMARY_COL_ABS_DATE_TIME,
	SUMMARY_COL_DELTA_TIME,
	SUMMARY_COL_UNRES_DL_SRC,
	SUMMARY_COL_UNRES_DL_DST,
	SUMMARY_COL_RES_DL_SRC,
	SUMMARY_COL_RES_DL_DST,
	SUMMARY_COL_UNRES_NET_SRC,
	SUMMARY_COL_UNRES_NET_DST,
    SUMMARY_COL_RES_NET_SRC,
    SUMMARY_COL_RES_NET_DST,
	SUMMARY_COL_PACKET_LENGTH,
	SUMMARY_COL_PROTOCOL,
	SUMMARY_COL_INFO,
    SUMMARY_COL_INFO_PHYSICAL_LAYER, // ie, ethernet
    SUMMARY_COL_INFO_NETWORK_LAYER, // ie, ip
    SUMMARY_COL_INFO_TRANSPORT_LAYER, // ie, tcp
	SUMMARY_COL_STATUS,

    NUMBER_OF_SUMMARY_COL

} SummaryColumns;

#endif

